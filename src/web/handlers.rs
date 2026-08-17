use crate::config::model::{AppConfig, IpFetchConfig, NotificationConfig, UserAuthConfig};
use crate::config::storage::ConfigManager;
use crate::core::domain::parse_domain;
use crate::dns::trait_def::{DnsRecordType, SyncRecordResult, SyncStatus};
use crate::ip_fetcher::create_ip_fetcher;
use crate::notifier::dispatcher::NotificationDispatcher;
use crate::notifier::trait_def::{NotificationEvent, NotificationOverallStatus};
use crate::util::log_buffer::{LogBuffer, LogEntry};
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use chrono::Local;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::mpsc;

#[derive(Clone)]
pub struct AppState {
    pub config_manager: Arc<ConfigManager>,
    pub trigger_sender: mpsc::Sender<()>,
    pub log_buffer: LogBuffer,
}

#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub message: String,
    pub data: Option<T>,
}

impl<T> ApiResponse<T> {
    pub fn ok(data: T) -> Self {
        Self {
            success: true,
            message: "操作成功".to_string(),
            data: Some(data),
        }
    }

    pub fn err(message: String) -> Self {
        Self {
            success: false,
            message,
            data: None,
        }
    }
}

/// 获取当前配置
pub async fn get_config_handler(State(state): State<AppState>) -> impl IntoResponse {
    let conf = state.config_manager.get_config();
    let mut clean_conf = (*conf).clone();
    // 隐藏敏感哈希
    if let Some(ref mut auth) = clean_conf.auth {
        auth.password_hash = "******".to_string();
    }
    Json(ApiResponse::ok(clean_conf))
}

#[derive(Debug, Deserialize)]
pub struct SaveConfigRequest {
    pub config: AppConfig,
    pub new_password: Option<String>,
}

/// 保存更新配置
pub async fn save_config_handler(
    State(state): State<AppState>,
    Json(payload): Json<SaveConfigRequest>,
) -> impl IntoResponse {
    let mut new_config = payload.config;

    // 如果用户提交了新密码，生成 bcrypt 哈希
    if let Some(ref pwd) = payload.new_password {
        if !pwd.trim().is_empty() {
            match bcrypt::hash(pwd.trim(), bcrypt::DEFAULT_COST) {
                Ok(hash) => {
                    let username = new_config
                        .auth
                        .as_ref()
                        .map(|a| a.username.clone())
                        .unwrap_or_else(|| "admin".to_string());
                    new_config.auth = Some(UserAuthConfig {
                        username,
                        password_hash: hash,
                    });
                }
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ApiResponse::<()>::err(format!("密码哈希失败: {}", e))),
                    );
                }
            }
        }
    } else if let Some(ref auth) = new_config.auth {
        // 保留原密码哈希（如果传入的是占位符）
        if auth.password_hash == "******" {
            let current = state.config_manager.get_config();
            if let Some(ref cur_auth) = current.auth {
                new_config.auth = Some(cur_auth.clone());
            }
        }
    }

    match state.config_manager.update_config(new_config) {
        Ok(_) => (StatusCode::OK, Json(ApiResponse::ok(()))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::<()>::err(format!("保存配置失败: {}", e))),
        ),
    }
}

/// 手动触发立即全量同步
pub async fn manual_sync_handler(State(state): State<AppState>) -> impl IntoResponse {
    let _ = state.trigger_sender.send(()).await;
    Json(ApiResponse::ok("已触发后台全量同步"))
}

/// 测试 IP 提取器配置请求体
#[derive(Debug, Deserialize)]
pub struct TestIpRequest {
    pub ip_type: Option<String>,
    #[serde(flatten)]
    pub config: IpFetchConfig,
}

/// 测试 IP 提取器配置
#[derive(Debug, Serialize)]
pub struct TestIpResult {
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
}

pub async fn test_ip_handler(Json(payload): Json<TestIpRequest>) -> impl IntoResponse {
    let config = payload.config;
    if let Some(fetcher) = create_ip_fetcher(&config) {
        let is_v4_test = payload.ip_type.as_deref() == Some("ipv4");
        let is_v6_test = payload.ip_type.as_deref() == Some("ipv6");

        let ipv4 = if is_v6_test {
            None
        } else {
            fetcher
                .fetch_ipv4()
                .await
                .ok()
                .flatten()
                .map(|ip| ip.to_string())
        };

        let ipv6 = if is_v4_test {
            None
        } else {
            fetcher
                .fetch_ipv6()
                .await
                .ok()
                .flatten()
                .map(|ip| ip.to_string())
        };

        Json(ApiResponse::ok(TestIpResult { ipv4, ipv6 }))
    } else {
        Json(ApiResponse::<TestIpResult>::err(
            "无法创建 IP 提取器，请检查是否填写了网卡名称或有效的 URL".to_string(),
        ))
    }
}

/// 测试通知发送（优先提取当前已配置的真实公网 IP 与真实域名数据）
pub async fn test_notify_handler(
    State(state): State<AppState>,
    Json(config): Json<NotificationConfig>,
) -> impl IntoResponse {
    let app_config = state.config_manager.get_config();
    let dispatcher = NotificationDispatcher::new(config);

    // 尝试从当前任务中探测真实 IP 并生成真实测试数据
    let task = app_config.dns_tasks.first();
    let task_name = task
        .map(|t| t.name.clone())
        .unwrap_or_else(|| "默认任务".to_string());

    let mut ipv4 = None;
    let mut ipv6 = None;
    let mut results = Vec::new();

    if let Some(t) = task {
        // 探测真实 IPv4
        if let Some(fetcher) = if t.ipv4.enabled {
            create_ip_fetcher(&t.ipv4)
        } else {
            None
        } {
            ipv4 = fetcher.fetch_ipv4().await.ok().flatten();
        }
        // 探测真实 IPv6
        if let Some(fetcher) = if t.ipv6.enabled {
            create_ip_fetcher(&t.ipv6)
        } else {
            None
        } {
            ipv6 = fetcher.fetch_ipv6().await.ok().flatten();
        }

        // 构建真实的域名结果列表
        for d in &t.ipv4.domains {
            if let Some(parsed) = parse_domain(d) {
                let ip_str = ipv4
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "127.0.0.1".to_string());
                results.push(SyncRecordResult {
                    domain: parsed.full_domain(),
                    record_type: DnsRecordType::A,
                    target_ip: ip_str,
                    status: SyncStatus::Updated,
                    message: "通知通道测试消息（真实 IPv4 数据）".to_string(),
                });
            }
        }

        for d in &t.ipv6.domains {
            if let Some(parsed) = parse_domain(d) {
                let ip_str = ipv6
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "::1".to_string());
                results.push(SyncRecordResult {
                    domain: parsed.full_domain(),
                    record_type: DnsRecordType::AAAA,
                    target_ip: ip_str,
                    status: SyncStatus::Updated,
                    message: "通知通道测试消息（真实 IPv6 数据）".to_string(),
                });
            }
        }
    }

    // 如果未配置任何域名，使用示例域名
    if results.is_empty() {
        results.push(SyncRecordResult {
            domain: "test.example.com".to_string(),
            record_type: if ipv6.is_some() && ipv4.is_none() {
                DnsRecordType::AAAA
            } else {
                DnsRecordType::A
            },
            target_ip: ipv4
                .map(|ip| ip.to_string())
                .or_else(|| ipv6.map(|ip| ip.to_string()))
                .unwrap_or_else(|| "127.0.0.1".to_string()),
            status: SyncStatus::Updated,
            message: "这是一条测试消息，表明通知渠道工作正常！".to_string(),
        });
    }

    let sample_event = NotificationEvent {
        overall_status: NotificationOverallStatus::Success,
        title: "rddns 通知通道测试".to_string(),
        task_name,
        ipv4,
        ipv6,
        ip_changed: true,
        results,
        timestamp: Local::now(),
    };

    dispatcher.dispatch(sample_event);
    Json(ApiResponse::ok(
        "测试通知已派发至已启用的渠道，请查看目标平台",
    ))
}

/// 获取最近操作日志快照
pub async fn get_logs_handler(State(state): State<AppState>) -> impl IntoResponse {
    let logs: Vec<LogEntry> = state.log_buffer.get_recent();
    Json(ApiResponse::ok(logs))
}

/// 获取当前系统可用的网卡列表
pub async fn get_network_interfaces_handler() -> impl IntoResponse {
    let ifaces = crate::ip_fetcher::net_interface::list_system_interfaces();
    Json(ApiResponse::ok(ifaces))
}
