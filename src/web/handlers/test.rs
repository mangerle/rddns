use super::{ApiResponse, AppState};
use crate::config::model::{IpFetchConfig, IpSourceType, NotificationConfig};
use crate::core::domain::parse_domain;
use crate::dns::trait_def::{DnsRecordType, SyncRecordResult, SyncStatus};
use crate::ip_fetcher::create_ip_fetcher;
use crate::notifier::dispatcher::NotificationDispatcher;
use crate::notifier::trait_def::{NotificationEvent, NotificationOverallStatus};
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use chrono::Local;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// 测试通知触发的最小时间间隔，杜绝短时间内滥用中继发送通知 (P1-9)
const TEST_NOTIFY_MIN_INTERVAL: Duration = Duration::from_millis(3000);

/// 上一次触发测试通知的单调时钟时刻
static LAST_NOTIFY_TEST_TIME: Mutex<Option<Instant>> = Mutex::new(None);

/// 测试 IP 提取器配置请求体
#[derive(Debug, Deserialize)]
pub struct TestIpRequest {
    pub ip_type: Option<String>,
    pub http_interface: Option<String>,
    #[serde(flatten)]
    pub config: IpFetchConfig,
}

/// 测试 IP 提取器配置响应
#[derive(Debug, Serialize)]
pub struct TestIpResult {
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
}

/// 校验测试目标 URL 是否安全（防范 SSRF 滥用与协议走私）
async fn validate_safe_url_endpoint(raw_url: &str) -> Result<(), String> {
    crate::util::net::validate_safe_url_endpoint(raw_url).await
}

/// 测试 IP 提取器在线获取
pub async fn test_ip_handler(Json(payload): Json<TestIpRequest>) -> impl IntoResponse {
    let iface = payload.http_interface.as_deref();
    let config = payload.config;

    // 1. 命令型 IP 获取明确禁止在线即时测试（防止 Web API 暴露任意命令执行风险）
    if config.source_type == IpSourceType::Command {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<TestIpResult>::err(
                "命令型 IP 获取不支持在线测试，请保存配置后通过同步日志验证！".to_string(),
            )),
        );
    }

    // 2. URL 型 IP 获取强制校验安全限制 (防范协议走私与 SSRF 滥用)
    if config.source_type == IpSourceType::Url {
        for url in &config.url_endpoints {
            if let Err(err_msg) = validate_safe_url_endpoint(url).await {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ApiResponse::<TestIpResult>::err(err_msg)),
                );
            }
        }
    }

    if let Some(fetcher) = create_ip_fetcher(&config, iface) {
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

        (
            StatusCode::OK,
            Json(ApiResponse::ok(TestIpResult { ipv4, ipv6 })),
        )
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<TestIpResult>::err(
                "无法创建 IP 提取器，请检查网卡、URL 或 STUN 配置是否正确".to_string(),
            )),
        )
    }
}

/// 辅助判断是否配置了至少一个启用的通知渠道
fn has_any_enabled_channel(config: &NotificationConfig) -> bool {
    config.wechat_official.as_ref().is_some_and(|c| c.enabled)
        || config.wecom.as_ref().is_some_and(|c| c.enabled)
        || config.telegram.as_ref().is_some_and(|c| c.enabled)
        || config.dingtalk.as_ref().is_some_and(|c| c.enabled)
        || config.feishu.as_ref().is_some_and(|c| c.enabled)
        || config.bark.as_ref().is_some_and(|c| c.enabled)
        || config.email.as_ref().is_some_and(|c| c.enabled)
        || config.webhook.as_ref().is_some_and(|c| c.enabled)
}

/// 测试通知发送（优先提取当前已配置的真实公网 IP 与真实域名数据）
pub async fn test_notify_handler(
    State(state): State<AppState>,
    Json(config): Json<NotificationConfig>,
) -> impl IntoResponse {
    // 1. 检查是否至少启用了某一个通知渠道（优先阻断空配置）
    if !has_any_enabled_channel(&config) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<()>::err(
                "未启用任何通知渠道，请先启用至少一个通知渠道再进行测试".to_string(),
            )),
        )
            .into_response();
    }

    // 2. 校验所有通知渠道的 URL 地址安全性，防御针对内网及保留地址的 SSRF 探测
    if let Err(e) = crate::web::handlers::config::validate_notification_urls(&config).await {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<()>::err(format!(
                "测试通知失败: {}",
                e.message
            ))),
        )
            .into_response();
    }

    // 3. 频控校验：防止短时间内高频调用通知测试造成垃圾消息轰炸或放大反射攻击 (P1-9)
    {
        let mut last_time = LAST_NOTIFY_TEST_TIME.lock();
        let now = Instant::now();
        if let Some(prev) = *last_time {
            let elapsed = now.saturating_duration_since(prev);
            if elapsed < TEST_NOTIFY_MIN_INTERVAL {
                let remaining_millis = (TEST_NOTIFY_MIN_INTERVAL - elapsed).as_millis();
                let remaining_secs = remaining_millis.div_ceil(1000);
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(ApiResponse::<()>::err(format!(
                        "测试通知发送过于频繁，请等待 {} 秒后重试",
                        remaining_secs
                    ))),
                )
                    .into_response();
            }
        }
        *last_time = Some(now);
    }

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
            create_ip_fetcher(&t.ipv4, t.http_interface.as_deref())
        } else {
            None
        } {
            ipv4 = fetcher.fetch_ipv4().await.ok().flatten();
        }
        // 探测真实 IPv6
        if let Some(fetcher) = if t.ipv6.enabled {
            create_ip_fetcher(&t.ipv6, t.http_interface.as_deref())
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
        task_name,
        ipv4,
        ipv6,
        ip_changed: true,
        results,
        timestamp: Local::now(),
    };

    dispatcher.dispatch_force(sample_event);
    Json(ApiResponse::ok(
        "测试通知已派发至已启用的渠道，请查看目标平台",
    ))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::storage::ConfigManager;
    use crate::core::state::StateManager;
    use std::sync::Arc;
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn test_test_ip_rejects_command() {
        let req = TestIpRequest {
            ip_type: Some("ipv4".to_string()),
            http_interface: None,
            config: IpFetchConfig {
                enabled: true,
                source_type: IpSourceType::Command,
                cmd: Some("whoami".to_string()),
                ..Default::default()
            },
        };
        let res = test_ip_handler(Json(req)).await.into_response();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_test_ip_rejects_invalid_scheme() {
        let req = TestIpRequest {
            ip_type: Some("ipv4".to_string()),
            http_interface: None,
            config: IpFetchConfig {
                enabled: true,
                source_type: IpSourceType::Url,
                url_endpoints: vec!["file:///etc/passwd".to_string()],
                ..Default::default()
            },
        };
        let res = test_ip_handler(Json(req)).await.into_response();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_test_ip_supports_stun() {
        let req = TestIpRequest {
            ip_type: Some("ipv4".to_string()),
            http_interface: None,
            config: IpFetchConfig {
                enabled: true,
                source_type: IpSourceType::Stun,
                stun_server: Some("stun.miwifi.com".to_string()),
                ..Default::default()
            },
        };
        // 确保不会返回 BAD_REQUEST
        let res = test_ip_handler(Json(req)).await.into_response();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_test_ip_rejects_ssrf_private_and_loopback_addresses() {
        let ssrf_targets = vec![
            "http://127.0.0.1:8080/admin",
            "http://localhost:3000/",
            "http://192.168.1.1/router",
            "http://10.0.0.1/",
            "http://172.16.0.1/",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]:8080/",
        ];

        for target in ssrf_targets {
            let req = TestIpRequest {
                ip_type: Some("ipv4".to_string()),
                http_interface: None,
                config: IpFetchConfig {
                    enabled: true,
                    source_type: IpSourceType::Url,
                    url_endpoints: vec![target.to_string()],
                    ..Default::default()
                },
            };
            let res = test_ip_handler(Json(req)).await.into_response();
            assert_eq!(
                res.status(),
                StatusCode::BAD_REQUEST,
                "应拦截 SSRF 目标地址: {}",
                target
            );
        }
    }

    #[tokio::test]
    async fn test_test_notify_rejects_empty_channel() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let config_manager = Arc::new(ConfigManager::load_or_create(config_path).unwrap());
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let state = AppState {
            config_manager,
            trigger_sender: tx,
            log_buffer: crate::util::logging::LogBuffer::new(10),
            state_manager: StateManager::new(),
            cancel_token: CancellationToken::new(),
            active_listen_port: 9876,
            active_not_allow_wan_access: true,
        };

        let empty_config = NotificationConfig::default();
        let res = test_notify_handler(State(state), Json(empty_config))
            .await
            .into_response();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_test_notify_rate_limit() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let config_manager = Arc::new(ConfigManager::load_or_create(config_path).unwrap());
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let state = AppState {
            config_manager,
            trigger_sender: tx,
            log_buffer: crate::util::logging::LogBuffer::new(10),
            state_manager: StateManager::new(),
            cancel_token: CancellationToken::new(),
            active_listen_port: 9876,
            active_not_allow_wan_access: true,
        };

        let mut config = NotificationConfig::default();
        config.telegram = Some(crate::config::model::TelegramConfig {
            enabled: true,
            bot_token: "fake_token".to_string(),
            chat_id: "fake_id".to_string(),
            api_proxy: None,
        });

        // 第一次调用设置限流时间戳
        let _ = test_notify_handler(State(state.clone()), Json(config.clone())).await;

        // 连续快速调用第二次，必须被频控拦截并返回 429
        let res2 = test_notify_handler(State(state), Json(config))
            .await
            .into_response();
        assert_eq!(res2.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
