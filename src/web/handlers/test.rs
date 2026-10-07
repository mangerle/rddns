use super::{ApiResponse, AppState};
use crate::config::model::{AppConfig, IpFetchConfig, IpSourceType, NotificationConfig};
use crate::core::domain::parse_domain;
use crate::core::state::StateManager;
use crate::dns::trait_def::{DnsRecordType, SyncRecordResult, SyncStatus};
use crate::ip_fetcher::create_ip_fetcher;
use crate::notifier::dispatcher::NotificationDispatcher;
use crate::notifier::trait_def::{NotificationEvent, NotificationOverallStatus};
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use chrono::Local;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// 测试通知触发的最小时间间隔，杜绝短时间内滥用中继发送通知 (P1-9)
const TEST_NOTIFY_MIN_INTERVAL: Duration = Duration::from_millis(3000);

/// 上一次触发测试通知的单调时钟时刻
static LAST_NOTIFY_TEST_TIME: Mutex<Option<Instant>> = Mutex::new(None);

/// 测试 IP 提取触发的最小时间间隔，杜绝短时间内高频调用作为外部 HTTP 反射源 (L-8)
const TEST_IP_MIN_INTERVAL: Duration = Duration::from_millis(1000);

/// 上一次触发测试 IP 获取的单调时钟时刻
static LAST_IP_TEST_TIME: Mutex<Option<Instant>> = Mutex::new(None);

/// 重置在线测试接口的全局频控状态（仅供测试套件保证用例间隔离）
#[cfg(test)]
pub(crate) fn reset_test_rate_limiters() {
    *LAST_NOTIFY_TEST_TIME.lock() = None;
    *LAST_IP_TEST_TIME.lock() = None;
}

/// 通用单调时钟频控检查器
fn check_rate_limit(
    tracker: &Mutex<Option<Instant>>,
    min_interval: Duration,
    action_label: &str,
) -> Result<(), String> {
    let mut last_time = tracker.lock();
    let now = Instant::now();
    if let Some(prev) = *last_time {
        let elapsed = now.saturating_duration_since(prev);
        if elapsed < min_interval {
            let remaining_secs = (min_interval - elapsed).as_millis().div_ceil(1000);
            return Err(format!(
                "{}过于频繁，请等待 {} 秒后重试",
                action_label, remaining_secs
            ));
        }
    }
    *last_time = Some(now);
    Ok(())
}

/// 测试 IP 提取器配置请求体
#[derive(Debug, Clone, Deserialize)]
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

/// 测试通知请求体（同时兼容前端 `{ channel?, config }` 嵌套结构与直接平铺 `NotificationConfig`）
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TestNotifyRequest {
    #[serde(default)]
    pub channel: Option<String>,
    #[serde(default)]
    pub config: Option<NotificationConfig>,
    #[serde(flatten)]
    pub flat_config: NotificationConfig,
}

impl TestNotifyRequest {
    /// 解析最终生效的目标单渠道名称与通知配置
    pub fn into_resolved(self) -> (Option<String>, NotificationConfig) {
        let cfg = self.config.unwrap_or(self.flat_config);
        let channel = self
            .channel
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty());
        (channel, cfg)
    }
}

impl From<NotificationConfig> for TestNotifyRequest {
    fn from(config: NotificationConfig) -> Self {
        Self {
            channel: None,
            config: Some(config),
            flat_config: NotificationConfig::default(),
        }
    }
}

/// 校验测试目标 URL 是否安全（防范 SSRF 滥用与协议走私）
async fn validate_safe_url_endpoint(raw_url: &str) -> Result<(), String> {
    crate::util::net::validate_safe_url_endpoint(raw_url).await
}

/// 测试 IP 提取器在线获取
pub async fn test_ip_handler(Json(payload): Json<TestIpRequest>) -> impl IntoResponse {
    if let Err(msg) = check_rate_limit(&LAST_IP_TEST_TIME, TEST_IP_MIN_INTERVAL, "IP 测试请求")
    {
        return (StatusCode::TOO_MANY_REQUESTS, Json(ApiResponse::err(msg)));
    }

    let iface = payload.http_interface.as_deref();
    let config = payload.config;

    if config.source_type == IpSourceType::Command {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<TestIpResult>::err(
                "命令型 IP 获取不支持在线测试，请保存配置后通过同步日志验证！".to_string(),
            )),
        );
    }

    if config.source_type == IpSourceType::Url {
        for url in &config.url_endpoints {
            if let Err(err_msg) = validate_safe_url_endpoint(url).await {
                return (StatusCode::BAD_REQUEST, Json(ApiResponse::err(err_msg)));
            }
        }
    }

    let Some(fetcher) = create_ip_fetcher(&config, iface) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err(
                "无法创建 IP 提取器，请检查网卡、URL 或 STUN 配置是否正确".to_string(),
            )),
        );
    };

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

/// 从内存缓存状态与首个任务配置组装测试通知事件（避免在测试通知接口内同步发起网络 IP 探测）
fn build_sample_notify_event(
    app_config: &AppConfig,
    state_manager: &StateManager,
) -> NotificationEvent {
    let task = app_config.dns_tasks.first();
    let task_name = task
        .map(|t| t.name.clone())
        .unwrap_or_else(|| "默认任务".to_string());
    let task_state = state_manager.get_task_state(&task_name);
    let ipv4 = task_state.last_ipv4;
    let ipv6 = task_state.last_ipv6;
    let mut results = Vec::with_capacity(4);

    if let Some(t) = task {
        let v4_str = ipv4
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "127.0.0.1".to_string());
        for d in &t.ipv4.domains {
            if let Some(parsed) = parse_domain(d) {
                results.push(SyncRecordResult {
                    domain: parsed.full_domain(),
                    record_type: DnsRecordType::A,
                    target_ip: v4_str.clone(),
                    status: SyncStatus::Updated,
                    message: "通知通道测试消息（IPv4 数据）".to_string(),
                });
            }
        }
        let v6_str = ipv6
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "::1".to_string());
        for d in &t.ipv6.domains {
            if let Some(parsed) = parse_domain(d) {
                results.push(SyncRecordResult {
                    domain: parsed.full_domain(),
                    record_type: DnsRecordType::AAAA,
                    target_ip: v6_str.clone(),
                    status: SyncStatus::Updated,
                    message: "通知通道测试消息（IPv6 数据）".to_string(),
                });
            }
        }
    }

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

    NotificationEvent {
        overall_status: NotificationOverallStatus::Success,
        task_name,
        ipv4,
        ipv6,
        ip_changed: true,
        results,
        timestamp: Local::now(),
    }
}

/// 测试通知发送（支持单渠道与全量渠道测试，自动还原脱敏凭据并同步更新全局投递状态）
pub async fn test_notify_handler(
    State(state): State<AppState>,
    Json(payload): Json<TestNotifyRequest>,
) -> impl IntoResponse {
    let app_config = state.config_manager.get_config();
    let (target_channel, mut config) = payload.into_resolved();
    config.restore_masked_credentials(&app_config.notifications);

    if let Some(ref ch) = target_channel
        && !config.retain_only_channel(ch)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<()>::err(format!(
                "不支持的通知渠道标识: {}",
                ch
            ))),
        )
            .into_response();
    }

    if !has_any_enabled_channel(&config) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<()>::err(
                "未启用任何通知渠道，请先启用目标通知渠道再进行测试".to_string(),
            )),
        )
            .into_response();
    }

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

    if let Err(msg) = check_rate_limit(
        &LAST_NOTIFY_TEST_TIME,
        TEST_NOTIFY_MIN_INTERVAL,
        "测试通知发送",
    ) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ApiResponse::<()>::err(msg)),
        )
            .into_response();
    }

    let dispatcher = NotificationDispatcher::new_with_trackers_and_statuses(
        config,
        Arc::new(RwLock::new(HashMap::new())),
        state.state_manager.delivery_statuses(),
    );
    let sample_event = build_sample_notify_event(&app_config, &state.state_manager);
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

    /// 跨用例异步互斥锁，确保并发测试执行时进程级限流时间戳互不干扰 (L-13)
    static TEST_RATE_LIMIT_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test]
    async fn test_test_ip_rate_limit() {
        let _lock = TEST_RATE_LIMIT_MUTEX.lock().await;
        reset_test_rate_limiters();
        let req = TestIpRequest {
            ip_type: Some("ipv4".to_string()),
            http_interface: None,
            config: IpFetchConfig {
                enabled: true,
                source_type: IpSourceType::Url,
                url_endpoints: vec!["https://api.ipify.org".to_string()],
                ..Default::default()
            },
        };

        // 第一次调用记录频控时刻
        let _ = test_ip_handler(Json(req.clone())).await;

        // 紧接着立即二次调用，必须触发 429 频控限制 (L-8)
        let res2 = test_ip_handler(Json(req)).await.into_response();
        assert_eq!(res2.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn test_test_ip_rejects_command() {
        let _lock = TEST_RATE_LIMIT_MUTEX.lock().await;
        reset_test_rate_limiters();
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
        let _lock = TEST_RATE_LIMIT_MUTEX.lock().await;
        reset_test_rate_limiters();
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
        let _lock = TEST_RATE_LIMIT_MUTEX.lock().await;
        reset_test_rate_limiters();
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
        let _lock = TEST_RATE_LIMIT_MUTEX.lock().await;
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
            reset_test_rate_limiters();
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
        let res = test_notify_handler(State(state), Json(empty_config.into()))
            .await
            .into_response();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_test_notify_nested_payload_and_single_channel_filter() {
        let _lock = TEST_RATE_LIMIT_MUTEX.lock().await;
        reset_test_rate_limiters();
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

        // 模拟前端实际发送的嵌套 JSON 结构：{ "channel": "telegram", "config": { ... } }
        let raw_json = r#"{
            "channel": "telegram",
            "config": {
                "telegram": {
                    "enabled": true,
                    "bot_token": "******",
                    "chat_id": "123456"
                },
                "webhook": {
                    "enabled": false,
                    "url": "http://127.0.0.1:8080/internal"
                }
            }
        }"#;
        let req: TestNotifyRequest = serde_json::from_str(raw_json).unwrap();
        let res = test_notify_handler(State(state), Json(req))
            .await
            .into_response();
        // 仅保留 telegram 渠道，未启用的 webhook 内网地址不应阻断 telegram 单渠道测试
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_test_notify_rate_limit() {
        let _lock = TEST_RATE_LIMIT_MUTEX.lock().await;
        reset_test_rate_limiters();
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

        let config = NotificationConfig {
            telegram: Some(crate::config::model::TelegramConfig {
                enabled: true,
                bot_token: "fake_token".to_string(),
                chat_id: "fake_id".to_string(),
                api_proxy: None,
            }),
            ..Default::default()
        };

        // 第一次调用设置限流时间戳
        let _ = test_notify_handler(State(state.clone()), Json(config.clone().into())).await;

        // 连续快速调用第二次，必须被频控拦截并返回 429
        let res2 = test_notify_handler(State(state), Json(config.into()))
            .await
            .into_response();
        assert_eq!(res2.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
