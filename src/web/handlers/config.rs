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
            // 配置版本号由加载期的迁移链统一管理，Web 保存不参与版本变更 (P1-4)
            config_version: crate::config::model::CURRENT_CONFIG_VERSION,
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
mod tests;
