use super::{ApiResponse, AppError, AppState};
use crate::config::model::{AppConfig, NotificationConfig, ProviderConfig, UserAuthConfig};
use crate::config::storage::ConfigError;
use crate::util::dns_resolver::{clear_custom_dns_server, set_custom_dns_server};
use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use serde::Deserialize;

/// 获取当前配置 (并对所有敏感凭据实施掩码保护)
pub async fn get_config_handler(State(state): State<AppState>) -> impl IntoResponse {
    let conf = state.config_manager.get_config();
    let mut clean_conf = (*conf).clone();
    mask_sensitive_credentials_for_ui(&mut clean_conf);
    Json(ApiResponse::ok(clean_conf))
}

/// 对配置数据中的关键敏感项（如密码哈希）进行脱敏保护
pub fn mask_sensitive_credentials_for_ui(conf: &mut AppConfig) {
    if let Some(ref mut auth) = conf.auth {
        auth.password_hash = "******".to_string();
    }
}

#[derive(Debug, Deserialize)]
pub struct SaveConfigRequest {
    pub config: AppConfig,
    pub new_password: Option<String>,
}

/// 合并新旧配置中的敏感凭据 (如果新配置包含 "******" 占位符则保留旧凭据)
pub fn merge_sensitive_credentials(new_conf: &mut AppConfig, old_conf: &AppConfig) {
    let is_masked = |s: &str| s.trim() == "******";

    // 1. 管理员密码哈希
    if let Some(new_auth) = &mut new_conf.auth
        && is_masked(&new_auth.password_hash)
        && let Some(old_auth) = &old_conf.auth
    {
        new_auth.password_hash = old_auth.password_hash.clone();
    }

    // 2. DNS 任务提供商凭据 (优先按任务名称精确匹配，防止任务重排或删除时按索引错位)
    let old_tasks_len = old_conf.dns_tasks.len();
    let new_tasks_len = new_conf.dns_tasks.len();
    for (i, new_task) in new_conf.dns_tasks.iter_mut().enumerate() {
        let old_task_opt = old_conf
            .dns_tasks
            .iter()
            .find(|t| t.name == new_task.name)
            .or_else(|| {
                if old_tasks_len == new_tasks_len {
                    old_conf.dns_tasks.get(i)
                } else {
                    None
                }
            });

        if let Some(old_task) = old_task_opt {
            match (&mut new_task.provider, &old_task.provider) {
                (
                    ProviderConfig::Cloudflare {
                        api_token: new_t,
                        api_key: new_k,
                        ..
                    },
                    ProviderConfig::Cloudflare {
                        api_token: old_t,
                        api_key: old_k,
                        ..
                    },
                ) => {
                    if new_t.as_deref().map(is_masked).unwrap_or(false) {
                        *new_t = old_t.clone();
                    }
                    if new_k.as_deref().map(is_masked).unwrap_or(false) {
                        *new_k = old_k.clone();
                    }
                }
                (
                    ProviderConfig::AliDns {
                        access_key_secret: new_s,
                        ..
                    },
                    ProviderConfig::AliDns {
                        access_key_secret: old_s,
                        ..
                    },
                ) => {
                    if is_masked(new_s) {
                        *new_s = old_s.clone();
                    }
                }
                (
                    ProviderConfig::TencentCloud {
                        secret_key: new_s, ..
                    },
                    ProviderConfig::TencentCloud {
                        secret_key: old_s, ..
                    },
                ) => {
                    if is_masked(new_s) {
                        *new_s = old_s.clone();
                    }
                }
                (
                    ProviderConfig::HuaweiCloud {
                        secret_access_key: new_s,
                        ..
                    },
                    ProviderConfig::HuaweiCloud {
                        secret_access_key: old_s,
                        ..
                    },
                ) => {
                    if is_masked(new_s) {
                        *new_s = old_s.clone();
                    }
                }
                (
                    ProviderConfig::Porkbun {
                        secret_key: new_s, ..
                    },
                    ProviderConfig::Porkbun {
                        secret_key: old_s, ..
                    },
                ) => {
                    if is_masked(new_s) {
                        *new_s = old_s.clone();
                    }
                }
                (
                    ProviderConfig::GoDaddy {
                        api_secret: new_s, ..
                    },
                    ProviderConfig::GoDaddy {
                        api_secret: old_s, ..
                    },
                ) => {
                    if is_masked(new_s) {
                        *new_s = old_s.clone();
                    }
                }
                (
                    ProviderConfig::Dynv6 { token: new_t },
                    ProviderConfig::Dynv6 { token: old_t },
                ) => {
                    if is_masked(new_t) {
                        *new_t = old_t.clone();
                    }
                }
                (
                    ProviderConfig::BaiduCloud {
                        secret_access_key: new_s,
                        ..
                    },
                    ProviderConfig::BaiduCloud {
                        secret_access_key: old_s,
                        ..
                    },
                ) => {
                    if is_masked(new_s) {
                        *new_s = old_s.clone();
                    }
                }
                (
                    ProviderConfig::TrafficRoute {
                        secret_access_key: new_s,
                        ..
                    },
                    ProviderConfig::TrafficRoute {
                        secret_access_key: old_s,
                        ..
                    },
                ) => {
                    if is_masked(new_s) {
                        *new_s = old_s.clone();
                    }
                }
                (
                    ProviderConfig::Namecheap { password: new_p },
                    ProviderConfig::Namecheap { password: old_p },
                ) => {
                    if is_masked(new_p) {
                        *new_p = old_p.clone();
                    }
                }
                (
                    ProviderConfig::NameSilo { api_key: new_k },
                    ProviderConfig::NameSilo { api_key: old_k },
                ) => {
                    if is_masked(new_k) {
                        *new_k = old_k.clone();
                    }
                }
                (
                    ProviderConfig::Spaceship {
                        api_secret: new_s, ..
                    },
                    ProviderConfig::Spaceship {
                        api_secret: old_s, ..
                    },
                ) => {
                    if is_masked(new_s) {
                        *new_s = old_s.clone();
                    }
                }
                (
                    ProviderConfig::Dynadot { password: new_p },
                    ProviderConfig::Dynadot { password: old_p },
                ) => {
                    if is_masked(new_p) {
                        *new_p = old_p.clone();
                    }
                }
                (
                    ProviderConfig::Vercel { token: new_t, .. },
                    ProviderConfig::Vercel { token: old_t, .. },
                ) => {
                    if is_masked(new_t) {
                        *new_t = old_t.clone();
                    }
                }
                (
                    ProviderConfig::RainYun { api_key: new_k, .. },
                    ProviderConfig::RainYun { api_key: old_k, .. },
                ) => {
                    if is_masked(new_k) {
                        *new_k = old_k.clone();
                    }
                }
                (
                    ProviderConfig::ClouDNS {
                        auth_password: new_p,
                        ..
                    },
                    ProviderConfig::ClouDNS {
                        auth_password: old_p,
                        ..
                    },
                ) => {
                    if is_masked(new_p) {
                        *new_p = old_p.clone();
                    }
                }
                (
                    ProviderConfig::Gcore { api_key: new_k },
                    ProviderConfig::Gcore { api_key: old_k },
                ) => {
                    if is_masked(new_k) {
                        *new_k = old_k.clone();
                    }
                }
                (
                    ProviderConfig::NameCom {
                        api_token: new_t, ..
                    },
                    ProviderConfig::NameCom {
                        api_token: old_t, ..
                    },
                ) => {
                    if is_masked(new_t) {
                        *new_t = old_t.clone();
                    }
                }
                (
                    ProviderConfig::DnsLa {
                        api_secret: new_s, ..
                    },
                    ProviderConfig::DnsLa {
                        api_secret: old_s, ..
                    },
                ) => {
                    if is_masked(new_s) {
                        *new_s = old_s.clone();
                    }
                }
                (
                    ProviderConfig::AliEsa {
                        access_key_secret: new_s,
                        ..
                    },
                    ProviderConfig::AliEsa {
                        access_key_secret: old_s,
                        ..
                    },
                ) => {
                    if is_masked(new_s) {
                        *new_s = old_s.clone();
                    }
                }
                (
                    ProviderConfig::EdgeOne {
                        secret_key: new_s, ..
                    },
                    ProviderConfig::EdgeOne {
                        secret_key: old_s, ..
                    },
                ) => {
                    if is_masked(new_s) {
                        *new_s = old_s.clone();
                    }
                }
                (
                    ProviderConfig::NowCn { secret: new_s, .. },
                    ProviderConfig::NowCn { secret: old_s, .. },
                ) => {
                    if is_masked(new_s) {
                        *new_s = old_s.clone();
                    }
                }
                (
                    ProviderConfig::Eranet { secret: new_s, .. },
                    ProviderConfig::Eranet { secret: old_s, .. },
                ) => {
                    if is_masked(new_s) {
                        *new_s = old_s.clone();
                    }
                }
                (
                    ProviderConfig::TNetHk { secret: new_s, .. },
                    ProviderConfig::TNetHk { secret: old_s, .. },
                ) => {
                    if is_masked(new_s) {
                        *new_s = old_s.clone();
                    }
                }
                (
                    ProviderConfig::NsOne { api_key: new_k },
                    ProviderConfig::NsOne { api_key: old_k },
                ) if is_masked(new_k) => {
                    *new_k = old_k.clone();
                }
                (
                    ProviderConfig::HipmDnsMgr {
                        api_token: new_t, ..
                    },
                    ProviderConfig::HipmDnsMgr {
                        api_token: old_t, ..
                    },
                ) if is_masked(new_t) => {
                    *new_t = old_t.clone();
                }
                _ => {}
            }
        }
    }

    // 3. 通知渠道敏感凭据
    merge_notification_credentials(&mut new_conf.notifications, &old_conf.notifications);
}

/// 合并通知配置中的敏感凭据 (如果包含 "******" 掩码则还原为已保存的真实凭据)
pub fn merge_notification_credentials(
    new_notif: &mut NotificationConfig,
    old_notif: &NotificationConfig,
) {
    let is_masked = |s: &str| s.trim() == "******";

    if let (Some(new_wx), Some(old_wx)) =
        (&mut new_notif.wechat_official, &old_notif.wechat_official)
        && is_masked(&new_wx.app_secret)
    {
        new_wx.app_secret = old_wx.app_secret.clone();
    }

    if let (Some(new_wc), Some(old_wc)) = (&mut new_notif.wecom, &old_notif.wecom)
        && new_wc
            .corp_secret
            .as_deref()
            .map(is_masked)
            .unwrap_or(false)
    {
        new_wc.corp_secret = old_wc.corp_secret.clone();
    }

    if let (Some(new_tg), Some(old_tg)) = (&mut new_notif.telegram, &old_notif.telegram)
        && is_masked(&new_tg.bot_token)
    {
        new_tg.bot_token = old_tg.bot_token.clone();
    }

    if let (Some(new_dt), Some(old_dt)) = (&mut new_notif.dingtalk, &old_notif.dingtalk)
        && new_dt.secret.as_deref().map(is_masked).unwrap_or(false)
    {
        new_dt.secret = old_dt.secret.clone();
    }

    if let (Some(new_fs), Some(old_fs)) = (&mut new_notif.feishu, &old_notif.feishu)
        && new_fs.secret.as_deref().map(is_masked).unwrap_or(false)
    {
        new_fs.secret = old_fs.secret.clone();
    }

    if let (Some(new_em), Some(old_em)) = (&mut new_notif.email, &old_notif.email)
        && is_masked(&new_em.password)
    {
        new_em.password = old_em.password.clone();
    }
}

/// 保存更新配置
pub async fn save_config_handler(
    State(state): State<AppState>,
    Json(payload): Json<SaveConfigRequest>,
) -> Result<Json<ApiResponse<()>>, AppError> {
    let mut new_config = payload.config;

    // 校验任务名称非空
    for task in &new_config.dns_tasks {
        if task.name.trim().is_empty() {
            return Err(AppError::bad_request("任务名称不能为空"));
        }
    }

    // 如果用户提交了新密码，生成 bcrypt 哈希
    if let Some(ref pwd) = payload.new_password
        && !pwd.trim().is_empty()
    {
        let hash = bcrypt::hash(pwd.trim(), bcrypt::DEFAULT_COST)
            .map_err(|e| AppError::internal(format!("密码哈希失败: {}", e)))?;
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

    // 热更新全局 DNS 解析服务器配置 (若清空则重置回系统默认)
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

    state
        .config_manager
        .modify_config::<_, ConfigError>(|old_config| {
            let mut to_save = new_config.clone();
            merge_sensitive_credentials(&mut to_save, old_config);
            Ok(to_save)
        })
        .map_err(|e| AppError::internal(format!("保存配置失败: {}", e)))?;

    Ok(Json(ApiResponse::ok(())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::{DnsTaskConfig, FeishuConfig, ProviderConfig};

    #[test]
    fn test_merge_sensitive_credentials_by_task_name() {
        let old_conf = AppConfig {
            dns_tasks: vec![
                DnsTaskConfig {
                    name: "任务1".to_string(),
                    provider: ProviderConfig::Cloudflare {
                        api_token: Some("real_token_1".to_string()),
                        api_key: None,
                        email: None,
                    },
                    ..Default::default()
                },
                DnsTaskConfig {
                    name: "任务2".to_string(),
                    provider: ProviderConfig::AliDns {
                        access_key_id: "ak2".to_string(),
                        access_key_secret: "real_secret_2".to_string(),
                        endpoint: None,
                    },
                    ..Default::default()
                },
            ],
            ..Default::default()
        };

        // 新配置调整了任务顺序，并且包含掩码
        let mut new_conf = AppConfig {
            dns_tasks: vec![
                DnsTaskConfig {
                    name: "任务2".to_string(),
                    provider: ProviderConfig::AliDns {
                        access_key_id: "ak2".to_string(),
                        access_key_secret: "******".to_string(),
                        endpoint: None,
                    },
                    ..Default::default()
                },
                DnsTaskConfig {
                    name: "任务1".to_string(),
                    provider: ProviderConfig::Cloudflare {
                        api_token: Some("******".to_string()),
                        api_key: None,
                        email: None,
                    },
                    ..Default::default()
                },
            ],
            ..Default::default()
        };

        merge_sensitive_credentials(&mut new_conf, &old_conf);

        // 验证任务2准确保留了自身的 secret，而不是因为排在第0个就被赋给任务1的 token
        if let ProviderConfig::AliDns {
            ref access_key_secret,
            ..
        } = new_conf.dns_tasks[0].provider
        {
            assert_eq!(access_key_secret, "real_secret_2");
        } else {
            panic!("类型不匹配");
        }

        if let ProviderConfig::Cloudflare { ref api_token, .. } = new_conf.dns_tasks[1].provider {
            assert_eq!(api_token.as_deref(), Some("real_token_1"));
        } else {
            panic!("类型不匹配");
        }
    }

    #[test]
    fn test_mask_sensitive_credentials_for_ui() {
        let mut conf = AppConfig {
            auth: Some(UserAuthConfig {
                username: "admin".to_string(),
                password_hash: "hashed_secret_pw".to_string(),
            }),
            ..Default::default()
        };

        mask_sensitive_credentials_for_ui(&mut conf);

        assert_eq!(conf.auth.unwrap().password_hash, "******");
    }

    #[test]
    fn test_task_enabled_serialization() {
        let yaml_str = r#"
name: "测试已禁用任务"
enabled: false
provider:
  type: "cloudflare"
ipv4:
  enabled: true
  source_type: "url"
  domains:
    - "test.example.com"
"#;
        let task: DnsTaskConfig = serde_yaml::from_str(yaml_str).unwrap();
        assert!(!task.enabled);

        let default_yaml = r#"
name: "测试默认启用任务"
provider:
  type: "cloudflare"
"#;
        let task_default: DnsTaskConfig = serde_yaml::from_str(default_yaml).unwrap();
        assert!(task_default.enabled);
    }

    #[test]
    fn test_merge_notification_credentials() {
        let old_notif = NotificationConfig {
            feishu: Some(FeishuConfig {
                enabled: true,
                webhook_url: "https://open.feishu.cn/hook/xxx".to_string(),
                secret: Some("real_secret_123456".to_string()),
            }),
            ..Default::default()
        };

        // 用户在前端界面点击测试时，前端表单传过来的是脱敏的 "******"
        let mut new_notif = NotificationConfig {
            feishu: Some(FeishuConfig {
                enabled: true,
                webhook_url: "https://open.feishu.cn/hook/xxx".to_string(),
                secret: Some("******".to_string()),
            }),
            ..Default::default()
        };

        merge_notification_credentials(&mut new_notif, &old_notif);

        // 验证掩码已被正确还原为真实的 secret
        assert_eq!(
            new_notif.feishu.unwrap().secret,
            Some("real_secret_123456".to_string())
        );
    }
}
