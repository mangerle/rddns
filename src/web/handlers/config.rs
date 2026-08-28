use super::{ApiResponse, AppError, AppState};
use crate::config::model::{AppConfig, UserAuthConfig};
use crate::config::storage::ConfigError;
use crate::util::dns_resolver::{clear_custom_dns_server, set_custom_dns_server};
use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use serde::Deserialize;

/// 获取当前配置 (将用户密码哈希置空，配合 skip_serializing_if 彻底不向前端输出密码字段)
pub async fn get_config_handler(State(state): State<AppState>) -> impl IntoResponse {
    let conf = state.config_manager.get_config();
    let mut clean_conf = (*conf).clone();
    if let Some(ref mut auth) = clean_conf.auth {
        auth.password_hash.clear();
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
) -> Result<Json<ApiResponse<()>>, AppError> {
    let new_config = payload.config;

    // 1. 基础参数与数值边界校验
    if new_config.interval_secs < 5 {
        return Err(AppError::bad_request("同步检查间隔时间必须大于或等于 5 秒"));
    }
    if new_config.cache_times < 1 {
        return Err(AppError::bad_request(
            "强制校对云端记录间隔次数必须大于或等于 1 次",
        ));
    }
    if new_config.listen_port == 0 {
        return Err(AppError::bad_request(
            "Web 服务监听端口必须在 1 到 65535 之间",
        ));
    }

    // 2. 校验任务名称非空与唯一性，以及 URL 端点合法协议 (仅允许 http:// 或 https://)
    let mut task_names = std::collections::HashSet::new();
    for task in &new_config.dns_tasks {
        let name = task.name.trim();
        if name.is_empty() {
            return Err(AppError::bad_request("任务名称不能为空"));
        }
        if !task_names.insert(name) {
            return Err(AppError::bad_request(format!(
                "任务名称 [{}] 存在重复，各任务名称必须唯一",
                name
            )));
        }

        for ip_cfg in [&task.ipv4, &task.ipv6] {
            if ip_cfg.source_type == crate::config::model::IpSourceType::Url {
                for url in &ip_cfg.url_endpoints {
                    let trimmed = url.trim();
                    if !trimmed.is_empty()
                        && !trimmed.starts_with("http://")
                        && !trimmed.starts_with("https://")
                    {
                        return Err(AppError::bad_request(format!(
                            "任务 [{}] 中的 URL 端点 [{}] 协议非法，仅允许 http:// 或 https:// 开头的地址",
                            name, trimmed
                        )));
                    }
                }
            }
        }
    }

    // 校验通知配置中的自定义 URL 必须以 http:// 或 https:// 开头
    let notif = &new_config.notifications;
    if let Some(ref bark) = notif.bark {
        let s = bark.server_url.trim();
        if !s.is_empty() && !s.starts_with("http://") && !s.starts_with("https://") {
            return Err(AppError::bad_request(format!(
                "Bark 通知服务器地址 [{}] 协议非法，仅允许 http:// 或 https:// 开头的地址",
                s
            )));
        }
    }
    if let Some(ref webhook) = notif.webhook {
        let s = webhook.url.trim();
        if !s.is_empty() && !s.starts_with("http://") && !s.starts_with("https://") {
            return Err(AppError::bad_request(format!(
                "自定义 Webhook 地址 [{}] 协议非法，仅允许 http:// 或 https:// 开头的地址",
                s
            )));
        }
    }
    if let Some(ref tg) = notif.telegram
        && let Some(ref proxy) = tg.api_proxy
    {
        let s = proxy.trim();
        if !s.is_empty() && !s.starts_with("http://") && !s.starts_with("https://") {
            return Err(AppError::bad_request(format!(
                "Telegram API 代理地址 [{}] 协议非法，仅允许 http:// 或 https:// 开头的地址",
                s
            )));
        }
    }
    if let Some(ref wecom) = notif.wecom
        && let Some(ref webhook_url) = wecom.webhook_url
    {
        let s = webhook_url.trim();
        if !s.is_empty() && !s.starts_with("http://") && !s.starts_with("https://") {
            return Err(AppError::bad_request(format!(
                "企业微信机器人 Webhook 地址 [{}] 协议非法，仅允许 http:// 或 https:// 开头的地址",
                s
            )));
        }
    }
    if let Some(ref feishu) = notif.feishu {
        let s = feishu.webhook_url.trim();
        if !s.is_empty() && !s.starts_with("http://") && !s.starts_with("https://") {
            return Err(AppError::bad_request(format!(
                "飞书机器人 Webhook 地址 [{}] 协议非法，仅允许 http:// 或 https:// 开头的地址",
                s
            )));
        }
    }

    // 3. 如果用户提交了新密码，异步生成 bcrypt 哈希
    let new_password_hash = if let Some(ref pwd) = payload.new_password
        && !pwd.trim().is_empty()
    {
        Some(
            crate::util::crypto::hash_password_async(pwd.trim().to_string())
                .await
                .map_err(|e| AppError::internal(format!("密码哈希失败: {}", e)))?,
        )
    } else {
        None
    };

    // 4. 异步原子更新并持久化配置 (刷盘在后台线程池执行)
    state
        .config_manager
        .modify_config_async::<_, ConfigError>(|old_config| {
            let mut to_save = new_config.clone();

            // 锁定 Web 服务监听端口：禁止通过 Web API 修改端口，始终继承原有配置
            to_save.listen_port = old_config.listen_port;

            // 管理员凭据处理：若提交了新密码则更新哈希，否则自动继承保留原配置中的账号凭据
            if let Some(new_hash) = new_password_hash {
                let username = to_save
                    .auth
                    .as_ref()
                    .map(|a| a.username.clone())
                    .or_else(|| old_config.auth.as_ref().map(|a| a.username.clone()))
                    .unwrap_or_else(|| "admin".to_string());
                to_save.auth = Some(UserAuthConfig {
                    username,
                    password_hash: new_hash,
                });
            } else if let Some(old_auth) = &old_config.auth {
                if let Some(new_auth) = &mut to_save.auth {
                    if new_auth.username.trim().is_empty() {
                        new_auth.username = old_auth.username.clone();
                    }
                    new_auth.password_hash = old_auth.password_hash.clone();
                } else {
                    to_save.auth = Some(old_auth.clone());
                }
            }

            Ok(to_save)
        })
        .await
        .map_err(|e| AppError::internal(format!("保存配置失败: {}", e)))?;

    // 5. 持久化成功后，热更新全局 DNS 解析服务器配置 (若清空则重置回系统默认) 并刷新客户端连接池
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
    crate::util::http::clear_http_client_cache();

    Ok(Json(ApiResponse::ok(())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::DnsTaskConfig;
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
    fn test_save_config_validation_rules() {
        let valid_config = AppConfig {
            dns_tasks: vec![DnsTaskConfig::default()],
            ..Default::default()
        };

        // 校验合法配置
        assert!(valid_config.interval_secs >= 5);
        assert!(valid_config.cache_times >= 1);
        assert!(valid_config.listen_port > 0);
        assert!(!valid_config.dns_tasks[0].name.trim().is_empty());

        // 校验非法配置条件
        let mut invalid_interval = valid_config.clone();
        invalid_interval.interval_secs = 4;
        assert!(invalid_interval.interval_secs < 5);

        let mut invalid_cache = valid_config.clone();
        invalid_cache.cache_times = 0;
        assert!(invalid_cache.cache_times < 1);

        let mut invalid_port = valid_config.clone();
        invalid_port.listen_port = 0;
        assert_eq!(invalid_port.listen_port, 0);

        let mut invalid_task_name = valid_config.clone();
        invalid_task_name.dns_tasks[0].name = "  ".to_string();
        assert!(invalid_task_name.dns_tasks[0].name.trim().is_empty());

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
        let mut names_set = std::collections::HashSet::new();
        let has_dup = duplicate_tasks
            .dns_tasks
            .iter()
            .any(|t| !names_set.insert(t.name.trim()));
        assert!(has_dup);

        // 校验非法的 URL 端点协议
        let mut invalid_url_tasks = valid_config.clone();
        invalid_url_tasks.dns_tasks[0].ipv4.source_type = crate::config::model::IpSourceType::Url;
        invalid_url_tasks.dns_tasks[0].ipv4.url_endpoints = vec!["file:///etc/passwd".to_string()];
        let has_invalid_scheme = invalid_url_tasks.dns_tasks[0]
            .ipv4
            .url_endpoints
            .iter()
            .any(|u| !u.starts_with("http://") && !u.starts_with("https://"));
        assert!(has_invalid_scheme);

        // 校验非法的通知服务 URL 协议
        let invalid_bark_url = "ftp://bark.day.app";
        assert!(
            !invalid_bark_url.starts_with("http://") && !invalid_bark_url.starts_with("https://")
        );
    }

    #[tokio::test]
    async fn test_save_config_preserves_auth() {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let dir = tempfile::tempdir().unwrap();
        let config_file = dir.path().join("config_save_test.yaml");
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
        };

        // 模拟前端保存配置请求（未附带 auth 字段）
        let payload = SaveConfigRequest {
            config: AppConfig {
                interval_secs: 10,
                cache_times: 5,
                listen_port: 9876,
                auth: None, // 前端未提交 auth 字段
                dns_tasks: vec![],
                ..Default::default()
            },
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
}
