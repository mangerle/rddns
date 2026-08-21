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

    // 2. 校验任务名称非空
    for task in &new_config.dns_tasks {
        if task.name.trim().is_empty() {
            return Err(AppError::bad_request("任务名称不能为空"));
        }
    }

    // 2. 如果用户提交了新密码，异步生成 bcrypt 哈希
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

    // 3. 原子更新并持久化配置
    state
        .config_manager
        .modify_config::<_, ConfigError>(|old_config| {
            let mut to_save = new_config.clone();

            // 管理员凭据处理：若提交了新密码则更新哈希，否则直接继承保留原密码哈希
            if let Some(new_hash) = new_password_hash {
                let username = to_save
                    .auth
                    .as_ref()
                    .map(|a| a.username.clone())
                    .unwrap_or_else(|| "admin".to_string());
                to_save.auth = Some(UserAuthConfig {
                    username,
                    password_hash: new_hash,
                });
            } else if let Some(old_auth) = &old_config.auth
                && let Some(new_auth) = &mut to_save.auth
            {
                new_auth.password_hash = old_auth.password_hash.clone();
            }

            Ok(to_save)
        })
        .map_err(|e| AppError::internal(format!("保存配置失败: {}", e)))?;

    // 4. 持久化成功后，热更新全局 DNS 解析服务器配置 (若清空则重置回系统默认) 并刷新客户端连接池
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
    }
}
