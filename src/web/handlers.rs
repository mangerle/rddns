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

/// 合并新旧配置中的敏感凭据 (如果新配置包含 "******" 占位符则保留旧凭据)
fn merge_sensitive_credentials(new_conf: &mut AppConfig, old_conf: &AppConfig) {
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
                    crate::config::model::ProviderConfig::Cloudflare {
                        api_token: new_t,
                        api_key: new_k,
                        ..
                    },
                    crate::config::model::ProviderConfig::Cloudflare {
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
                    crate::config::model::ProviderConfig::AliDns {
                        access_key_secret: new_s,
                        ..
                    },
                    crate::config::model::ProviderConfig::AliDns {
                        access_key_secret: old_s,
                        ..
                    },
                ) => {
                    if is_masked(new_s) {
                        *new_s = old_s.clone();
                    }
                }
                (
                    crate::config::model::ProviderConfig::TencentCloud {
                        secret_key: new_s, ..
                    },
                    crate::config::model::ProviderConfig::TencentCloud {
                        secret_key: old_s, ..
                    },
                ) => {
                    if is_masked(new_s) {
                        *new_s = old_s.clone();
                    }
                }
                (
                    crate::config::model::ProviderConfig::HuaweiCloud {
                        secret_access_key: new_s,
                        ..
                    },
                    crate::config::model::ProviderConfig::HuaweiCloud {
                        secret_access_key: old_s,
                        ..
                    },
                ) => {
                    if is_masked(new_s) {
                        *new_s = old_s.clone();
                    }
                }
                (
                    crate::config::model::ProviderConfig::Porkbun {
                        secret_key: new_s, ..
                    },
                    crate::config::model::ProviderConfig::Porkbun {
                        secret_key: old_s, ..
                    },
                ) => {
                    if is_masked(new_s) {
                        *new_s = old_s.clone();
                    }
                }
                (
                    crate::config::model::ProviderConfig::GoDaddy {
                        api_secret: new_s, ..
                    },
                    crate::config::model::ProviderConfig::GoDaddy {
                        api_secret: old_s, ..
                    },
                ) => {
                    if is_masked(new_s) {
                        *new_s = old_s.clone();
                    }
                }
                (
                    crate::config::model::ProviderConfig::Dynv6 { token: new_t },
                    crate::config::model::ProviderConfig::Dynv6 { token: old_t },
                ) => {
                    if is_masked(new_t) {
                        *new_t = old_t.clone();
                    }
                }
                (
                    crate::config::model::ProviderConfig::BaiduCloud {
                        secret_access_key: new_s,
                        ..
                    },
                    crate::config::model::ProviderConfig::BaiduCloud {
                        secret_access_key: old_s,
                        ..
                    },
                ) => {
                    if is_masked(new_s) {
                        *new_s = old_s.clone();
                    }
                }
                (
                    crate::config::model::ProviderConfig::TrafficRoute {
                        secret_access_key: new_s,
                        ..
                    },
                    crate::config::model::ProviderConfig::TrafficRoute {
                        secret_access_key: old_s,
                        ..
                    },
                ) => {
                    if is_masked(new_s) {
                        *new_s = old_s.clone();
                    }
                }
                (
                    crate::config::model::ProviderConfig::Namecheap { password: new_p },
                    crate::config::model::ProviderConfig::Namecheap { password: old_p },
                ) => {
                    if is_masked(new_p) {
                        *new_p = old_p.clone();
                    }
                }
                (
                    crate::config::model::ProviderConfig::NameSilo { api_key: new_k },
                    crate::config::model::ProviderConfig::NameSilo { api_key: old_k },
                ) => {
                    if is_masked(new_k) {
                        *new_k = old_k.clone();
                    }
                }
                (
                    crate::config::model::ProviderConfig::Spaceship {
                        api_secret: new_s, ..
                    },
                    crate::config::model::ProviderConfig::Spaceship {
                        api_secret: old_s, ..
                    },
                ) => {
                    if is_masked(new_s) {
                        *new_s = old_s.clone();
                    }
                }
                (
                    crate::config::model::ProviderConfig::Dynadot { password: new_p },
                    crate::config::model::ProviderConfig::Dynadot { password: old_p },
                ) => {
                    if is_masked(new_p) {
                        *new_p = old_p.clone();
                    }
                }
                (
                    crate::config::model::ProviderConfig::Vercel { token: new_t, .. },
                    crate::config::model::ProviderConfig::Vercel { token: old_t, .. },
                ) => {
                    if is_masked(new_t) {
                        *new_t = old_t.clone();
                    }
                }
                (
                    crate::config::model::ProviderConfig::RainYun { api_key: new_k, .. },
                    crate::config::model::ProviderConfig::RainYun { api_key: old_k, .. },
                ) => {
                    if is_masked(new_k) {
                        *new_k = old_k.clone();
                    }
                }
                (
                    crate::config::model::ProviderConfig::ClouDNS {
                        auth_password: new_p,
                        ..
                    },
                    crate::config::model::ProviderConfig::ClouDNS {
                        auth_password: old_p,
                        ..
                    },
                ) => {
                    if is_masked(new_p) {
                        *new_p = old_p.clone();
                    }
                }
                (
                    crate::config::model::ProviderConfig::Gcore { api_key: new_k },
                    crate::config::model::ProviderConfig::Gcore { api_key: old_k },
                ) => {
                    if is_masked(new_k) {
                        *new_k = old_k.clone();
                    }
                }
                (
                    crate::config::model::ProviderConfig::NameCom {
                        api_token: new_t, ..
                    },
                    crate::config::model::ProviderConfig::NameCom {
                        api_token: old_t, ..
                    },
                ) => {
                    if is_masked(new_t) {
                        *new_t = old_t.clone();
                    }
                }
                (
                    crate::config::model::ProviderConfig::DnsLa {
                        api_secret: new_s, ..
                    },
                    crate::config::model::ProviderConfig::DnsLa {
                        api_secret: old_s, ..
                    },
                ) => {
                    if is_masked(new_s) {
                        *new_s = old_s.clone();
                    }
                }
                (
                    crate::config::model::ProviderConfig::AliEsa {
                        access_key_secret: new_s,
                        ..
                    },
                    crate::config::model::ProviderConfig::AliEsa {
                        access_key_secret: old_s,
                        ..
                    },
                ) => {
                    if is_masked(new_s) {
                        *new_s = old_s.clone();
                    }
                }
                (
                    crate::config::model::ProviderConfig::EdgeOne {
                        secret_key: new_s, ..
                    },
                    crate::config::model::ProviderConfig::EdgeOne {
                        secret_key: old_s, ..
                    },
                ) => {
                    if is_masked(new_s) {
                        *new_s = old_s.clone();
                    }
                }
                (
                    crate::config::model::ProviderConfig::NowCn { secret: new_s, .. },
                    crate::config::model::ProviderConfig::NowCn { secret: old_s, .. },
                ) => {
                    if is_masked(new_s) {
                        *new_s = old_s.clone();
                    }
                }
                (
                    crate::config::model::ProviderConfig::Eranet { secret: new_s, .. },
                    crate::config::model::ProviderConfig::Eranet { secret: old_s, .. },
                ) => {
                    if is_masked(new_s) {
                        *new_s = old_s.clone();
                    }
                }
                (
                    crate::config::model::ProviderConfig::TNetHk { secret: new_s, .. },
                    crate::config::model::ProviderConfig::TNetHk { secret: old_s, .. },
                ) => {
                    if is_masked(new_s) {
                        *new_s = old_s.clone();
                    }
                }
                (
                    crate::config::model::ProviderConfig::NsOne { api_key: new_k },
                    crate::config::model::ProviderConfig::NsOne { api_key: old_k },
                ) if is_masked(new_k) => {
                    *new_k = old_k.clone();
                }
                (
                    crate::config::model::ProviderConfig::HipmDnsMgr {
                        api_token: new_t, ..
                    },
                    crate::config::model::ProviderConfig::HipmDnsMgr {
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
    if let (Some(new_wx), Some(old_wx)) = (
        &mut new_conf.notifications.wechat_official,
        &old_conf.notifications.wechat_official,
    ) && is_masked(&new_wx.app_secret)
    {
        new_wx.app_secret = old_wx.app_secret.clone();
    }

    if let (Some(new_wc), Some(old_wc)) = (
        &mut new_conf.notifications.wecom,
        &old_conf.notifications.wecom,
    ) && new_wc
        .corp_secret
        .as_deref()
        .map(is_masked)
        .unwrap_or(false)
    {
        new_wc.corp_secret = old_wc.corp_secret.clone();
    }

    if let (Some(new_tg), Some(old_tg)) = (
        &mut new_conf.notifications.telegram,
        &old_conf.notifications.telegram,
    ) && is_masked(&new_tg.bot_token)
    {
        new_tg.bot_token = old_tg.bot_token.clone();
    }

    if let (Some(new_dt), Some(old_dt)) = (
        &mut new_conf.notifications.dingtalk,
        &old_conf.notifications.dingtalk,
    ) && new_dt.secret.as_deref().map(is_masked).unwrap_or(false)
    {
        new_dt.secret = old_dt.secret.clone();
    }

    if let (Some(new_fs), Some(old_fs)) = (
        &mut new_conf.notifications.feishu,
        &old_conf.notifications.feishu,
    ) && new_fs.secret.as_deref().map(is_masked).unwrap_or(false)
    {
        new_fs.secret = old_fs.secret.clone();
    }

    if let (Some(new_em), Some(old_em)) = (
        &mut new_conf.notifications.email,
        &old_conf.notifications.email,
    ) && is_masked(&new_em.password)
    {
        new_em.password = old_em.password.clone();
    }
}

/// 保存更新配置
pub async fn save_config_handler(
    State(state): State<AppState>,
    Json(payload): Json<SaveConfigRequest>,
) -> impl IntoResponse {
    let mut new_config = payload.config;
    let old_config = state.config_manager.get_config();

    // 合并保留脱敏掩码对应的历史真实凭据
    merge_sensitive_credentials(&mut new_config, &old_config);

    // 如果用户提交了新密码，生成 bcrypt 哈希
    if let Some(ref pwd) = payload.new_password
        && !pwd.trim().is_empty()
    {
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

    // 热更新全局 DNS 解析服务器配置 (若清空则重置回系统默认)
    if let Some(ref dns_srv) = new_config.dns_server {
        let clean = dns_srv.trim();
        if !clean.is_empty() {
            crate::util::dns_resolver::set_custom_dns_server(clean.to_string());
        } else {
            crate::util::dns_resolver::clear_custom_dns_server();
        }
    } else {
        crate::util::dns_resolver::clear_custom_dns_server();
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
    pub http_interface: Option<String>,
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
    let iface = payload.http_interface.as_deref();
    let config = payload.config;
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

#[derive(Debug, Serialize)]
pub struct AuthStatusResponse {
    pub need_init: bool,
    pub username: Option<String>,
}

/// 获取当前认证状态
pub async fn get_auth_status_handler(State(state): State<AppState>) -> impl IntoResponse {
    let config = state.config_manager.get_config();
    let need_init = config.auth.is_none();
    let username = config.auth.as_ref().map(|a| a.username.clone());
    Json(ApiResponse::ok(AuthStatusResponse {
        need_init,
        username,
    }))
}

#[derive(Debug, Deserialize)]
pub struct AuthInitRequest {
    pub username: String,
    pub password: String,
}

/// 首次初始化管理员账号与密码
pub async fn init_auth_handler(
    State(state): State<AppState>,
    Json(req): Json<AuthInitRequest>,
) -> impl IntoResponse {
    let mut config = (*state.config_manager.get_config()).clone();
    if config.auth.is_some() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err(
                "系统已初始化管理员账号，无法重复初始化".to_string(),
            )),
        );
    }

    let username = req.username.trim();
    let password = req.password.trim();
    if username.is_empty() || password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err("用户名和密码不能为空".to_string())),
        );
    }

    let hash = match bcrypt::hash(password, bcrypt::DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::err(format!("密码加密失败: {}", e))),
            );
        }
    };

    config.auth = Some(UserAuthConfig {
        username: username.to_string(),
        password_hash: hash,
    });

    if let Err(e) = state.config_manager.update_config(config) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::err(format!("保存管理员配置失败: {}", e))),
        );
    }

    tracing::info!("管理员账号 [{}] 已成功初始化", username);
    (
        StatusCode::OK,
        Json(ApiResponse::ok("管理员账号初始化成功")),
    )
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// 登录验证接口
pub async fn login_auth_handler(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> impl IntoResponse {
    let config = state.config_manager.get_config();
    if let Some(ref auth) = config.auth {
        if req.username == auth.username
            && bcrypt::verify(&req.password, &auth.password_hash).unwrap_or(false)
        {
            return (StatusCode::OK, Json(ApiResponse::ok("登录成功")));
        }
        return (
            StatusCode::UNAUTHORIZED,
            Json(ApiResponse::err("用户名或密码错误".to_string())),
        );
    }
    // 未设置密码时视为成功
    (
        StatusCode::OK,
        Json(ApiResponse::ok("系统未设置密码，直接放行")),
    )
}

/// 获取系统版本与更新信息
pub async fn get_version_handler() -> impl IntoResponse {
    match crate::util::update::check_version().await {
        Ok(info) => Json(ApiResponse::ok(info)),
        Err(err) => Json(ApiResponse::err(err)),
    }
}

/// 触发在线自动更新并平滑热重启
pub async fn trigger_upgrade_handler() -> impl IntoResponse {
    tokio::spawn(async {
        match crate::util::update::upgrade_self().await {
            Ok(()) => {
                tracing::info!("🎉 自动更新完成，正在平滑重启服务以加载新版本...");
                if let Err(e) = crate::util::update::restart_process() {
                    tracing::error!("重启服务失败，请手动重启: {}", e);
                }
            }
            Err(e) => {
                tracing::error!("在线自动更新失败: {}", e);
            }
        }
    });

    Json(ApiResponse::ok(
        "已在后台启动自动更新，文件下载替换完成后将自动平滑重启服务",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::{DnsTaskConfig, ProviderConfig};

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
}
