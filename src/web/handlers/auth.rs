use super::{ApiResponse, AppError, AppState};
use crate::config::model::UserAuthConfig;
use crate::config::storage::ConfigError;
use crate::util::net::is_private_or_loopback;
use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use log::{info, warn};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

/// 登录尝试频控记录 (key -> (连续失败次数, 最后一次失败时间))
static LOGIN_FAIL_LIMITER: LazyLock<Mutex<HashMap<String, (u32, Instant)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn check_and_record_login_failure(key: &str, is_success: bool) -> Result<(), AppError> {
    let mut map = LOGIN_FAIL_LIMITER.lock();
    let now = Instant::now();

    // 清理超过 10 分钟无活动的记录
    map.retain(|_, (_, last)| now.duration_since(*last) < Duration::from_secs(600));

    if is_success {
        map.remove(key);
        return Ok(());
    }

    let entry = map.entry(key.to_string()).or_insert((0, now));
    entry.0 += 1;
    entry.1 = now;

    if entry.0 >= 5 {
        let elapsed = now.duration_since(entry.1);
        if elapsed < Duration::from_secs(300) {
            let remain = 300 - elapsed.as_secs();
            return Err(AppError::unauthorized(format!(
                "登录失败次数过多，账号已临时锁定，请 {} 秒后再试",
                remain
            )));
        }
    }
    Ok(())
}

fn check_login_locked(key: &str) -> Result<(), AppError> {
    let mut map = LOGIN_FAIL_LIMITER.lock();
    let now = Instant::now();
    map.retain(|_, (_, last)| now.duration_since(*last) < Duration::from_secs(600));

    if let Some((fails, last)) = map.get(key)
        && *fails >= 5
    {
        let elapsed = now.duration_since(*last);
        if elapsed < Duration::from_secs(300) {
            let remain = 300 - elapsed.as_secs();
            return Err(AppError::unauthorized(format!(
                "登录失败次数过多，账号已临时锁定，请 {} 秒后再试",
                remain
            )));
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct AuthStatusResponse {
    pub need_init: bool,
    pub username: Option<String>,
}

/// 获取当前认证状态
pub async fn get_auth_status_handler(
    State(state): State<AppState>,
) -> Json<ApiResponse<AuthStatusResponse>> {
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
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<AuthInitRequest>,
) -> Result<Json<ApiResponse<&'static str>>, AppError> {
    // 1. 来源 IP 校验：仅允许本地回环和私网局域网初始化，禁止公网直接初始化
    if !is_private_or_loopback(&peer_addr.ip()) {
        warn!(
            "[安全拦截] 阻止公网 IP ({}) 初始化管理员账号",
            peer_addr.ip()
        );
        return Err(AppError::forbidden(
            "出于安全保护，禁止从公网(WAN)初始化管理员账号，请从本机(127.0.0.1)或内网局域网访问！",
        ));
    }

    // 2. 防范 Drive-by 跨站请求伪造 (CSRF) 攻击
    if let Some(fetch_site) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok())
        && fetch_site == "cross-site"
    {
        warn!("[安全拦截] 拦截来自跨站发起的初始化请求 (Sec-Fetch-Site: cross-site)");
        return Err(AppError::forbidden(
            "出于安全保护，禁止跨站请求发起账号初始化！",
        ));
    }

    if let Some(origin) = headers.get("origin").and_then(|v| v.to_str().ok()) {
        let host_header = headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let origin_host = origin
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_end_matches('/');

        if !host_header.is_empty() && !origin_host.is_empty() && origin_host != host_header {
            warn!(
                "[安全拦截] Origin ({}) 与 Host ({}) 不匹配，拦截跨站初始化请求",
                origin, host_header
            );
            return Err(AppError::forbidden(
                "出于安全保护，禁止跨站请求发起账号初始化！",
            ));
        }
    }

    let username = req.username.trim();
    let password = req.password.trim();
    if username.is_empty() || password.is_empty() {
        return Err(AppError::bad_request("用户名和密码不能为空"));
    }

    // 异步生成 bcrypt 密码哈希，避免阻塞 async runtime
    let hash = crate::util::crypto::hash_password_async(password.to_string())
        .await
        .map_err(|e| AppError::internal(format!("密码加密失败: {}", e)))?;

    let user_str = username.to_string();
    state
        .config_manager
        .modify_config::<_, ConfigError>(|current_conf| {
            if current_conf.auth.is_some() {
                return Err(ConfigError::TempFile(
                    "系统已初始化管理员账号，无法重复初始化".to_string(),
                ));
            }
            let mut updated = current_conf.clone();
            updated.auth = Some(UserAuthConfig {
                username: user_str,
                password_hash: hash,
            });
            Ok(updated)
        })
        .map_err(|e| AppError::bad_request(format!("初始化管理员账号失败: {}", e)))?;

    info!("管理员账号 [{}] 已成功初始化", username);
    Ok(Json(ApiResponse::ok("管理员账号初始化成功")))
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
) -> Result<Json<ApiResponse<&'static str>>, AppError> {
    let username = req.username.trim();
    let password = req.password.trim();
    if username.is_empty() || password.is_empty() {
        return Err(AppError::bad_request("用户名和密码不能为空"));
    }

    // 检查登录频控锁定状态
    check_login_locked(username)?;

    let config = state.config_manager.get_config();
    if let Some(ref auth) = config.auth {
        if username == auth.username
            && crate::util::crypto::verify_password_async(
                password.to_string(),
                auth.password_hash.clone(),
            )
            .await
        {
            let _ = check_and_record_login_failure(username, true);
            return Ok(Json(ApiResponse::ok("登录成功")));
        }
        let _ = check_and_record_login_failure(username, false);
        return Err(AppError::unauthorized("用户名或密码错误"));
    }

    // 未设置管理员账号时返回明确提示，引导首次初始化
    Err(AppError::bad_request(
        "系统尚未初始化管理员账号，请先完成账号初始化设置",
    ))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SseTicketData {
    pub ticket: String,
}

/// 生成 SSE 实时日志一次性访问凭据 Ticket
pub async fn create_sse_ticket_handler() -> impl IntoResponse {
    let ticket = crate::web::auth::issue_sse_ticket();
    Json(ApiResponse::ok(SseTicketData { ticket }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::storage::ConfigManager;
    use crate::util::logging::LogBuffer;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_init_auth_rejects_wan_ip() {
        let (tx, _rx) = mpsc::channel(1);
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let config_manager = Arc::new(ConfigManager::load_or_create(config_path).unwrap());
        let state = AppState {
            config_manager,
            trigger_sender: tx,
            log_buffer: LogBuffer::new(10),
        };

        // 模拟来自公网 IP (8.8.8.8) 的初始化请求
        let wan_addr = SocketAddr::from(([8, 8, 8, 8], 12345));
        let headers = HeaderMap::new();
        let req = AuthInitRequest {
            username: "admin".to_string(),
            password: "password123".to_string(),
        };

        let res = init_auth_handler(ConnectInfo(wan_addr), headers, State(state), Json(req))
            .await
            .into_response();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_init_auth_rejects_cross_site_and_origin_mismatch() {
        let (tx, _rx) = mpsc::channel(1);
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let config_manager = Arc::new(ConfigManager::load_or_create(config_path).unwrap());
        let state = AppState {
            config_manager,
            trigger_sender: tx,
            log_buffer: LogBuffer::new(10),
        };

        let local_addr = SocketAddr::from(([127, 0, 0, 1], 12345));

        // 1. Sec-Fetch-Site: cross-site 拦截
        let mut headers = HeaderMap::new();
        headers.insert("sec-fetch-site", "cross-site".parse().unwrap());
        let req = AuthInitRequest {
            username: "admin".to_string(),
            password: "password123".to_string(),
        };
        let res = init_auth_handler(
            ConnectInfo(local_addr),
            headers,
            State(state.clone()),
            Json(req),
        )
        .await
        .into_response();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        // 2. Origin 域名与 Host 不一致拦截
        let mut headers2 = HeaderMap::new();
        headers2.insert("host", "127.0.0.1:9876".parse().unwrap());
        headers2.insert("origin", "http://malicious-site.com".parse().unwrap());
        let req2 = AuthInitRequest {
            username: "admin".to_string(),
            password: "password123".to_string(),
        };
        let res2 = init_auth_handler(ConnectInfo(local_addr), headers2, State(state), Json(req2))
            .await
            .into_response();
        assert_eq!(res2.status(), StatusCode::FORBIDDEN);
    }
}
