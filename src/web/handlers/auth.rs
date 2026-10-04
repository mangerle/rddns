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

/// 登录失败频控阈值：连续失败达到该次数即触发临时锁定
const LOGIN_FAIL_THRESHOLD: u32 = 5;
/// 账号锁定持续时长（秒）
const LOGIN_LOCK_DURATION_SECS: u64 = 300;
/// 频控记录的空闲清理时长（秒），需大于锁定时长以避免锁定期内记录被提前回收
const LOGIN_RECORD_IDLE_SECS: u64 = 600;

/// 登录尝试频控记录
///
/// # 字段语义
/// - `fail_count`: 自上次成功登录以来的连续失败次数
/// - `last_fail_at`: 最后一次失败的时间戳
/// - `locked_until`: 锁定截止时间戳；`None` 表示当前未锁定
///
/// # 设计原理
/// 锁定截止时间在「首次达到阈值」时一次性写入并**不随后续失败刷新**，
/// 从而保证攻击者无法通过持续发送错误请求无限延长锁定时长。
#[derive(Debug, Clone)]
struct LoginFailRecord {
    fail_count: u32,
    last_fail_at: Instant,
    locked_until: Option<Instant>,
}

/// 登录尝试频控记录表 (用户名 -> 失败记录)
static LOGIN_FAIL_LIMITER: LazyLock<Mutex<HashMap<String, LoginFailRecord>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// 生成锁定提示文案
fn build_locked_message(remain_secs: u64) -> AppError {
    AppError::unauthorized(format!(
        "登录失败次数过多，账号已临时锁定，请 {} 秒后再试",
        remain_secs
    ))
}

/// 清理空闲记录并返回当前时刻
///
/// # 设计原理
/// 统一收口清理逻辑，确保各判定入口的过期标准一致。
fn now_and_retain(map: &mut HashMap<String, LoginFailRecord>) -> Instant {
    let now = Instant::now();
    let idle = Duration::from_secs(LOGIN_RECORD_IDLE_SECS);
    map.retain(|_, rec| {
        // 仍处于锁定期的记录必须保留，直到锁定自然到期
        rec.locked_until.is_some_and(|until| until > now)
            || now.duration_since(rec.last_fail_at) < idle
    });
    now
}

/// 查询账号当前是否处于锁定期
///
/// # 设计原理
/// 仅依据 `locked_until` 判定，与失败计数解耦，避免出现「每次失败都刷新
/// 时间戳导致锁定永不过期」的问题。
fn check_login_locked(key: &str) -> Result<(), AppError> {
    let mut map = LOGIN_FAIL_LIMITER.lock();
    let now = now_and_retain(&mut map);

    if let Some(rec) = map.get(key)
        && let Some(until) = rec.locked_until
        && until > now
    {
        return Err(build_locked_message((until - now).as_secs().max(1)));
    }
    Ok(())
}

/// 记录一次登录尝试结果，并在达到阈值时执行锁定
///
/// # 设计原理
/// - 成功登录：清空该账号的失败记录；
/// - 失败：累加计数，仅在**首次**达到阈值时写入锁定截止时间；
///   已处于锁定期时不刷新截止时间，使锁定时长固定为 LOGIN_LOCK_DURATION_SECS。
fn record_login_failure(key: &str, is_success: bool) {
    let mut map = LOGIN_FAIL_LIMITER.lock();
    let now = now_and_retain(&mut map);

    if is_success {
        map.remove(key);
        return;
    }

    let rec = map.entry(key.to_string()).or_insert(LoginFailRecord {
        fail_count: 0,
        last_fail_at: now,
        locked_until: None,
    });

    rec.fail_count += 1;
    rec.last_fail_at = now;

    // 首次达到阈值时写入锁定截止时间，后续失败不再刷新
    if rec.fail_count >= LOGIN_FAIL_THRESHOLD && rec.locked_until.is_none() {
        rec.locked_until = Some(now + Duration::from_secs(LOGIN_LOCK_DURATION_SECS));
        warn!(
            "账号 [{}] 连续登录失败 {} 次，已临时锁定 {} 秒",
            key, rec.fail_count, LOGIN_LOCK_DURATION_SECS
        );
    }
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
    if password.len() < 4 {
        return Err(AppError::bad_request("管理员密码长度不能少于 4 个字符"));
    }

    // 异步生成 bcrypt 密码哈希，避免阻塞 async runtime
    let hash = crate::util::crypto::hash_password_async(password.to_string())
        .await
        .map_err(|e| AppError::internal(format!("密码加密失败: {}", e)))?;

    let user_str = username.to_string();
    state
        .config_manager
        .modify_config_async::<_, ConfigError>(|current_conf| {
            if current_conf.auth.is_some() {
                return Err(ConfigError::TempFile(
                    "系统已初始化管理员账号，无法重复初始化".to_string(),
                ));
            }
            let mut updated = current_conf.clone();
            updated.auth = Some(UserAuthConfig {
                username: user_str.clone(),
                password_hash: hash.clone(),
            });
            Ok(updated)
        })
        .await
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
            record_login_failure(username, true);
            return Ok(Json(ApiResponse::ok("登录成功")));
        }
        record_login_failure(username, false);
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
    use crate::core::state::StateManager;
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
            state_manager: StateManager::new(),
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
            state_manager: StateManager::new(),
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

    #[tokio::test]
    async fn test_init_auth_rejects_short_password() {
        let (tx, _rx) = mpsc::channel(1);
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let config_manager = Arc::new(ConfigManager::load_or_create(config_path).unwrap());
        let state = AppState {
            config_manager,
            trigger_sender: tx,
            log_buffer: LogBuffer::new(10),
            state_manager: StateManager::new(),
        };

        let local_addr = SocketAddr::from(([127, 0, 0, 1], 12345));
        let headers = HeaderMap::new();
        let req = AuthInitRequest {
            username: "admin".to_string(),
            password: "123".to_string(), // 少于 4 位
        };

        let res = init_auth_handler(ConnectInfo(local_addr), headers, State(state), Json(req))
            .await
            .into_response();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    /// 清理全局频控表，避免用例间相互干扰
    ///
    /// # 并发说明
    /// Rust 测试默认多线程并行执行，而 `LOGIN_FAIL_LIMITER` 是进程级全局状态，
    /// 因此各用例必须使用**互不相同的账号名**，且仅清理自己写入的条目，
    /// 不可调用 `clear()` 清空整表（否则会相互抹除数据）。
    fn cleanup_record(key: &str) {
        LOGIN_FAIL_LIMITER.lock().remove(key);
    }

    #[test]
    fn test_lock_triggers_at_threshold_and_blocks_correct_password() {
        let key = "lock_threshold_user";

        // 未达阈值时不应锁定
        for _ in 0..LOGIN_FAIL_THRESHOLD - 1 {
            record_login_failure(key, false);
            assert!(check_login_locked(key).is_ok(), "未达阈值时不应触发锁定");
        }

        // 第 N 次失败触发锁定
        record_login_failure(key, false);
        assert!(
            check_login_locked(key).is_err(),
            "达到阈值后必须锁定，否则正确密码也将被拒绝"
        );
        cleanup_record(key);
    }

    #[test]
    fn test_lock_not_extended_by_subsequent_failures() {
        let key = "lock_no_extend_user";

        // 触发锁定
        for _ in 0..LOGIN_FAIL_THRESHOLD {
            record_login_failure(key, false);
        }
        let first_locked_until = LOGIN_FAIL_LIMITER
            .lock()
            .get(key)
            .and_then(|r| r.locked_until)
            .expect("达到阈值后应写入锁定截止时间");

        // 攻击者继续尝试失败，锁定截止时间不得被刷新
        for _ in 0..20 {
            record_login_failure(key, false);
        }
        let after_locked_until = LOGIN_FAIL_LIMITER
            .lock()
            .get(key)
            .and_then(|r| r.locked_until)
            .expect("锁定期内应保留截止时间");

        assert_eq!(
            first_locked_until, after_locked_until,
            "后续失败不得延长锁定时长，否则账号将被无限期锁死"
        );
        cleanup_record(key);
    }

    #[test]
    fn test_success_login_clears_fail_record() {
        let key = "recover_user";

        // 失败 4 次后成功登录，记录应被清空
        for _ in 0..LOGIN_FAIL_THRESHOLD - 1 {
            record_login_failure(key, false);
        }
        record_login_failure(key, true);

        assert!(
            LOGIN_FAIL_LIMITER.lock().get(key).is_none(),
            "成功登录后应清空失败记录"
        );
        assert!(check_login_locked(key).is_ok());

        // 计数重置后再次失败不应立即触发锁定
        record_login_failure(key, false);
        assert!(check_login_locked(key).is_ok());
        cleanup_record(key);
    }

    #[test]
    fn test_locked_account_rejected_before_password_verify() {
        let key = "verify_order_user";
        for _ in 0..LOGIN_FAIL_THRESHOLD {
            record_login_failure(key, false);
        }
        // check_login_locked 必须在密码校验之前生效
        assert!(check_login_locked(key).is_err());
        cleanup_record(key);
    }
}
