use crate::web::handlers::AppState;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use log::warn;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

/// 提取客户端的有效识别 IP
///
/// # 安全与设计考虑 (P1-2)
/// - **实现初衷**: 当 rddns 部署在反向代理（如 Nginx、Caddy、Traefik）后方时，底层 TCP 连接对端 IP 为反代的回环地址（如 127.0.0.1 或 ::1）。
///   若直接以 TCP 对端为准，会导致所有客户端共享限流计数器，任意匿名攻击者 5 次失败即可使全局管理面板拒绝服务。
/// - **核心优势**: 仅在 TCP 连接确系来自本地回环地址（Loopback）时，才信任并解析 `X-Forwarded-For` 或 `X-Real-IP` 头中的真实客户端 IP；
///   对公网直连请求严格忽略任何伪造的转发标头，坚守防伪造底线。
pub(crate) fn resolve_client_ip(peer_addr: Option<SocketAddr>, headers: &HeaderMap) -> String {
    let peer_ip = peer_addr.map(|sa| sa.ip());

    // 仅当底层 TCP 来源为本地回环（反向代理典型部署）时才信任转发标头
    if let Some(ip) = peer_ip
        && ip.is_loopback()
    {
        // 1. 尝试从 X-Forwarded-For 提取（取首个有效客户端 IP）
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok())
            && let Some(client) = xff.split(',').next().map(|s| s.trim())
            && !client.is_empty()
        {
            return client.to_string();
        }

        // 2. 尝试从 X-Real-IP 提取
        if let Some(real_ip) = headers.get("x-real-ip").and_then(|v| v.to_str().ok())
            && !real_ip.trim().is_empty()
        {
            return real_ip.trim().to_string();
        }
    }

    // 默认使用底层 TCP 对端真实 IP
    peer_ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// SSE Ticket 默认有效生命周期 (30 秒)
const SSE_TICKET_TTL: Duration = Duration::from_secs(30);
/// 批量清理过期 Ticket 的最小时间间隔 (10 秒)
const SSE_CLEANUP_INTERVAL: Duration = Duration::from_secs(10);
/// Ticket 存储池容量硬上限，防止恶意请求导致内存无限膨胀
const MAX_SSE_TICKETS: usize = 512;

/// SSE Ticket 存储结构体
struct TicketStore {
    tickets: HashMap<String, Instant>,
    last_cleanup: Instant,
}

/// SSE 一次性 Ticket 存储池
static SSE_TICKETS: LazyLock<RwLock<TicketStore>> = LazyLock::new(|| {
    RwLock::new(TicketStore {
        tickets: HashMap::with_capacity(32),
        last_cleanup: Instant::now(),
    })
});

/// Basic Auth 快速凭据验证缓存 TTL (300 秒 / 5 分钟)
const CREDENTIAL_CACHE_TTL: Duration = Duration::from_secs(300);
/// 凭据缓存容量硬上限（极简单用户系统，防止恶意构造占用）
const MAX_CREDENTIAL_CACHE_ENTRIES: usize = 16;

/// 快速凭据验证缓存键
///
/// # 设计原理
/// - **实现初衷**: 避免合法请求每次调用 cost=12 的昂贵 bcrypt 耗尽 CPU (P-1)。
/// - **安全性**: 密码仅存 SHA-256 摘要（不落盘、不存明文）；同时绑定 `password_hash`，管理员一旦改密码旧缓存自动失效。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CredentialCacheKey {
    username: String,
    password_hash: String,
    password_sha256: [u8; 32],
}

/// 快速凭据验证缓存池
struct CredentialCache {
    entries: HashMap<CredentialCacheKey, Instant>,
}

/// 全局 Basic Auth 快速凭据验证缓存
static CREDENTIAL_CACHE: LazyLock<RwLock<CredentialCache>> = LazyLock::new(|| {
    RwLock::new(CredentialCache {
        entries: HashMap::with_capacity(4),
    })
});

/// 预热快速凭据验证缓存
pub(crate) fn insert_credential_cache(username: &str, password_hash: &str, raw_password: &str) {
    let pass_sha = crate::util::crypto::sha256_bytes(raw_password.as_bytes());
    let cache_key = CredentialCacheKey {
        username: username.to_string(),
        password_hash: password_hash.to_string(),
        password_sha256: pass_sha,
    };
    let now = Instant::now();
    let mut cache = CREDENTIAL_CACHE.write();
    if cache.entries.len() >= MAX_CREDENTIAL_CACHE_ENTRIES {
        cache
            .entries
            .retain(|_, created_at| now.duration_since(*created_at) < CREDENTIAL_CACHE_TTL);
    }
    if cache.entries.len() < MAX_CREDENTIAL_CACHE_ENTRIES {
        cache.entries.insert(cache_key, now);
    }
}

/// 清空全局凭据验证缓存（仅供测试套件保证用例间隔离）
#[cfg(test)]
pub(crate) fn clear_credential_cache_for_test() {
    CREDENTIAL_CACHE.write().entries.clear();
}

/// 生成并注册一个 30 秒有效的一次性 SSE Ticket
///
/// # 设计原理
/// - **实现初衷**: 为避免每次生成时执行高成本的 O(N) 全量遍历清理，采用按时间间隔与容量阈值节流惰性淘汰。
/// - **核心优势**: 减少持锁时间至微秒级；设置 512 条硬上限抵御高频调用导致的内存与 CPU 退化。
pub fn issue_sse_ticket() -> String {
    let mut bytes = [0u8; 16];
    crate::util::crypto::fill_random_bytes(&mut bytes);
    let ticket = hex::encode(bytes);

    let now = Instant::now();
    let mut store = SSE_TICKETS.write();

    // 节流淘汰：仅在达到清理间隔或容量达到 64 时执行全量清理
    if now.duration_since(store.last_cleanup) >= SSE_CLEANUP_INTERVAL || store.tickets.len() >= 64 {
        store
            .tickets
            .retain(|_, created_at| now.duration_since(*created_at) < SSE_TICKET_TTL);
        store.last_cleanup = now;
    }

    // 防御性硬上限
    if store.tickets.len() >= MAX_SSE_TICKETS {
        store
            .tickets
            .retain(|_, created_at| now.duration_since(*created_at) < SSE_TICKET_TTL);
    }
    if store.tickets.len() < MAX_SSE_TICKETS {
        store.tickets.insert(ticket.clone(), now);
    } else {
        warn!("SSE Ticket 存储池已达上限且无法通过过期回收释放空间，已拒绝本次缓存");
    }

    ticket
}

/// 验证并消耗一次性 Ticket (一次性使用，用后即焚)
///
/// # 设计原理
/// - **实现初衷**: 消费特定 Ticket 时只需 O(1) 精确删除，无需为了单个请求执行 O(N) 全表 retain 遍历。
/// - **核心优势**: 消除消费时的写锁长时间争用，过期检查直接针对目标条目。
pub fn consume_sse_ticket(ticket: &str) -> bool {
    let now = Instant::now();
    let mut store = SSE_TICKETS.write();
    if let Some(created_at) = store.tickets.remove(ticket) {
        now.duration_since(created_at) <= SSE_TICKET_TTL
    } else {
        false
    }
}

/// 清空 SSE 一次性 Ticket 存储池（仅供测试套件保证用例间隔离）
#[cfg(test)]
pub(crate) fn clear_sse_tickets_for_test() {
    SSE_TICKETS.write().tickets.clear();
}

/// 从请求头同步提取 Basic Auth 的 `(用户名, 密码, 限流键)`，避免跨 `.await` 借用非 `Sync` 的 `Request<Body>`
fn extract_basic_auth_context(req: &Request) -> Option<(String, String, String)> {
    let auth_header = req.headers().get(AUTHORIZATION)?;
    let auth_str = auth_header.to_str().ok()?;
    let encoded = auth_str.strip_prefix("Basic ")?;
    let decoded_bytes = BASE64_STANDARD.decode(encoded.trim()).ok()?;
    let decoded_str = String::from_utf8(decoded_bytes).ok()?;
    let (user, pass) = decoded_str.split_once(':')?;

    let peer_addr = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0);
    let client_ip = resolve_client_ip(peer_addr, req.headers());
    let limiter_key = format!("{}:{}", user, client_ip);
    Some((user.to_string(), pass.to_string(), limiter_key))
}

/// 校验提取出的 Basic Auth 凭据（含限流锁定检查、快速凭据缓存与常量时间哈希比对）
///
/// 返回 `Ok(true)` 表示认证通过，`Ok(false)` 表示凭据无效，`Err(String)` 表示触发防暴破锁定拦截的错误消息。
async fn verify_basic_credentials(
    user: &str,
    pass: &str,
    limiter_key: &str,
    auth_conf: &crate::config::model::UserAuthConfig,
) -> Result<bool, String> {
    // 校验账号是否已锁定，防止持续暴破 (S-3, S-8)
    crate::web::handlers::auth::check_login_locked(limiter_key).map_err(|e| e.to_string())?;

    // 优先检查快速凭据缓存，避免每轮受保护请求触发昂贵的 bcrypt 哈希验证 (P-1)
    let pass_sha = crate::util::crypto::sha256_bytes(pass.as_bytes());
    let cache_key = CredentialCacheKey {
        username: user.to_string(),
        password_hash: auth_conf.password_hash.clone(),
        password_sha256: pass_sha,
    };

    let now = Instant::now();
    let mut is_valid = {
        let cache = CREDENTIAL_CACHE.read();
        cache
            .entries
            .get(&cache_key)
            .is_some_and(|created_at| now.duration_since(*created_at) < CREDENTIAL_CACHE_TTL)
    };

    if !is_valid {
        // 常量时间校验凭据，防止利用用户名快速短路的时序侧信道攻击枚举系统用户名 (P1-8)
        is_valid = crate::util::crypto::verify_credentials_constant_time(
            user,
            pass,
            &auth_conf.username,
            &auth_conf.password_hash,
        )
        .await;

        if is_valid {
            let mut cache = CREDENTIAL_CACHE.write();
            if cache.entries.len() >= MAX_CREDENTIAL_CACHE_ENTRIES {
                cache
                    .entries
                    .retain(|_, created_at| now.duration_since(*created_at) < CREDENTIAL_CACHE_TTL);
            }
            if cache.entries.len() < MAX_CREDENTIAL_CACHE_ENTRIES {
                cache.entries.insert(cache_key, now);
            }
        }
    }

    crate::web::handlers::auth::record_login_failure(limiter_key, is_valid);
    Ok(is_valid)
}

/// Basic Auth 鉴权中间件
pub async fn auth_middleware(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let config = state.config_manager.get_config();

    // 如果未配置用户认证凭据：所有受保护接口直接拦截，强制要求先初始化管理员账号
    let Some(auth_conf) = config.auth.as_ref() else {
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header("Content-Type", "application/json; charset=utf-8")
            .body(axum::body::Body::from(
                r#"{"success":false,"message":"系统尚未配置管理员账号，请先访问管理页面进行初始化！"}"#,
            ))
            .unwrap_or_else(|_| StatusCode::FORBIDDEN.into_response());
    };

    // 1. 针对 SSE 流式日志接口 (/logs/sse)，优先检查 URL Query 中的一次性 Ticket
    if req.uri().path().ends_with("/logs/sse")
        && let Some(query) = req.uri().query()
    {
        for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
            if k == "ticket" && consume_sse_ticket(&v) {
                return next.run(req).await;
            }
        }
    }

    // 2. 校验 Authorization Header 中的 Basic Auth 凭据
    if let Some((user, pass, limiter_key)) = extract_basic_auth_context(&req) {
        match verify_basic_credentials(&user, &pass, &limiter_key, auth_conf).await {
            Ok(true) => return next.run(req).await,
            Ok(false) => {}
            Err(locked_err) => {
                return Response::builder()
                    .status(StatusCode::TOO_MANY_REQUESTS)
                    .header("Content-Type", "application/json; charset=utf-8")
                    .body(axum::body::Body::from(format!(
                        r#"{{"success":false,"message":"{}"}}"#,
                        locked_err
                    )))
                    .unwrap_or_else(|_| StatusCode::TOO_MANY_REQUESTS.into_response());
            }
        }
    }

    // 3. 鉴权失败：返回 401 JSON 响应（绝不附带 WWW-Authenticate 头，避免浏览器拦截弹出原生丑陋登录框）
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("Content-Type", "application/json")
        .body(axum::body::Body::from(
            r#"{"success":false,"message":"未登录或登录凭据已过期，请重新登录"}"#,
        ))
        .unwrap_or_else(|_| StatusCode::UNAUTHORIZED.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::{AppConfig, UserAuthConfig};
    use crate::config::storage::ConfigManager;
    use crate::core::state::StateManager;
    use crate::util::logging::LogBuffer;
    use axum::Router;
    use axum::middleware::from_fn_with_state;
    use axum::routing::get;
    use std::sync::Arc;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_auth_middleware_blocks_when_no_auth() {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let config_manager = Arc::new(ConfigManager::load_or_create(config_path).unwrap());
        let state = AppState {
            config_manager,
            trigger_sender: tx,
            log_buffer: LogBuffer::new(10),
            state_manager: StateManager::new(),
            cancel_token: tokio_util::sync::CancellationToken::new(),
            active_listen_port: 9876,
            active_not_allow_wan_access: true,
        };

        let app = Router::new()
            .route("/config", get(|| async { "ok" }))
            .layer(from_fn_with_state(state, auth_middleware));

        let req = Request::builder()
            .uri("/config")
            .body(axum::body::Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_auth_middleware_ticket_and_header() {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let config_manager = Arc::new(ConfigManager::load_or_create(config_path).unwrap());

        let hash = bcrypt::hash("admin123", bcrypt::DEFAULT_COST).unwrap();
        config_manager
            .update_config(AppConfig {
                auth: Some(UserAuthConfig {
                    username: "admin".to_string(),
                    password_hash: hash,
                }),
                ..Default::default()
            })
            .unwrap();

        let state = AppState {
            config_manager,
            trigger_sender: tx,
            log_buffer: LogBuffer::new(10),
            state_manager: StateManager::new(),
            cancel_token: tokio_util::sync::CancellationToken::new(),
            active_listen_port: 9876,
            active_not_allow_wan_access: true,
        };

        let app = Router::new()
            .route("/config", get(|| async { "ok" }))
            .route("/logs/sse", get(|| async { "ok" }))
            .layer(from_fn_with_state(state, auth_middleware));

        let auth_token = BASE64_STANDARD.encode("admin:admin123");

        // 1. 在任何接口上直接带 ?auth= 均应被拒绝 (401)，杜绝在 URL 中传递永久凭据
        let req1 = Request::builder()
            .uri(format!("/config?auth={}", auth_token))
            .body(axum::body::Body::empty())
            .unwrap();
        let res1 = app.clone().oneshot(req1).await.unwrap();
        assert_eq!(res1.status(), StatusCode::UNAUTHORIZED);

        let req2 = Request::builder()
            .uri(format!("/logs/sse?auth={}", auth_token))
            .body(axum::body::Body::empty())
            .unwrap();
        let res2 = app.clone().oneshot(req2).await.unwrap();
        assert_eq!(res2.status(), StatusCode::UNAUTHORIZED);

        // 2. 在普通接口带 Header 应该被允许 (200)
        let req3 = Request::builder()
            .uri("/config")
            .header(AUTHORIZATION, format!("Basic {}", auth_token))
            .body(axum::body::Body::empty())
            .unwrap();
        let res3 = app.clone().oneshot(req3).await.unwrap();
        assert_eq!(res3.status(), StatusCode::OK);

        // 3. 测试一次性 SSE Ticket 鉴权 (200)
        let ticket = issue_sse_ticket();
        let req_ticket = Request::builder()
            .uri(format!("/logs/sse?ticket={}", ticket))
            .body(axum::body::Body::empty())
            .unwrap();
        let res_ticket = app.clone().oneshot(req_ticket).await.unwrap();
        assert_eq!(res_ticket.status(), StatusCode::OK);

        // 4. 再次使用相同 Ticket 应已被销毁 (401)
        let req_reuse = Request::builder()
            .uri(format!("/logs/sse?ticket={}", ticket))
            .body(axum::body::Body::empty())
            .unwrap();
        let res_reuse = app.oneshot(req_reuse).await.unwrap();
        assert_eq!(res_reuse.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_sse_ticket_consume_and_cleanup_behavior() {
        clear_sse_tickets_for_test();
        // 1. 正常生成与消费
        let ticket = issue_sse_ticket();
        assert!(consume_sse_ticket(&ticket));
        // 再次消费应失败
        assert!(!consume_sse_ticket(&ticket));
        // 消费不存在的 ticket 应失败
        assert!(!consume_sse_ticket("nonexistent_ticket"));

        // 2. 模拟过期 ticket
        {
            let mut store = SSE_TICKETS.write();
            store.tickets.insert(
                "expired_ticket".to_string(),
                Instant::now() - Duration::from_secs(60),
            );
        }
        // 消费过期 ticket 判定为 false 且已被销毁
        assert!(!consume_sse_ticket("expired_ticket"));
    }

    #[test]
    fn test_resolve_client_ip_loopback_proxy_and_direct() {
        use std::net::SocketAddr;

        let loopback_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let public_addr: SocketAddr = "203.0.113.50:54321".parse().unwrap();

        // 1. 本地回环来自反向代理 + X-Forwarded-For 多级 IP：提取最左侧客户端真实 IP
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "198.51.100.88, 10.0.0.1".parse().unwrap(),
        );
        let ip = resolve_client_ip(Some(loopback_addr), &headers);
        assert_eq!(ip, "198.51.100.88");

        // 2. 本地回环来自反向代理 + X-Real-IP
        let mut headers2 = HeaderMap::new();
        headers2.insert("x-real-ip", "198.51.100.99".parse().unwrap());
        let ip2 = resolve_client_ip(Some(loopback_addr), &headers2);
        assert_eq!(ip2, "198.51.100.99");

        // 3. 直连公网 IP + 恶意伪造 X-Forwarded-For：坚决忽略伪造标头，以 TCP 对端为准
        let mut fake_headers = HeaderMap::new();
        fake_headers.insert("x-forwarded-for", "1.1.1.1".parse().unwrap());
        fake_headers.insert("x-real-ip", "2.2.2.2".parse().unwrap());
        let ip3 = resolve_client_ip(Some(public_addr), &fake_headers);
        assert_eq!(ip3, "203.0.113.50");

        // 4. 无标头或无 SocketAddr
        let empty_headers = HeaderMap::new();
        let ip4 = resolve_client_ip(Some(loopback_addr), &empty_headers);
        assert_eq!(ip4, "127.0.0.1");
        let ip5 = resolve_client_ip(None, &empty_headers);
        assert_eq!(ip5, "unknown");
    }

    #[tokio::test]
    async fn test_credential_cache_warmup_and_invalidation() {
        clear_credential_cache_for_test();
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let config_manager = Arc::new(ConfigManager::load_or_create(config_path).unwrap());

        let hash = bcrypt::hash("StrongPass#123", bcrypt::DEFAULT_COST).unwrap();
        config_manager
            .update_config(AppConfig {
                auth: Some(UserAuthConfig {
                    username: "cache_admin".to_string(),
                    password_hash: hash.clone(),
                }),
                ..Default::default()
            })
            .unwrap();

        let state = AppState {
            config_manager: config_manager.clone(),
            trigger_sender: tx,
            log_buffer: LogBuffer::new(10),
            state_manager: StateManager::new(),
            cancel_token: tokio_util::sync::CancellationToken::new(),
            active_listen_port: 9876,
            active_not_allow_wan_access: true,
        };

        let app = Router::new()
            .route("/config", get(|| async { "ok" }))
            .layer(from_fn_with_state(state, auth_middleware));

        let basic_token = BASE64_STANDARD.encode("cache_admin:StrongPass#123");

        // 1. 首次请求：未命中缓存，走 bcrypt，返回 200 并预热缓存
        let req1 = Request::builder()
            .uri("/config")
            .header(AUTHORIZATION, format!("Basic {}", basic_token))
            .body(axum::body::Body::empty())
            .unwrap();
        let res1 = app.clone().oneshot(req1).await.unwrap();
        assert_eq!(res1.status(), StatusCode::OK);

        // 验证凭据缓存中已存在该条目
        {
            let cache = CREDENTIAL_CACHE.read();
            assert!(
                cache
                    .entries
                    .iter()
                    .any(|(k, _)| k.username == "cache_admin"),
                "成功验证后应写入快速凭据缓存"
            );
        }

        // 2. 二次请求：直接命中快速缓存，秒级放行 (P-1 验证)
        let req2 = Request::builder()
            .uri("/config")
            .header(AUTHORIZATION, format!("Basic {}", basic_token))
            .body(axum::body::Body::empty())
            .unwrap();
        let res2 = app.clone().oneshot(req2).await.unwrap();
        assert_eq!(res2.status(), StatusCode::OK);

        // 3. 密码哈希变更：旧凭据缓存自动失效
        let new_hash = bcrypt::hash("NewStrongPass#456", bcrypt::DEFAULT_COST).unwrap();
        config_manager
            .update_config(AppConfig {
                auth: Some(UserAuthConfig {
                    username: "cache_admin".to_string(),
                    password_hash: new_hash,
                }),
                ..Default::default()
            })
            .unwrap();

        // 原旧密码请求必须立即被拒绝 (401)
        let req3 = Request::builder()
            .uri("/config")
            .header(AUTHORIZATION, format!("Basic {}", basic_token))
            .body(axum::body::Body::empty())
            .unwrap();
        let res3 = app.oneshot(req3).await.unwrap();
        assert_eq!(res3.status(), StatusCode::UNAUTHORIZED);
    }
}
