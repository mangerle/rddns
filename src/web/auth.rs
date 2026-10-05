use crate::web::handlers::AppState;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
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

/// Basic Auth 鉴权中间件
pub async fn auth_middleware(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let config = state.config_manager.get_config();

    // 如果未配置用户认证凭据：所有受保护接口直接拦截，强制要求先初始化管理员账号
    let auth_conf = match config.auth.as_ref() {
        Some(conf) => conf,
        None => {
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header("Content-Type", "application/json; charset=utf-8")
                .body(axum::body::Body::from(
                    r#"{"success":false,"message":"系统尚未配置管理员账号，请先访问管理页面进行初始化！"}"#,
                ))
                .unwrap_or_else(|_| StatusCode::FORBIDDEN.into_response());
        }
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

    // 2. 尝试从 Authorization Header 提取
    let mut auth_raw = None;
    if let Some(auth_header) = req.headers().get(AUTHORIZATION)
        && let Ok(auth_str) = auth_header.to_str()
        && auth_str.starts_with("Basic ")
    {
        auth_raw = Some(auth_str.trim_start_matches("Basic ").to_string());
    }

    // 3. 校验提取到的 Base64 编码凭据
    if let Some(encoded) = auth_raw
        && let Ok(decoded_bytes) = BASE64_STANDARD.decode(encoded.trim())
        && let Ok(decoded_str) = String::from_utf8(decoded_bytes)
        && let Some((user, pass)) = decoded_str.split_once(':')
    {
        let client_ip = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let limiter_key = format!("{}:{}", user, client_ip);

        // 校验账号是否已锁定，防止持续暴破 (S-3, S-8)
        if let Err(locked_err) = crate::web::handlers::auth::check_login_locked(&limiter_key) {
            return Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header("Content-Type", "application/json; charset=utf-8")
                .body(axum::body::Body::from(format!(
                    r#"{{"success":false,"message":"{}"}}"#,
                    locked_err
                )))
                .unwrap_or_else(|_| StatusCode::TOO_MANY_REQUESTS.into_response());
        }

        // 常量时间校验凭据，防止利用用户名快速短路的时序侧信道攻击枚举系统用户名 (P1-8)
        let is_valid = crate::util::crypto::verify_credentials_constant_time(
            user,
            pass,
            &auth_conf.username,
            &auth_conf.password_hash,
        )
        .await;

        // 记录失败或成功状态
        crate::web::handlers::auth::record_login_failure(&limiter_key, is_valid);

        if is_valid {
            return next.run(req).await;
        }
    }

    // 4. 鉴权失败：返回 401 JSON 响应（绝不附带 WWW-Authenticate 头，避免浏览器拦截弹出原生丑陋登录框）
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
}
