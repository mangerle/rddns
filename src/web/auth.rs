use crate::web::handlers::AppState;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

/// SSE 一次性 Ticket 存储映射表 (ticket -> 创建时间)
static SSE_TICKETS: LazyLock<RwLock<HashMap<String, Instant>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// 生成并注册一个 30 秒有效的一次性 SSE Ticket
pub fn issue_sse_ticket() -> String {
    let mut bytes = [0u8; 16];
    crate::util::crypto::fill_random_bytes(&mut bytes);
    let ticket = hex::encode(bytes);

    let now = Instant::now();
    let mut guard = SSE_TICKETS.write();
    // 清理过期 ticket (> 30s)
    guard.retain(|_, created_at| now.duration_since(*created_at) < Duration::from_secs(30));
    guard.insert(ticket.clone(), now);
    ticket
}

/// 验证并消耗一次性 Ticket (一次性使用，用后即焚)
pub fn consume_sse_ticket(ticket: &str) -> bool {
    let now = Instant::now();
    let mut guard = SSE_TICKETS.write();
    guard.retain(|_, created_at| now.duration_since(*created_at) < Duration::from_secs(30));
    guard.remove(ticket).is_some()
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
        && user == auth_conf.username
    {
        // 异步校验 bcrypt 密码哈希，避免阻塞 async runtime
        if crate::util::crypto::verify_password_async(
            pass.to_string(),
            auth_conf.password_hash.clone(),
        )
        .await
        {
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
        let config_path = dir.path().join("config.yaml");
        let config_manager = Arc::new(ConfigManager::load_or_create(config_path).unwrap());
        let state = AppState {
            config_manager,
            trigger_sender: tx,
            log_buffer: LogBuffer::new(10),
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
        let config_path = dir.path().join("config.yaml");
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
}
