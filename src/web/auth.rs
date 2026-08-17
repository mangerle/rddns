use crate::web::handlers::AppState;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

/// Basic Auth 鉴权中间件
pub async fn auth_middleware(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let config = state.config_manager.get_config();

    // 如果未配置用户认证凭据
    if config.auth.is_none() {
        return next.run(req).await;
    }

    let auth_conf = config.auth.as_ref().unwrap();

    // 提取 Authorization Header
    if let Some(auth_header) = req.headers().get(AUTHORIZATION)
        && let Ok(auth_str) = auth_header.to_str()
        && auth_str.starts_with("Basic ")
    {
        let encoded = auth_str.trim_start_matches("Basic ");
        if let Ok(decoded_bytes) = BASE64_STANDARD.decode(encoded)
            && let Ok(decoded_str) = String::from_utf8(decoded_bytes)
            && let Some((user, pass)) = decoded_str.split_once(':')
            && user == auth_conf.username
        {
            // 校验 bcrypt 密码哈希
            if bcrypt::verify(pass, &auth_conf.password_hash).unwrap_or(false) {
                return next.run(req).await;
            }
        }
    }

    // 鉴权失败，返回 401 Unauthorized 并附带 WWW-Authenticate 头
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("WWW-Authenticate", "Basic realm=\"rddns login\"")
        .body(axum::body::Body::from("401 Unauthorized"))
        .unwrap_or_else(|_| StatusCode::UNAUTHORIZED.into_response())
}
