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

    // 如果未配置用户认证凭据：默认只允许本地回环和内网局域网访问，严禁公网未授权访问
    if config.auth.is_none() {
        let client_ip_str = req
            .headers()
            .get("X-Forwarded-For")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.split(',').next())
            .or_else(|| {
                req.headers()
                    .get("X-Real-IP")
                    .and_then(|h| h.to_str().ok())
            })
            .map(|s| s.trim());

        if let Some(ip_str) = client_ip_str {
            if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
                if !crate::util::net::is_private_or_loopback(&ip) {
                    tracing::warn!("🛡️ [安全拦截] 阻止公网 IP ({}) 访问未设置密码的管理控制台", ip);
                    return Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .header("Content-Type", "application/json; charset=utf-8")
                        .body(axum::body::Body::from(
                            r#"{"success":false,"message":"🛡️ 出于安全保护，系统尚未配置管理员密码时禁止从公网(WAN)访问。请通过本机(127.0.0.1)或内网局域网私网IP登录并初始化密码！"}"#,
                        ))
                        .unwrap_or_else(|_| StatusCode::FORBIDDEN.into_response());
                }
            }
        }

        return next.run(req).await;
    }

    let auth_conf = config.auth.as_ref().unwrap();

    // 1. 尝试从 Authorization Header 提取
    let mut auth_raw = None;
    if let Some(auth_header) = req.headers().get(AUTHORIZATION)
        && let Ok(auth_str) = auth_header.to_str()
        && auth_str.starts_with("Basic ")
    {
        auth_raw = Some(auth_str.trim_start_matches("Basic ").to_string());
    }

    // 2. 若 Header 不存在，尝试从 URL Query（例如 SSE 请求中的 ?auth=...）提取
    if auth_raw.is_none()
        && let Some(query) = req.uri().query()
    {
        for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
            if k == "auth" {
                auth_raw = Some(v.into_owned());
                break;
            }
        }
    }

    // 3. 校验提取到的 Base64 编码凭据
    if let Some(encoded) = auth_raw
        && let Ok(decoded_bytes) = BASE64_STANDARD.decode(encoded.trim())
        && let Ok(decoded_str) = String::from_utf8(decoded_bytes)
        && let Some((user, pass)) = decoded_str.split_once(':')
        && user == auth_conf.username
    {
        // 校验 bcrypt 密码哈希
        if bcrypt::verify(pass, &auth_conf.password_hash).unwrap_or(false) {
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
