use axum::body::Body;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, ETAG, IF_NONE_MATCH};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "web-ui/"]
pub struct WebAssets;

#[derive(RustEmbed)]
#[folder = "assets/"]
pub struct RootAssets;

/// 根据文件扩展名匹配常用 Web 静态资源 MIME 类型 (零第三方依赖，纯静态分发)
fn get_mime_type(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "wasm" => "application/wasm",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// 静态资源托管处理器 (支持 If-None-Match 304 协商缓存与 SPA 路由降级)
pub async fn static_handler(uri: Uri, req_headers: HeaderMap) -> impl IntoResponse {
    let mut path = uri.path().trim_start_matches('/').to_string();
    if path.is_empty() {
        path = "index.html".to_string();
    }

    let embedded_file = if let Some(sub_path) = path.strip_prefix("assets/") {
        RootAssets::get(sub_path).or_else(|| WebAssets::get(&path))
    } else {
        WebAssets::get(&path)
    };

    match embedded_file {
        Some(content) => {
            let etag_str = format!("\"{}\"", hex::encode(content.metadata.sha256_hash()));

            // 协商缓存 304 校验
            if let Some(if_none_match) = req_headers.get(IF_NONE_MATCH)
                && if_none_match
                    .to_str()
                    .map(|v| v.trim() == etag_str)
                    .unwrap_or(false)
                && !path.ends_with(".html")
            {
                return Response::builder()
                    .status(StatusCode::NOT_MODIFIED)
                    .header(ETAG, etag_str)
                    .header("X-Content-Type-Options", "nosniff")
                    .header("X-Frame-Options", "SAMEORIGIN")
                    .header("Referrer-Policy", "strict-origin-when-cross-origin")
                    .body(Body::empty())
                    .unwrap_or_else(|_| StatusCode::NOT_MODIFIED.into_response());
            }

            let mime_type = get_mime_type(&path);

            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_TYPE, HeaderValue::from_static(mime_type));
            headers.insert(
                "X-Content-Type-Options",
                HeaderValue::from_static("nosniff"),
            );
            headers.insert("X-Frame-Options", HeaderValue::from_static("SAMEORIGIN"));
            headers.insert(
                "Referrer-Policy",
                HeaderValue::from_static("strict-origin-when-cross-origin"),
            );

            if path.ends_with(".html") || path == "index.html" {
                headers.insert(
                    CACHE_CONTROL,
                    HeaderValue::from_static("no-cache, no-store, must-revalidate"),
                );
            } else if let Ok(etag) = HeaderValue::from_str(&etag_str) {
                headers.insert(ETAG, etag);
                headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
            }

            let mut resp = Response::builder()
                .status(StatusCode::OK)
                .body(Body::from(content.data))
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
            *resp.headers_mut() = headers;
            resp
        }
        None => {
            // SPA Fallback 到 index.html
            if let Some(index) = WebAssets::get("index.html") {
                Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "text/html; charset=utf-8")
                    .header(CACHE_CONTROL, "no-cache, no-store, must-revalidate")
                    .header("X-Content-Type-Options", "nosniff")
                    .header("X-Frame-Options", "SAMEORIGIN")
                    .header("Referrer-Policy", "strict-origin-when-cross-origin")
                    .body(Body::from(index.data))
                    .unwrap_or_else(|_| StatusCode::NOT_FOUND.into_response())
            } else {
                StatusCode::NOT_FOUND.into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Uri;

    #[tokio::test]
    async fn test_static_handler_security_headers() {
        let uri: Uri = "/".parse().unwrap();
        let headers = HeaderMap::new();
        let resp = static_handler(uri, headers).await.into_response();

        let resp_headers = resp.headers();
        assert_eq!(
            resp_headers
                .get("X-Content-Type-Options")
                .and_then(|v| v.to_str().ok()),
            Some("nosniff")
        );
        assert_eq!(
            resp_headers
                .get("X-Frame-Options")
                .and_then(|v| v.to_str().ok()),
            Some("SAMEORIGIN")
        );
        assert_eq!(
            resp_headers
                .get("Referrer-Policy")
                .and_then(|v| v.to_str().ok()),
            Some("strict-origin-when-cross-origin")
        );
    }
}
