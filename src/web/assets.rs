use axum::body::Body;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, ETAG, IF_NONE_MATCH};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "web-ui/"]
pub struct WebAssets;

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

    match WebAssets::get(&path) {
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
                    .body(Body::empty())
                    .unwrap_or_else(|_| StatusCode::NOT_MODIFIED.into_response());
            }

            let mime_type = get_mime_type(&path);

            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_TYPE, HeaderValue::from_static(mime_type));
            if path.ends_with(".html") || path == "index.html" {
                headers.insert(
                    CACHE_CONTROL,
                    HeaderValue::from_static("no-cache, no-store, must-revalidate"),
                );
            } else if let Ok(etag) = HeaderValue::from_str(&etag_str) {
                headers.insert(ETAG, etag);
                headers.insert(
                    CACHE_CONTROL,
                    HeaderValue::from_static("public, max-age=31536000, immutable"),
                );
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
                    .body(Body::from(index.data))
                    .unwrap_or_else(|_| StatusCode::NOT_FOUND.into_response())
            } else {
                StatusCode::NOT_FOUND.into_response()
            }
        }
    }
}
