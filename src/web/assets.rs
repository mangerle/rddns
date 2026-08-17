use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, ETAG};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "web-ui/"]
pub struct WebAssets;

/// 静态资源托管处理器
pub async fn static_handler(uri: axum::http::Uri) -> impl IntoResponse {
    let mut path = uri.path().trim_start_matches('/').to_string();
    if path.is_empty() {
        path = "index.html".to_string();
    }

    match WebAssets::get(&path) {
        Some(content) => {
            let mime_type = mime_guess::from_path(&path)
                .first_or_octet_stream()
                .as_ref()
                .to_string();

            let mut headers = HeaderMap::new();
            if let Ok(val) = HeaderValue::from_str(&mime_type) {
                headers.insert(CONTENT_TYPE, val);
            }
            if let Ok(etag) = HeaderValue::from_str(&format!(
                "\"{}\"",
                hex::encode(content.metadata.sha256_hash())
            )) {
                headers.insert(ETAG, etag);
            }

            Response::builder()
                .status(StatusCode::OK)
                .body(Body::from(content.data))
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
        None => {
            // SPA Fallback 到 index.html
            if let Some(index) = WebAssets::get("index.html") {
                Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "text/html; charset=utf-8")
                    .body(Body::from(index.data))
                    .unwrap_or_else(|_| StatusCode::NOT_FOUND.into_response())
            } else {
                StatusCode::NOT_FOUND.into_response()
            }
        }
    }
}
