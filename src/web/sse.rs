use crate::web::handlers::AppState;
use axum::extract::State;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::IntoResponse;
use std::convert::Infallible;
use std::time::Duration;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

/// 实时日志 SSE 推流处理器
pub async fn sse_log_handler(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let rx = state.log_buffer.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|item| {
        match item {
            Ok(entry) => serde_json::to_string(&entry)
                .ok()
                .map(|json_str| Ok::<Event, Infallible>(Event::default().data(json_str))),
            Err(_) => None,
        }
    });

    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}
