use crate::web::handlers::AppState;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::response::sse::{Event, KeepAlive, Sse};
use log::debug;
use std::convert::Infallible;
use std::time::Duration;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;

/// 实时日志 SSE 推流处理器
pub async fn sse_log_handler(State(state): State<AppState>) -> impl IntoResponse {
    let rx = state.log_buffer.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|item| match item {
        Ok(entry) => serde_json::to_string(&entry)
            .ok()
            .map(|json_str| Ok::<Event, Infallible>(Event::default().data(json_str))),
        Err(BroadcastStreamRecvError::Lagged(missed)) => {
            debug!("SSE 客户端消费落后，跳过了 {} 条历史日志", missed);
            None
        }
    });

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    )
}
