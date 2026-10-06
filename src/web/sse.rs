use crate::web::handlers::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::sse::{Event, KeepAlive, Sse};
use futures_util::StreamExt;
use log::{debug, warn};
use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;

/// 最大并发 SSE 日志流连接数硬上限
///
/// # 设计原理
/// - **实现初衷**: 防止恶意刷新或僵尸客户端无限建立 SSE 长连接耗尽系统文件描述符与内存。
/// - **核心优势**: 管理后台仅供管理员使用，32 个连接极为充裕；超出时快速返回 429 保护系统资源。
pub const MAX_CONCURRENT_SSE_CONNECTIONS: usize = 32;

static ACTIVE_SSE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

/// SSE 连接计数 RAII 守卫
#[derive(Debug)]
pub struct SseConnectionGuard;

impl SseConnectionGuard {
    /// 尝试获取连接配额
    pub fn try_acquire() -> Option<Self> {
        let mut current = ACTIVE_SSE_CONNECTIONS.load(Ordering::Relaxed);
        loop {
            if current >= MAX_CONCURRENT_SSE_CONNECTIONS {
                return None;
            }
            match ACTIVE_SSE_CONNECTIONS.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(Self),
                Err(actual) => current = actual,
            }
        }
    }

    /// 获取当前活跃连接数
    pub fn active_count() -> usize {
        ACTIVE_SSE_CONNECTIONS.load(Ordering::Relaxed)
    }
}

impl Drop for SseConnectionGuard {
    fn drop(&mut self) {
        ACTIVE_SSE_CONNECTIONS.fetch_sub(1, Ordering::AcqRel);
    }
}

/// 实时日志 SSE 推流处理器 (支持并发连接数硬上限防护、连接初次自动回放历史快照与优雅降级)
///
/// # 设计原理
/// - **实现初衷**: 解决客户端建立连接或页面刷新后此前运行日志丢失的问题。在连接建立瞬间优先回放内存环形缓冲区中的历史快照，随后无缝接入实时广播流。
/// - **核心优势**: 通过先订阅广播通道后拉取历史快照，并基于自增 `id` 过滤掉连接瞬间产生的重复项，杜绝日志遗漏与乱序。
pub async fn sse_log_handler(State(state): State<AppState>) -> impl IntoResponse {
    let guard = match SseConnectionGuard::try_acquire() {
        Some(g) => Arc::new(g),
        None => {
            warn!(
                "SSE 实时日志连接数已达上限 ({})，拒绝新连接",
                MAX_CONCURRENT_SSE_CONNECTIONS
            );
            return (
                StatusCode::TOO_MANY_REQUESTS,
                "当前活跃日志流连接数已达上限，请稍后重试",
            )
                .into_response();
        }
    };

    // 1. 先订阅实时通道，再读取历史快照，防止在订阅与取快照的微小间隙内产生日志遗漏
    let rx = state.log_buffer.subscribe();
    let recent = state.log_buffer.get_recent();
    let last_history_id = recent.last().map(|e| e.id).unwrap_or(0);

    let cancel = state.cancel_token.clone();
    let stream_guard = guard.clone();

    // 2. 构造历史日志快照流
    let history_stream = futures_util::stream::iter(recent.into_iter().filter_map(|entry| {
        serde_json::to_string(&entry)
            .ok()
            .map(|json_str| Ok::<Event, Infallible>(Event::default().data(json_str)))
    }));

    // 3. 构造实时增量广播流，过滤快照中已包含的旧日志 (id <= last_history_id)
    let live_stream = BroadcastStream::new(rx).filter_map(move |item| {
        let _g = stream_guard.clone();
        async move {
            let _ref = &_g;
            match item {
                Ok(entry) => {
                    if entry.id <= last_history_id {
                        return None;
                    }
                    serde_json::to_string(&entry)
                        .ok()
                        .map(|json_str| Ok::<Event, Infallible>(Event::default().data(json_str)))
                }
                Err(BroadcastStreamRecvError::Lagged(missed)) => {
                    debug!("SSE 客户端消费落后，跳过了 {} 条历史日志", missed);
                    None
                }
            }
        }
    });

    let stream = history_stream.chain(live_stream).take_until(async move {
        cancel.cancelled().await;
    });

    drop(guard);

    Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("keep-alive"),
        )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sse_connection_guard_lifecycle_and_limit() {
        let initial = SseConnectionGuard::active_count();
        let mut guards = Vec::new();

        // 占满全部剩余名额
        while let Some(g) = SseConnectionGuard::try_acquire() {
            guards.push(g);
        }

        assert_eq!(
            SseConnectionGuard::active_count(),
            MAX_CONCURRENT_SSE_CONNECTIONS
        );
        // 满额后再次获取必定返回 None
        assert!(SseConnectionGuard::try_acquire().is_none());

        // 释放一个名额
        let released = guards.pop();
        drop(released);
        assert_eq!(
            SseConnectionGuard::active_count(),
            MAX_CONCURRENT_SSE_CONNECTIONS - 1
        );

        // 此时可以成功获取一个名额
        let new_guard = SseConnectionGuard::try_acquire();
        assert!(new_guard.is_some());
        guards.push(new_guard.unwrap());

        // 清理全部守卫恢复现场
        drop(guards);
        assert_eq!(SseConnectionGuard::active_count(), initial);
    }

    #[tokio::test]
    async fn test_sse_history_replay() {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let config_manager =
            Arc::new(crate::config::storage::ConfigManager::load_or_create(config_path).unwrap());
        let log_buffer = crate::util::logging::LogBuffer::new(10);
        log_buffer.push(log::Level::Info, "test_target", "历史测试日志".to_string());

        let state = AppState {
            config_manager,
            trigger_sender: tx,
            log_buffer: log_buffer.clone(),
            state_manager: crate::core::state::StateManager::new(),
            cancel_token: tokio_util::sync::CancellationToken::new(),
            active_listen_port: 9876,
            active_not_allow_wan_access: true,
        };

        let resp = sse_log_handler(axum::extract::State(state))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
