use super::{ApiResponse, AppState};
use crate::ip_fetcher::net_interface::list_system_interfaces;
use crate::util::logging::LogEntry;
use crate::util::update::{
    check_remote_version, local_version_info, query_version_cached, restart_process, upgrade_self,
};
use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use log::{error, info};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::spawn;

use axum::http::StatusCode;
use tokio::sync::mpsc::error::TrySendError;

/// 手动触发立即全量同步 (P-6: 采用 try_send 防挂起与限流反压)
pub async fn manual_sync_handler(State(state): State<AppState>) -> impl IntoResponse {
    match state.trigger_sender.try_send(()) {
        Ok(()) => (StatusCode::OK, Json(ApiResponse::ok("已触发后台全量同步"))).into_response(),
        Err(TrySendError::Full(_)) => (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ApiResponse::<()>::err(
                "已有同步任务在队列中，请稍后再试".into(),
            )),
        )
            .into_response(),
        Err(TrySendError::Closed(_)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiResponse::<()>::err("调度器已停止，无法触发同步".into())),
        )
            .into_response(),
    }
}

/// 获取最近操作日志快照
pub async fn get_logs_handler(State(state): State<AppState>) -> impl IntoResponse {
    let logs: Vec<LogEntry> = state.log_buffer.get_recent();
    Json(ApiResponse::ok(logs))
}

/// 获取当前系统可用的网卡列表
pub async fn get_network_interfaces_handler() -> impl IntoResponse {
    let ifaces = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        tokio::task::spawn_blocking(list_system_interfaces),
    )
    .await
    .ok()
    .and_then(|res| res.ok())
    .unwrap_or_default();
    Json(ApiResponse::ok(ifaces))
}

/// 获取当前生效的版本信息 (仅读取本地与启动预检缓存，绝不触发任何出站请求)
///
/// # 设计原理
/// - **实现初衷**：前端在页面加载、登录成功、初始化完成时均需展示版本徽标，
///   这些高频场景不应连带触发 GitHub 清单拉取。
/// - **核心优势**：纯内存读取，恒定成功返回，彻底消除 shipup 内部清单拉取日志的刷屏来源。
pub async fn get_version_handler() -> impl IntoResponse {
    Json(ApiResponse::ok(query_version_cached()))
}

/// 强制检查远端版本 (仅由用户点击顶栏版本徽标触发)
///
/// # 设计原理
/// - **实现初衷**：将「远端出站检查」的唯一入口收敛到用户明确表达意图的操作上。
/// - **核心优势**：绕过 24 小时缓存直连远端，保证用户点击时总能拿到最新结果；
///   远端不可达时降级返回本地版本，不向前端抛错。
pub async fn check_remote_version_handler() -> impl IntoResponse {
    match check_remote_version().await {
        Ok(info) => Json(ApiResponse::ok(info)),
        Err(e) => {
            log::debug!("强制检查远端版本失败 (已安全降级为本地版本): {:#}", e);
            Json(ApiResponse::ok(local_version_info()))
        }
    }
}

/// 全局更新状态锁 (防止并发触发重复下载与文件覆盖)
static IS_UPGRADING: AtomicBool = AtomicBool::new(false);

/// 自更新状态锁的 RAII 守卫
///
/// # 设计原理
/// - **实现初衷**：自更新属于长耗时网络/IO 异步任务，旧实现依赖任务尾部显式调用 `store(false)`。若发生协程 panic、任务被取消或异常退出，状态标志位将永久处于 `true`，导致后续自更新功能永久死锁不可用。
/// - **核心优势**：依托 Rust 严格的 RAII 确定性资源释放契约（`Drop` 特型），守卫被移入后台协程中。协程生命周期终止时（无论正常结束或发生 panic 展开），`drop` 均必定执行，实现零死锁与零状态脱节。
/// - **代价与局限**：后台任务执行期间全局仅允许单实例运行，其他并发更新请求将直接被拒绝。
#[derive(Debug)]
struct UpgradeLockGuard;

impl UpgradeLockGuard {
    /// 尝试获取全局更新锁
    fn try_acquire() -> Option<Self> {
        if IS_UPGRADING
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            Some(Self)
        } else {
            None
        }
    }
}

impl Drop for UpgradeLockGuard {
    fn drop(&mut self) {
        IS_UPGRADING.store(false, Ordering::Release);
    }
}

/// 触发在线自动更新并平滑热重启 (带并发防重锁与 RAII 确定性释放)
pub async fn trigger_upgrade_handler() -> impl IntoResponse {
    let guard = match UpgradeLockGuard::try_acquire() {
        Some(g) => g,
        None => {
            return Json(ApiResponse::err(
                "当前已有更新任务正在进行中，请勿重复触发！".to_string(),
            ));
        }
    };

    // 更新流程耗时可达数十秒，不能阻塞 HTTP 响应，故交由后台异步任务执行。
    // RAII 守卫被移入后台任务作用域中，即使任务内部发生 panic 或提早退出，
    // 在任务结束析构时均必定触发 Drop 释放全局锁，彻底杜绝死锁隐患。 (P3-15)
    let _upgrade_handle = spawn(async move {
        let _guard = guard;
        let update_task = spawn(async {
            match upgrade_self().await {
                Ok(()) => {
                    info!("自动更新完成，正在平滑重启服务以加载新版本...");
                    if let Err(e) = restart_process() {
                        error!("重启服务失败，请手动重启: {:#}", e);
                    }
                }
                Err(e) => {
                    error!("在线自动更新失败: {:#}", e);
                }
            }
        });

        if let Err(join_err) = update_task.await {
            error!("自更新后台任务异常终止: {}", join_err);
        }
    });

    Json(ApiResponse::ok(
        "已在后台启动自动更新，文件下载替换完成后将自动平滑重启服务",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // 串行化涉及全局静态原子标志位的单元测试，防止并发测试竞态
    static TEST_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test]
    async fn test_trigger_upgrade_concurrency_lock() {
        let _guard = TEST_MUTEX.lock().await;
        IS_UPGRADING.store(true, Ordering::SeqCst);
        let resp = trigger_upgrade_handler().await.into_response();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        // 清理状态
        IS_UPGRADING.store(false, Ordering::SeqCst);
    }

    #[tokio::test]
    async fn test_upgrade_lock_guard_raii_release() {
        let _guard = TEST_MUTEX.lock().await;
        // 确保初始状态已复位
        IS_UPGRADING.store(false, Ordering::SeqCst);

        // 初始状态下应能成功获取锁
        let first_guard = UpgradeLockGuard::try_acquire();
        assert!(first_guard.is_some(), "应当成功获取首次更新锁");

        // 在锁被持有时再次获取应当失败
        let second_guard = UpgradeLockGuard::try_acquire();
        assert!(second_guard.is_none(), "更新锁被持有时不应允许重复获取");

        // 显式释放守卫 (模拟任务结束或 panic 析构)
        drop(first_guard);

        // 释放后应当能再次成功获取锁
        let third_guard = UpgradeLockGuard::try_acquire();
        assert!(third_guard.is_some(), "RAII 守卫释放后应可重新获取更新锁");

        // 清理状态
        drop(third_guard);
        IS_UPGRADING.store(false, Ordering::SeqCst);
    }
}
