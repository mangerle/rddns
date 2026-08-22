use super::{ApiResponse, AppState};
use crate::ip_fetcher::net_interface::list_system_interfaces;
use crate::util::logging::LogEntry;
use crate::util::update::{VersionInfo, check_version, restart_process, upgrade_self};
use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use log::{error, info};
use std::sync::atomic::{AtomicBool, Ordering};

/// 手动触发立即全量同步
pub async fn manual_sync_handler(State(state): State<AppState>) -> impl IntoResponse {
    let _ = state.trigger_sender.send(()).await;
    Json(ApiResponse::ok("已触发后台全量同步"))
}

/// 获取最近操作日志快照
pub async fn get_logs_handler(State(state): State<AppState>) -> impl IntoResponse {
    let logs: Vec<LogEntry> = state.log_buffer.get_recent();
    Json(ApiResponse::ok(logs))
}

/// 获取当前系统可用的网卡列表
pub async fn get_network_interfaces_handler() -> impl IntoResponse {
    let ifaces = tokio::task::spawn_blocking(list_system_interfaces)
        .await
        .unwrap_or_default();
    Json(ApiResponse::ok(ifaces))
}

/// 获取系统版本与更新信息 (支持优雅降级，GitHub 连接失败时不抛 500 且不刷 ERROR 日志)
pub async fn get_version_handler() -> impl IntoResponse {
    match check_version().await {
        Ok(info) => Json(ApiResponse::ok(info)),
        Err(e) => {
            log::debug!("获取 GitHub 最新版本失败 (已安全降级为本地版本): {:#}", e);
            let current_version = env!("CARGO_PKG_VERSION").to_string();
            let fallback_info = VersionInfo {
                current_version: current_version.clone(),
                latest_version: current_version,
                has_update: false,
                release_url: String::new(),
                release_notes: String::new(),
            };
            Json(ApiResponse::ok(fallback_info))
        }
    }
}

/// 全局更新状态锁 (防止并发触发重复下载与文件覆盖)
static IS_UPGRADING: AtomicBool = AtomicBool::new(false);

/// 触发在线自动更新并平滑热重启 (带并发防重锁)
pub async fn trigger_upgrade_handler() -> impl IntoResponse {
    if IS_UPGRADING
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Json(ApiResponse::err(
            "当前已有更新任务正在进行中，请勿重复触发！".to_string(),
        ));
    }

    tokio::spawn(async {
        let upgrade_res = upgrade_self().await;
        IS_UPGRADING.store(false, Ordering::SeqCst);

        match upgrade_res {
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

    Json(ApiResponse::ok(
        "已在后台启动自动更新，文件下载替换完成后将自动平滑重启服务",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_trigger_upgrade_concurrency_lock() {
        IS_UPGRADING.store(true, Ordering::SeqCst);
        let resp = trigger_upgrade_handler().await.into_response();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        // 清理状态
        IS_UPGRADING.store(false, Ordering::SeqCst);
    }
}
