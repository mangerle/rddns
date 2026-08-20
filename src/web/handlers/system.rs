use super::{ApiResponse, AppState};
use crate::ip_fetcher::net_interface::list_system_interfaces;
use crate::util::logging::LogEntry;
use crate::util::update::{VersionInfo, check_version, restart_process, upgrade_self};
use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use log::{error, info};

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
    let ifaces = list_system_interfaces();
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

/// 触发在线自动更新并平滑热重启
pub async fn trigger_upgrade_handler() -> impl IntoResponse {
    tokio::spawn(async {
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

    Json(ApiResponse::ok(
        "已在后台启动自动更新，文件下载替换完成后将自动平滑重启服务",
    ))
}
