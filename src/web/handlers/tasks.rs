use super::{ApiResponse, AppState};
use crate::core::state::TaskRuntimeState;
use axum::Json;
use axum::extract::State;
use std::collections::HashMap;

/// 查询全部 DNS 任务的运行时状态快照
///
/// # 设计原理
/// - **实现初衷**: 此前运行状态仅存在于引擎内部，前端只能解析 SSE 日志文本
///   反推「上次同步时间」「连续失败次数」，导致日志格式成为事实上的数据通道。
/// - **核心优势**: 暴露结构化状态后，日志格式调整与 UI 展示彻底解耦。
/// - **安全约束**: 返回内容包含域名与解析 IP，必须置于鉴权中间件之后；
///   `last_error` 已由 `TaskRuntimeState::sanitized` 截断，防止服务商原始
///   报文中的账号信息外泄。
pub async fn get_task_status_handler(
    State(state): State<AppState>,
) -> Json<ApiResponse<HashMap<String, TaskRuntimeState>>> {
    let snapshot: HashMap<String, TaskRuntimeState> = state.state_manager.snapshot_all();
    Json(ApiResponse::ok(snapshot))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::storage::ConfigManager;
    use crate::core::state::StateManager;
    use crate::util::logging::LogBuffer;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    fn build_state() -> AppState {
        let (tx, _rx) = mpsc::channel(1);
        let dir = tempfile::tempdir().expect("创建临时目录失败");
        let config_path = dir.path().join("config.yaml");
        let config_manager =
            Arc::new(ConfigManager::load_or_create(config_path).expect("加载配置失败"));
        AppState {
            config_manager,
            trigger_sender: tx,
            log_buffer: LogBuffer::new(10),
            state_manager: StateManager::new(),
            cancel_token: tokio_util::sync::CancellationToken::new(),
        }
    }

    #[tokio::test]
    async fn test_task_status_returns_empty_map_when_no_task_ran() {
        let state = build_state();
        let Json(resp) = get_task_status_handler(State(state)).await;
        assert!(resp.success);
        let data = resp.data.expect("应返回数据体");
        assert!(data.is_empty(), "未执行过任务时应返回空快照");
    }

    #[tokio::test]
    async fn test_task_status_exposes_structured_state() {
        let state = build_state();
        // 模拟引擎写入运行状态
        state.state_manager.update_task_state("家用 NAS", |s| {
            s.last_ipv4 = Some("1.2.3.4".parse().unwrap());
            s.consecutive_failures = 3;
            s.last_error = Some("连接超时".to_string());
            s.last_sync_time = Some("2026-10-04 12:00:00".to_string());
            s.synced_domains
                .insert("nas.example.com:A".to_string(), "1.2.3.4".to_string());
        });

        let Json(resp) = get_task_status_handler(State(state)).await;
        assert!(resp.success);
        let data = resp.data.expect("应返回数据体");

        // 前端应能直接读到结构化字段，无需解析日志文本
        let task = data.get("家用 NAS").expect("应包含该任务状态");
        assert_eq!(task.last_ipv4, Some("1.2.3.4".parse().unwrap()));
        assert_eq!(task.consecutive_failures, 3);
        assert_eq!(task.last_error.as_deref(), Some("连接超时"));
        assert_eq!(task.last_sync_time.as_deref(), Some("2026-10-04 12:00:00"));
        assert_eq!(
            task.synced_domains.get("nas.example.com:A"),
            Some(&"1.2.3.4".to_string())
        );
    }

    #[tokio::test]
    async fn test_task_status_truncates_oversized_error() {
        let state = build_state();
        // 模拟服务商返回超长原始报文
        let long_error = "服务商标记 ERR ".repeat(200);
        state.state_manager.update_task_state("超长错误任务", |s| {
            s.last_error = Some(long_error);
        });

        let Json(resp) = get_task_status_handler(State(state)).await;
        let data = resp.data.expect("应返回数据体");
        let task = data.get("超长错误任务").expect("应包含该任务状态");
        let err = task.last_error.as_deref().expect("应保留错误摘要");

        // 截断后长度受控，且带截断标记，避免原始报文中的敏感信息外泄
        assert!(
            err.chars().count() <= 520,
            "错误摘要长度应受控，实际 {} 字符",
            err.chars().count()
        );
        assert!(err.ends_with("...(已截断)"), "应带有截断标记");
    }
}
