pub mod auth;
pub mod config;
pub mod system;
pub mod tasks;
pub mod test;

pub use auth::*;
pub use config::*;
pub use system::*;
pub use tasks::*;
pub use test::*;

use crate::config::storage::ConfigManager;
use crate::core::state::StateManager;
use crate::util::logging::LogBuffer;
use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use log::{debug, error};
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Web 管理后台全局共享状态
#[derive(Clone)]
pub struct AppState {
    pub config_manager: Arc<ConfigManager>,
    pub trigger_sender: mpsc::Sender<()>,
    pub log_buffer: LogBuffer,
    /// 任务运行时状态管理器
    ///
    /// # 设计原理
    /// 与 DDNS 引擎共享同一实例（内部为 `Arc<RwLock<..>>`），使前端得以读取
    /// 结构化运行状态，而不必解析日志文本。
    pub state_manager: StateManager,
    /// 全局退出取消令牌（用于通知在途长连接与 SSE 优雅退出）
    pub cancel_token: CancellationToken,
    /// 活跃的 Web 服务监听端口（服务启动时实际绑定的端口）
    pub active_listen_port: u16,
    /// 活跃的外网访问策略（是否仅绑定本地回环 127.0.0.1）
    pub active_not_allow_wan_access: bool,
}

/// 统一 API 响应包装模型
#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub message: String,
    pub data: Option<T>,
}

impl<T> ApiResponse<T> {
    pub fn ok(data: T) -> Self {
        Self {
            success: true,
            message: "操作成功".to_string(),
            data: Some(data),
        }
    }

    pub fn err(message: String) -> Self {
        Self {
            success: false,
            message,
            data: None,
        }
    }
}

/// 统一 Web API 错误封装 (支持通过 ? 运算符自动转化并输出标准 ApiResponse 响应)
#[derive(Debug)]
pub struct AppError {
    pub status: StatusCode,
    pub message: String,
}

impl AppError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, msg)
    }

    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, msg)
    }

    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, msg)
    }

    pub fn internal(err: impl std::fmt::Display) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for AppError {}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // 对消息换行进行转义并限制日志输出最大长度，杜绝换行日志注入伪造日志行 (P-7)
        let safe_msg = if self.message.contains('\n') || self.message.contains('\r') {
            self.message.replace('\r', "\\r").replace('\n', "\\n")
        } else {
            self.message.clone()
        };
        let truncated_msg = if safe_msg.len() > 256 {
            format!("{}...(截断)", &safe_msg[..256])
        } else {
            safe_msg
        };

        // 遵循 AGENTS.md 日志分级契约：仅 5xx 服务端故障记录 error!，4xx 客户端输入错误记录 debug! (P-7)
        if self.status.is_server_error() {
            error!("Web API 服务端故障 [{}]: {}", self.status, truncated_msg);
        } else {
            debug!(
                "Web API 客户端请求未通过 [{}]: {}",
                self.status, truncated_msg
            );
        }

        (self.status, Json(ApiResponse::<()>::err(self.message))).into_response()
    }
}

/// 配置持久化失败统一映射为 500
///
/// # 设计原理
/// 刻意**不实现** `impl<E: Into<anyhow::Error>> From<E> for AppError` 这类
/// 全泛型转换：它会让任何可转为 `anyhow::Error` 的类型在 `?` 处被隐式
/// 包装成 500 Internal Server Error，使参数校验失败一类的**业务错误**
/// 被错误地伪装为服务端故障，掩盖真实原因。
/// 各调用点应显式 `map_err` 并映射到语义正确的状态码。
impl From<crate::config::storage::ConfigError> for AppError {
    fn from(err: crate::config::storage::ConfigError) -> Self {
        Self::internal(format!("配置读写失败: {}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_app_error_into_response_formatting_and_status() {
        let err_400 = AppError::bad_request("无效的输入\n伪造的日志行");
        let resp_400 = err_400.into_response();
        assert_eq!(resp_400.status(), StatusCode::BAD_REQUEST);

        let err_500 = AppError::internal("系统内部异常");
        let resp_500 = err_500.into_response();
        assert_eq!(resp_500.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
