pub mod auth;
pub mod config;
pub mod system;
pub mod test;

pub use auth::*;
pub use config::*;
pub use system::*;
pub use test::*;

use crate::config::storage::ConfigManager;
use crate::util::log_buffer::LogBuffer;
use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use log::error;
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Web 管理后台全局共享状态
#[derive(Clone)]
pub struct AppState {
    pub config_manager: Arc<ConfigManager>,
    pub trigger_sender: mpsc::Sender<()>,
    pub log_buffer: LogBuffer,
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

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        error!("Web API 请求失败 [{}]: {}", self.status, self.message);
        (self.status, Json(ApiResponse::<()>::err(self.message))).into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        let anyhow_err = err.into();
        Self::internal(format!("{:#}", anyhow_err))
    }
}
