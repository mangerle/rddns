use crate::dns::trait_def::SyncRecordResult;
use async_trait::async_trait;
use chrono::{DateTime, Local};
use std::net::{Ipv4Addr, Ipv6Addr};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NotifyError {
    #[error("HTTP 请求失败: {0}")]
    Http(#[from] reqwest::Error),
    #[error("邮件发送错误: {0}")]
    Email(String),
    #[error("数据序列化错误: {0}")]
    Json(#[from] serde_json::Error),
    #[error("通知服务商返回错误: {0}")]
    Provider(String),
}

/// 同步总状态标识
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationOverallStatus {
    Success,
    Failed,
    PartialSuccess,
}

impl NotificationOverallStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "同步成功",
            Self::Failed => "同步失败",
            Self::PartialSuccess => "部分成功",
        }
    }
}

/// 领域通知事件实体
#[derive(Debug, Clone)]
pub struct NotificationEvent {
    pub overall_status: NotificationOverallStatus,
    pub task_name: String,
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
    pub ip_changed: bool,
    pub results: Vec<SyncRecordResult>,
    pub timestamp: DateTime<Local>,
}

impl NotificationEvent {
    /// 生成格式化的摘要详情文本
    pub fn format_details_text(&self) -> String {
        let mut lines = Vec::new();
        for r in &self.results {
            lines.push(format!(
                "- [{}] {} ({}) -> 状态: {:?}, {}",
                r.record_type, r.domain, r.target_ip, r.status, r.message
            ));
        }
        lines.join("\n")
    }

    /// 获取涉及的所有域名列表（逗号分隔）
    pub fn domains_comma_separated(&self) -> String {
        let mut domains: Vec<String> = self.results.iter().map(|r| r.domain.clone()).collect();
        domains.dedup();
        domains.join(", ")
    }
}

/// 统一的通知发送者接口
#[async_trait]
pub trait Notifier: Send + Sync {
    /// 渠道标识名称
    fn channel_name(&self) -> &'static str;

    /// 发送通知
    async fn send(&self, event: &NotificationEvent) -> Result<(), NotifyError>;
}
