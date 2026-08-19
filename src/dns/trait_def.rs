use crate::core::domain::ParsedDomain;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;
use thiserror::Error;

/// DNS 记录类型
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DnsRecordType {
    A,
    AAAA,
}

impl fmt::Display for DnsRecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsRecordType::A => write!(f, "A"),
            DnsRecordType::AAAA => write!(f, "AAAA"),
        }
    }
}

/// DNS 同步状态
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncStatus {
    /// 新增记录成功
    Created,
    /// 更新记录成功
    Updated,
    /// 记录已是最新，无需修改
    Unchanged,
    /// 同步失败
    Failed,
}

impl SyncStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            SyncStatus::Created => "已创建",
            SyncStatus::Updated => "已更新",
            SyncStatus::Unchanged => "未变动",
            SyncStatus::Failed => "失败",
        }
    }
}

impl fmt::Display for SyncStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// 单条记录同步结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRecordResult {
    pub domain: String,
    pub record_type: DnsRecordType,
    pub target_ip: String,
    pub status: SyncStatus,
    pub message: String,
}

impl SyncRecordResult {
    /// 构造“未变动”同步结果
    pub fn unchanged(
        domain: impl Into<String>,
        record_type: DnsRecordType,
        ip: impl Into<String>,
    ) -> Self {
        Self {
            domain: domain.into(),
            record_type,
            target_ip: ip.into(),
            status: SyncStatus::Unchanged,
            message: "记录未发生变化，无需更新".to_string(),
        }
    }

    /// 构造“已更新”同步结果
    pub fn updated(
        domain: impl Into<String>,
        record_type: DnsRecordType,
        ip: impl Into<String>,
    ) -> Self {
        Self {
            domain: domain.into(),
            record_type,
            target_ip: ip.into(),
            status: SyncStatus::Updated,
            message: "记录更新成功".to_string(),
        }
    }

    /// 构造“已创建”同步结果
    pub fn created(
        domain: impl Into<String>,
        record_type: DnsRecordType,
        ip: impl Into<String>,
    ) -> Self {
        Self {
            domain: domain.into(),
            record_type,
            target_ip: ip.into(),
            status: SyncStatus::Created,
            message: "记录添加成功".to_string(),
        }
    }

    /// 构造“失败”同步结果
    pub fn failed(
        domain: impl Into<String>,
        record_type: DnsRecordType,
        ip: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            domain: domain.into(),
            record_type,
            target_ip: ip.into(),
            status: SyncStatus::Failed,
            message: message.into(),
        }
    }
}

#[derive(Debug, Error)]
pub enum DnsProviderError {
    #[error("HTTP 通信错误: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JSON 序列化/反序列化错误: {0}")]
    Json(#[from] serde_json::Error),
    #[error("DNS 服务商未找到根域名对应的 Zone: {0}")]
    ZoneNotFound(String),
    #[error("服务商 API 错误 [{code}]: {message}")]
    ApiError { code: String, message: String },
    #[error("缺少认证凭据: {0}")]
    MissingCredentials(String),
    #[error("其他服务商错误: {0}")]
    Other(String),
}

/// DNS 提供商抽象接口
#[async_trait]
pub trait DnsProvider: Send + Sync {
    /// 服务商名称标识
    fn provider_name(&self) -> &'static str;

    /// 执行记录同步（查询、对比、增删改）
    async fn sync_record(
        &self,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
        ip: &IpAddr,
        ttl: Option<u32>,
    ) -> Result<SyncRecordResult, DnsProviderError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_record_result_constructors() {
        let res_unchanged = SyncRecordResult::unchanged("example.com", DnsRecordType::A, "1.1.1.1");
        assert_eq!(res_unchanged.status, SyncStatus::Unchanged);
        assert_eq!(res_unchanged.domain, "example.com");

        let res_updated = SyncRecordResult::updated("example.com", DnsRecordType::A, "1.1.1.2");
        assert_eq!(res_updated.status, SyncStatus::Updated);

        let res_created = SyncRecordResult::created("example.com", DnsRecordType::AAAA, "::1");
        assert_eq!(res_created.status, SyncStatus::Created);

        let res_failed =
            SyncRecordResult::failed("example.com", DnsRecordType::A, "1.1.1.1", "网络超时");
        assert_eq!(res_failed.status, SyncStatus::Failed);
        assert_eq!(res_failed.message, "网络超时");
    }
}
