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

/// 单条记录同步结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRecordResult {
    pub domain: String,
    pub record_type: DnsRecordType,
    pub target_ip: String,
    pub status: SyncStatus,
    pub message: String,
}

#[allow(dead_code)]
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
    #[error("签名生成错误: {0}")]
    Signature(String),
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
