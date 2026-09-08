use crate::core::domain::ParsedDomain;
use async_trait::async_trait;
use log::info;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;
use std::sync::LazyLock;
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

    /// 记录日志并构造“未变动”同步结果
    pub fn unchanged_log(
        provider: &str,
        domain: impl Into<String>,
        record_type: DnsRecordType,
        ip: impl Into<String>,
    ) -> Self {
        let domain_str = domain.into();
        let ip_str = ip.into();
        info!(
            "[{}] 域名 {} 记录未变化 ({}), 跳过更新",
            provider, domain_str, ip_str
        );
        Self::unchanged(domain_str, record_type, ip_str)
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

    /// 记录日志并构造“已更新”同步结果
    pub fn updated_log(
        provider: &str,
        domain: impl Into<String>,
        record_type: DnsRecordType,
        ip: impl Into<String>,
    ) -> Self {
        let domain_str = domain.into();
        let ip_str = ip.into();
        info!("[{}] 成功更新域名 {} -> {}", provider, domain_str, ip_str);
        Self::updated(domain_str, record_type, ip_str)
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

    /// 记录日志并构造“已创建”同步结果
    pub fn created_log(
        provider: &str,
        domain: impl Into<String>,
        record_type: DnsRecordType,
        ip: impl Into<String>,
    ) -> Self {
        let domain_str = domain.into();
        let ip_str = ip.into();
        info!(
            "[{}] 成功创建域名解析 {} -> {}",
            provider, domain_str, ip_str
        );
        Self::created(domain_str, record_type, ip_str)
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

/// 匹配 URL 查询参数中敏感凭据的正则表达式
///
/// # 逻辑不变性保证
/// 正则表达式模式串为静态硬编码常量，符合标准正则语法，编译绝对安全且不会失败。
static SENSITIVE_PARAM_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(key|password|passwd|secret|signature|token|accesskeyid|auth)=([^&\s)]+)")
        .expect("静态敏感参数正则表达式语法必定合法")
});

/// 对包含敏感信息（如 API Key、密码、签名等）的 URL 或错误文本进行脱敏
///
/// # 设计原理
/// - **实现初衷**: 部分 DNS 服务商（如 NameSilo, Namecheap 等）使用 GET 请求传递鉴权密钥，当网络异常抛错时会将带凭据的完整 URL 输出到错误上下文。
/// - **核心优势**: 通过静态预编译正则对敏感键值对进行统一脱敏掩码（替换为 `******`），彻底防范日志与通知中的凭证泄漏。
/// - **代价与局限**: 采用全局正则替换产生轻微字符串复制开销，仅在网络错误或脱敏日志输出时触发。
pub fn sanitize_sensitive_url_params(input: &str) -> String {
    SENSITIVE_PARAM_REGEX
        .replace_all(input, "$1=******")
        .to_string()
}

/// DNS 提供商同步与通信过程中可能发生的领域错误类型
#[derive(Debug, Error)]
pub enum DnsProviderError {
    #[error("HTTP 通信错误: {0}")]
    Http(String),
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

impl From<reqwest::Error> for DnsProviderError {
    fn from(err: reqwest::Error) -> Self {
        Self::Http(sanitize_sensitive_url_params(&err.to_string()))
    }
}

/// DNS 提供商抽象接口
///
/// # 设计原理
/// - **实现初衷**: 屏蔽不同 DNS 解析商（如阿里云、腾讯云、Cloudflare、华为云、火山引擎等）各异的 REST API、签名算法与数据模型，向上层调度引擎暴露统一的同步契约。
/// - **核心优势**: 标准化单条解析记录的查询、比对与同步（新增/修改/跳过），支持零变动检测避免无谓调用。
/// - **代价与局限**: 各服务商针对特定记录（如 CAA, TXT 或 SRV）的高级特性被屏蔽，仅专注于 DDNS 必需的 A 与 AAAA 记录同步。
#[async_trait]
pub trait DnsProvider: Send + Sync {
    /// 服务商名称标识
    fn provider_name(&self) -> &'static str;

    /// 执行记录同步（查询、对比、增删改）
    ///
    /// # Errors
    ///
    /// 当凭据不正确、网络通信失败或服务商 API 返回错误码时返回 [`DnsProviderError`]。
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
    fn test_sanitize_sensitive_url_params() {
        let raw_err = "error sending request for url (https://www.namesilo.com/api/dnsListRecords?version=1&type=xml&key=secret123456&domain=example.com): operation timed out";
        let sanitized = sanitize_sensitive_url_params(raw_err);
        assert!(!sanitized.contains("secret123456"));
        assert!(sanitized.contains("key=******"));

        let raw_nc = "https://dynamicdns.park-your-domain.com/update?host=@&domain=test.com&password=my_password_xyz&ip=1.1.1.1";
        let sanitized_nc = sanitize_sensitive_url_params(raw_nc);
        assert!(!sanitized_nc.contains("my_password_xyz"));
        assert!(sanitized_nc.contains("password=******"));
    }

    #[test]
    fn test_sync_record_result_constructors() {
        let res_unchanged = SyncRecordResult::unchanged("example.com", DnsRecordType::A, "1.1.1.1");
        assert_eq!(res_unchanged.status, SyncStatus::Unchanged);
        assert_eq!(res_unchanged.domain, "example.com");

        let res_updated = SyncRecordResult::updated("example.com", DnsRecordType::A, "1.1.1.2");
        assert_eq!(res_updated.status, SyncStatus::Updated);

        let res_created = SyncRecordResult::created("example.com", DnsRecordType::AAAA, "::1");
        assert_eq!(res_created.status, SyncStatus::Created);

        let res_unchanged_log = SyncRecordResult::unchanged_log(
            "TestProvider",
            "example.com",
            DnsRecordType::A,
            "1.1.1.1",
        );
        assert_eq!(res_unchanged_log.status, SyncStatus::Unchanged);

        let res_updated_log = SyncRecordResult::updated_log(
            "TestProvider",
            "example.com",
            DnsRecordType::A,
            "1.1.1.2",
        );
        assert_eq!(res_updated_log.status, SyncStatus::Updated);

        let res_created_log = SyncRecordResult::created_log(
            "TestProvider",
            "example.com",
            DnsRecordType::AAAA,
            "::1",
        );
        assert_eq!(res_created_log.status, SyncStatus::Created);

        let res_failed =
            SyncRecordResult::failed("example.com", DnsRecordType::A, "1.1.1.1", "网络超时");
        assert_eq!(res_failed.status, SyncStatus::Failed);
        assert_eq!(res_failed.message, "网络超时");
    }
}
