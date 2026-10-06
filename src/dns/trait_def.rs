use crate::core::domain::ParsedDomain;
use async_trait::async_trait;
use log::{debug, info};
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

/// 全局通用 DNS TTL 默认值（600 秒 / 10 分钟）
pub const DEFAULT_DNS_TTL: u32 = 600;

/// 标准 DNS 记录生存时间安全下限（60 秒）
pub const MIN_DNS_TTL: u32 = 60;

/// 规范化 DNS TTL：未设置时采用 `default_ttl`，且不得低于 `min_ttl`
///
/// # 设计原理
/// - 若用户未指定 TTL，回退至 provider 默认配置（如 `DEFAULT_DNS_TTL` 或厂商特定推荐值）；
/// - 钳制至不低于 `min_ttl`（标准通常为 60s），防止传入 0 或极小值导致权威 DNS 报错拒绝。
#[inline]
pub fn clamp_ttl(ttl: Option<u32>, default_ttl: u32, min_ttl: u32) -> u32 {
    ttl.unwrap_or(default_ttl).max(min_ttl)
}

/// 采用全局默认配置（600s 默认，60s 下限）规范化 TTL
#[inline]
pub fn default_ttl(ttl: Option<u32>) -> u32 {
    clamp_ttl(ttl, DEFAULT_DNS_TTL, MIN_DNS_TTL)
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
        debug!(
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

/// 脱敏掩码占位符
pub const MASK_PLACEHOLDER: &str = crate::util::text::MASK_PLACEHOLDER;

/// 对包含敏感信息（如 API Key、密码、签名等）的 URL 或错误文本进行脱敏
///
/// # 设计原理
/// 实现已下沉至 [`crate::util::text`]（文本基础设施层），此处保留薄转发
/// 以维持既有调用点与 40 余处 provider 代码的稳定 (P1-17)。
///
/// 下沉动因：脱敏是跨层通用能力，此前定义于 `dns` 导致 `util::logging`
/// 反向依赖业务层（日志基础设施依赖 DNS 模块），属职责倒置。
pub fn sanitize_sensitive_url_params(input: &str) -> String {
    crate::util::text::sanitize_sensitive_params(input)
}

/// 对错误描述文本执行统一截断与脱敏输出 (P1-3)
pub fn format_sanitized_err(input: &str) -> String {
    sanitize_sensitive_url_params(truncate_body(input))
}

/// DNS 提供商同步与通信过程中可能发生的领域错误类型
///
/// # 设计原理
/// - **实现初衷**: 采用 [`thiserror::Error`] 派生标准错误契约，同时通过字段级脱敏函数将敏感信息脱敏与最大 1024 字符截断收敛到错误文本的统一出口，使服务商模块无需逐个改造调用点即自动受安全保护。
/// - **核心优势**: 消除手写样板代码，兼顾结构化错误模式匹配与凭据防泄漏。
/// - **Debug 出口防护**: 手写 [`fmt::Debug`] 复用 `Display` 格式化，杜绝 `derive(Debug)` 绕过脱敏导致原始凭据泄漏。
#[derive(Error)]
pub enum DnsProviderError {
    /// HTTP 通信层错误，文本可能包含带凭据的请求 URL
    #[error("HTTP 通信错误: {}", format_sanitized_err(.0))]
    Http(String),

    /// JSON 序列化或反序列化错误
    #[error("JSON 序列化/反序列化错误: {}", truncate_body(.0))]
    Json(String),

    /// 未找到根域名对应的 Zone，载荷为根域名本身（不含凭据）
    #[error("DNS 服务商未找到根域名对应的 Zone: {}", truncate_body(.0))]
    ZoneNotFound(String),

    /// 服务商返回的业务错误，文本可能包含完整响应体
    #[error("服务商 API 错误 [{}]: {}", truncate_body(.code), format_sanitized_err(.message))]
    ApiError { code: String, message: String },

    /// 缺少认证凭据
    #[error("缺少认证凭据: {}", format_sanitized_err(.0))]
    MissingCredentials(String),

    /// 服务商不支持指定的 DNS 记录类型（如 Namecheap 仅支持 IPv4 A 记录）
    #[error("服务商 {provider} 不支持 {record_type} 记录类型")]
    UnsupportedRecordType {
        provider: &'static str,
        record_type: DnsRecordType,
    },

    /// 其他服务商错误
    #[error("其他服务商错误: {}", format_sanitized_err(.0))]
    Other(String),
}

impl fmt::Debug for DnsProviderError {
    /// # 设计原理
    /// 复用 [`fmt::Display`] 的脱敏实现：任何 `{:?}` 格式化路径都经由同一
    /// 脱敏出口，杜绝 `derive(Debug)` 绕过脱敏导致凭据泄漏 (P1-3)。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl From<reqwest::Error> for DnsProviderError {
    fn from(err: reqwest::Error) -> Self {
        Self::Http(err.to_string())
    }
}

impl From<serde_json::Error> for DnsProviderError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err.to_string())
    }
}

/// 错误响应体最大保留字符数 (Q-4)
pub const MAX_ERR_BODY_CHARS: usize = 1024;

/// 截断过长响应体，防止内存放大与正则回溯失控 (Q-4)
pub fn truncate_body(body: &str) -> &str {
    match body.char_indices().nth(MAX_ERR_BODY_CHARS) {
        Some((idx, _)) => &body[..idx],
        None => body,
    }
}

/// 统一比对远程 DNS 记录值与目标 IP 是否一致 (Q-3)
///
/// 核心优势：支持 IPv6 标准化缩写等价比较（如 2001:0db8::1 等价于 2001:db8::1），
/// 杜绝格式差异引发的重复全量写操作。
pub fn ip_value_matches(remote_value: &str, target: &std::net::IpAddr) -> bool {
    match remote_value.trim().parse::<std::net::IpAddr>() {
        Ok(parsed) => &parsed == target,
        Err(_) => remote_value.trim() == target.to_string(),
    }
}

impl DnsProviderError {
    /// 构造服务商 API 错误
    ///
    /// # 设计原理
    /// 错误文本的脱敏已由 [`fmt::Display`] 实现统一兜底，本构造器仅负责
    /// 结构化组装，保留调用点原有的可读构造方式。
    pub fn api(code: impl Into<String>, message: impl Into<String>) -> Self {
        let msg = message.into();
        Self::ApiError {
            code: code.into(),
            message: truncate_body(&msg).to_string(),
        }
    }

    /// 统一的「HTTP 失败」构造器：自动截断过长响应体并携带状态码 (Q-4)
    pub fn http_status(status: reqwest::StatusCode, body: &str) -> Self {
        Self::ApiError {
            code: status.to_string(),
            message: truncate_body(body).to_string(),
        }
    }

    /// 构造限流/频控错误 (明确具备可重试语义)
    pub fn rate_limited(message: impl Into<String>) -> Self {
        Self::ApiError {
            code: "429".to_string(),
            message: truncate_body(&message.into()).to_string(),
        }
    }

    /// 构造服务端临时故障错误 (明确具备可重试语义)
    pub fn server_error(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::ApiError {
            code: code.into(),
            message: truncate_body(&message.into()).to_string(),
        }
    }

    /// 判定该错误是否属于可重试的临时网络或对端服务瞬时抖动异常 (P1-11)
    ///
    /// # 设计原理
    /// - **数字 HTTP 状态码优先**: 对 429 (限流) 以及 500..=504 (服务端宕机/网关超时) 进行无分配整数范围比对。
    /// - **结构化错误码特征匹配**: 识别云服务商标准的频控错误码 (Rate / Throttling / TooManyRequests / ServerError)。
    /// - **错误描述特征匹配**: 兜底匹配错误文本中的频控与网关超时描述。
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) => true,
            Self::ApiError { code, message } => {
                // 1. HTTP 状态码数字快速范围匹配
                if let Ok(status) = code.trim().parse::<u16>()
                    && (status == 429 || (500..=504).contains(&status))
                {
                    return true;
                }

                // 2. 结构化错误码关键字匹配
                const RETRYABLE_CODE_KEYWORDS: &[&str] =
                    &["RATE", "THROTTLING", "TOOMANYREQUESTS", "SERVERERROR"];
                let code_upper = code.to_ascii_uppercase();
                if RETRYABLE_CODE_KEYWORDS
                    .iter()
                    .any(|kw| code_upper.contains(kw))
                {
                    return true;
                }

                // 3. 错误提示描述关键字匹配
                const RETRYABLE_MSG_KEYWORDS: &[&str] = &[
                    "RATE LIMIT",
                    "TOO MANY REQUESTS",
                    "SERVER TEMPORARILY UNAVAILABLE",
                    "GATEWAY TIMEOUT",
                ];
                let msg_upper = message.to_ascii_uppercase();
                RETRYABLE_MSG_KEYWORDS
                    .iter()
                    .any(|kw| msg_upper.contains(kw))
            }
            Self::Json(_)
            | Self::ZoneNotFound(_)
            | Self::MissingCredentials(_)
            | Self::UnsupportedRecordType { .. }
            | Self::Other(_) => false,
        }
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

    /// 查询该服务商是否支持指定的记录类型（如 IPv4 A 记录或 IPv6 AAAA 记录）
    ///
    /// # 默认实现
    /// 默认返回 `true`，表示支持所有标准记录类型。
    /// 仅支持部分类型的服务商（如仅支持 IPv4 的 Namecheap）应覆写此方法返回 `false` (P2-11)。
    fn supports_record_type(&self, _record_type: DnsRecordType) -> bool {
        true
    }

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
#[path = "trait_def_tests.rs"]
mod trait_def_tests;
