use crate::core::domain::ParsedDomain;
use async_trait::async_trait;
use log::{debug, info};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;
use std::sync::LazyLock;

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

/// 匹配 URL 查询参数中敏感凭据的正则表达式
///
/// # 逻辑不变性保证
/// 正则表达式模式串为静态硬编码常量，符合标准正则语法，编译绝对安全且不会失败。
static SENSITIVE_PARAM_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(key|password|passwd|pwd|secret|signature|token|accesskeyid|auth)=([^&\s)]+)")
        .expect("静态敏感参数正则表达式语法必定合法")
});

/// 匹配 Telegram Bot 路径中 Token 的正则表达式（如 /bot123456:ABC-DEF/）
static TELEGRAM_BOT_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)/bot([0-9]{5,}:[A-Za-z0-9_-]{20,})")
        .expect("静态 Telegram Bot 正则表达式语法必定合法")
});

/// 匹配 JSON 文本中敏感字段的正则表达式
///
/// # 设计原理
/// 部分服务商在响应体中回显请求内容（如回显 token 或完整请求 JSON），
/// 仅脱敏 URL 查询参数无法覆盖 JSON 形态，需单独匹配。
/// 同时兼容双引号包裹的值与 JSON 常见的 `null` 值。
///
/// # 逻辑不变性保证
/// 正则表达式模式串为静态硬编码常量，符合标准正则语法，编译绝对安全且不会失败。
static SENSITIVE_JSON_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)"(key|password|passwd|pwd|secret|signature|token|accesskeyid|auth|api_key|apiToken)"\s*:\s*("(?:[^"\\]|\\.)*"|[^,}\s]+)"#,
    )
    .expect("静态敏感 JSON 正则表达式语法必定合法")
});

/// 脱敏掩码占位符
const MASK_PLACEHOLDER: &str = "******";

/// 对包含敏感信息（如 API Key、密码、签名等）的 URL 或错误文本进行脱敏
///
/// # 设计原理
/// - **实现初衷**: 部分 DNS 服务商（如 NameSilo, Namecheap 等）使用 GET 请求传递鉴权密钥，
///   当网络异常抛错或服务端返回非预期响应时，会将带凭据的完整 URL 或响应体
///   输出到错误上下文，并最终流向日志、状态面板与第三方通知渠道。
/// - **核心优势**: 统一覆盖 URL 查询串与 JSON body 两种主要凭据载体，
///   彻底防范日志与通知中的凭证泄漏。
/// - **代价与局限**: 采用全局正则替换产生字符串复制开销，仅在错误构造与
///   脱敏日志输出时触发，不在高频同步热路径上。
pub fn sanitize_sensitive_url_params(input: &str) -> String {
    let url_masked = SENSITIVE_PARAM_REGEX.replace_all(input, "$1=******");
    let tg_masked = TELEGRAM_BOT_REGEX.replace_all(&url_masked, "/bot******");
    SENSITIVE_JSON_REGEX
        .replace_all(&tg_masked, &format!("\"$1\":\"{}\"", MASK_PLACEHOLDER))
        .to_string()
}

/// DNS 提供商同步与通信过程中可能发生的领域错误类型
///
/// # 设计原理
/// 刻意**不使用** `thiserror` 派生，而是手写 [`fmt::Display`]：
/// 目的是把敏感信息脱敏收敛到错误文本的唯一出口（详见该实现注释），
/// 使 27 个 provider 无需逐个改造调用点即自动受保护。
///代价是需手工维护 `From` 转换，已在下方显式列出。
#[derive(Debug)]
pub enum DnsProviderError {
    /// HTTP 通信层错误，文本可能包含带凭据的请求 URL
    Http(String),
    /// JSON 序列化或反序列化错误
    Json(String),
    /// 未找到根域名对应的 Zone，载荷为根域名本身（不含凭据）
    ZoneNotFound(String),
    /// 服务商返回的业务错误，文本可能包含完整响应体
    ApiError { code: String, message: String },
    /// 缺少认证凭据
    MissingCredentials(String),
    /// 其他服务商错误
    Other(String),
}

impl fmt::Display for DnsProviderError {
    /// 统一在错误文本出口处执行脱敏与长度截断 (P2-17)
    ///
    /// # 设计原理
    /// 各服务商在返回非预期响应时，往往把完整响应体塞入错误上下文。
    /// 本实现将脱敏与最大 1024 字符的截断同时收敛到 `Display` 唯一出口：
    /// 无论错误由 40 多个构造点的何处产生，呈现给外部、日志与通知的文本
    /// 都必然经过脱敏并受到长度上限保护，彻底消除长报文引起的内存放大与正则回溯失控。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http(msg) => write!(
                f,
                "HTTP 通信错误: {}",
                truncate_body(&sanitize_sensitive_url_params(msg))
            ),
            Self::Json(err) => write!(
                f,
                "JSON 序列化/反序列化错误: {}",
                truncate_body(&err.to_string())
            ),
            Self::ZoneNotFound(domain) => {
                write!(
                    f,
                    "DNS 服务商未找到根域名对应的 Zone: {}",
                    truncate_body(domain)
                )
            }
            Self::ApiError { code, message } => write!(
                f,
                "服务商 API 错误 [{}]: {}",
                code,
                truncate_body(&sanitize_sensitive_url_params(message))
            ),
            Self::MissingCredentials(msg) => {
                write!(
                    f,
                    "缺少认证凭据: {}",
                    truncate_body(&sanitize_sensitive_url_params(msg))
                )
            }
            Self::Other(msg) => write!(
                f,
                "其他服务商错误: {}",
                truncate_body(&sanitize_sensitive_url_params(msg))
            ),
        }
    }
}

impl std::error::Error for DnsProviderError {}

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

    /// 判定该错误是否属于可重试的临时网络或对端服务瞬时抖动异常 (P1-11)
    pub fn is_retryable(&self) -> bool {
        match self {
            DnsProviderError::Http(_) => true,
            DnsProviderError::ApiError { code, message } => {
                let code_upper = code.to_uppercase();
                let msg_upper = message.to_uppercase();
                code_upper.contains("RATE")
                    || code_upper.contains("THROTTLING")
                    || code_upper.contains("TOOMANYREQUESTS")
                    || code_upper.contains("SERVERERROR")
                    || code_upper == "429"
                    || code_upper == "500"
                    || code_upper == "502"
                    || code_upper == "503"
                    || code_upper == "504"
                    || msg_upper.contains("RATE LIMIT")
                    || msg_upper.contains("TOO MANY REQUESTS")
                    || msg_upper.contains("SERVER TEMPORARILY UNAVAILABLE")
                    || msg_upper.contains("GATEWAY TIMEOUT")
            }
            DnsProviderError::Json(_)
            | DnsProviderError::ZoneNotFound(_)
            | DnsProviderError::MissingCredentials(_)
            | DnsProviderError::Other(_) => false,
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
