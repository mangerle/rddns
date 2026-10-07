//! 文本处理基础设施：敏感信息脱敏
//!
//! # 设计原理
//! - **实现初衷**: 凭据脱敏是**跨层通用能力**——DNS 错误文本、通知渠道错误、
//!   Web 访问日志、用户自定义命令串均需经过它。此前该能力定义在
//!   `dns::trait_def`，导致两个方向的问题：
//!   1. `util::logging::buffer`（日志基础设施）反向依赖 `dns`（业务层），
//!      属职责倒置；
//!   2. `notifier` 需跨模块调用 `dns` 的函数来脱敏自身错误，耦合不必要。
//! - **核心优势**: 下沉至 `util`（最底层基础设施）后，`util` 自洽、
//!   `dns` 与 `notifier` 均可正向依赖，依赖方向恢复为
//!   `web → core → dns/ip_fetcher/notifier → config/util`。
//!
//! # 不变式保证
//! 三个正则均为静态硬编码常量，符合标准正则语法，编译必然成功。

use regex::Regex;
use std::sync::LazyLock;

/// 匹配 URL 查询参数中敏感凭据的正则表达式
static SENSITIVE_PARAM_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(key|api_key|apikey|device_key|password|passwd|pwd|secret|appsecret|corpsecret|signature|sign|token|access_token|bot_token|accesskeyid|auth)=([^&\s)]+)")
        .expect("静态敏感参数正则表达式语法必定合法")
});

/// 匹配 Telegram Bot 路径中 Token 的正则表达式（如 /bot123456:ABC-DEF/）
static TELEGRAM_BOT_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)/bot([0-9]{5,}:[A-Za-z0-9_-]{20,})")
        .expect("静态 Telegram Bot 正则表达式语法必定合法")
});

/// 匹配 Authorization Bearer 令牌的正则表达式
static BEARER_TOKEN_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(Bearer\s+)([A-Za-z0-9._~+/-]+=*)")
        .expect("静态 Bearer Token 正则表达式语法必定合法")
});

/// 匹配 JSON 文本中敏感字段的正则表达式
///
/// # 设计原理
/// 部分服务商在响应体中回显请求内容（如回显 token 或完整请求 JSON），
/// 仅脱敏 URL 查询参数无法覆盖 JSON 形态，需单独匹配。
/// 同时兼容双引号包裹的值与 JSON 常见的 `null` 值。
static SENSITIVE_JSON_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)"(key|api_key|apikey|device_key|password|passwd|pwd|secret|appsecret|corpsecret|signature|sign|token|access_token|bot_token|accesskeyid|auth|apiToken)"\s*:\s*("(?:[^"\\]|\\.)*"|[^,}\s]+)"#,
    )
    .expect("静态敏感 JSON 正则表达式语法必定合法")
});

/// 脱敏掩码占位符
pub const MASK_PLACEHOLDER: &str = "******";

/// 错误与响应体最大保留字符数
pub const MAX_ERR_BODY_CHARS: usize = 1024;

/// 截断过长响应体，防止内存放大与正则回溯失控
pub fn truncate_body(body: &str) -> &str {
    match body.char_indices().nth(MAX_ERR_BODY_CHARS) {
        Some((idx, _)) => &body[..idx],
        None => body,
    }
}

/// 对文本先按安全字符数上限截断，再执行敏感凭据脱敏
pub fn format_sanitized_text(input: &str) -> String {
    sanitize_sensitive_params(truncate_body(input))
}

/// 对包含敏感信息（如 API Key、密码、签名等）的 URL 或错误文本进行脱敏
///
/// # 设计原理
/// - **实现初衷**: 多个 DNS 服务商（如 NameSilo、Namecheap 等）使用 GET 请求
///   传递鉴权密钥，当网络异常抛错或服务端返回非预期响应时，会将带凭据的
///   完整 URL 或响应体输出到错误上下文，并最终流向日志、状态面板与第三方
///   通知渠道。
/// - **核心优势**: 统一覆盖 URL 查询串、Telegram 路径、Bearer 令牌与 JSON body
///   四种凭据载体，彻底防范日志与通知中的凭证泄漏。
/// - **代价与局限**: 采用全局正则替换产生字符串复制开销，仅在错误构造与
///   脱敏日志输出时触发，不在高频同步热路径上。
///
/// # 参数
/// - `input`: 待脱敏的原始文本
///
/// # 返回值
/// 脱敏后的文本，所有命中的敏感字段值均被替换为 [`MASK_PLACEHOLDER`]
pub fn sanitize_sensitive_params(input: &str) -> String {
    let url_masked = SENSITIVE_PARAM_REGEX.replace_all(input, "$1=******");
    let tg_masked = TELEGRAM_BOT_REGEX.replace_all(&url_masked, "/bot******");
    let bearer_masked = BEARER_TOKEN_REGEX.replace_all(&tg_masked, "${1}******");
    SENSITIVE_JSON_REGEX
        .replace_all(&bearer_masked, &format!("\"$1\":\"{}\"", MASK_PLACEHOLDER))
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_url_query_params() {
        let raw = "error sending request for url (https://www.namesilo.com/api/dnsListRecords?version=1&type=xml&key=secret123456&sign=mysign999&domain=example.com): operation timed out";
        let sanitized = sanitize_sensitive_params(raw);
        assert!(!sanitized.contains("secret123456"));
        assert!(!sanitized.contains("mysign999"));
        assert!(sanitized.contains("key=******"));
        assert!(sanitized.contains("sign=******"));
        // 非敏感参数必须原样保留
        assert!(sanitized.contains("domain=example.com"));
        assert!(sanitized.contains("version=1"));
    }

    #[test]
    fn test_sanitize_bearer_and_telegram_bot() {
        let raw = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.secret https://api.telegram.org/bot123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw/sendMessage";
        let sanitized = sanitize_sensitive_params(raw);
        assert!(!sanitized.contains("eyJhbGciOiJIUzI1NiJ9.secret"));
        assert!(sanitized.contains("Bearer ******"));
        assert!(!sanitized.contains("AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw"));
        assert!(sanitized.contains("/bot******"));
    }

    #[test]
    fn test_sanitize_json_fields() {
        let raw = r#"{"code":401,"token":"ghp_16CharsOfStuff","corpsecret":"wecom_sec","message":"bad creds"}"#;
        let sanitized = sanitize_sensitive_params(raw);
        assert!(!sanitized.contains("ghp_16CharsOfStuff"));
        assert!(!sanitized.contains("wecom_sec"));
        assert!(sanitized.contains("\"token\":\"******\""));
        assert!(sanitized.contains("\"corpsecret\":\"******\""));
        // 非敏感字段保留
        assert!(sanitized.contains("\"code\":401"));
    }

    #[test]
    fn test_sanitize_handles_null_and_plain_values() {
        // JSON 中 token 为 null 的常见形态
        let raw = r#"{"token":null,"secret":"plain_value"}"#;
        let sanitized = sanitize_sensitive_params(raw);
        assert!(!sanitized.contains("plain_value"));
    }

    #[test]
    fn test_sanitize_is_idempotent() {
        let raw = "key=abc123 Bearer my_secret_token_123";
        let once = sanitize_sensitive_params(raw);
        let twice = sanitize_sensitive_params(&once);
        assert_eq!(once, twice, "重复脱敏不应改变已脱敏文本");
    }

    #[test]
    fn test_sanitize_preserves_ordinary_text() {
        // 普通文本不应被破坏
        let raw = "任务 [NAS] 同步完成，记录数 12，耗时 45ms";
        assert_eq!(sanitize_sensitive_params(raw), raw);
    }
}
