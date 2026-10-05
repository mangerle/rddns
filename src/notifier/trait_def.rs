use crate::dns::trait_def::SyncRecordResult;
use async_trait::async_trait;
use chrono::{DateTime, Local};
use regex::Regex;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;

#[derive(Debug)]
pub enum NotifyError {
    /// 网络请求错误，文本可能包含敏感 URL
    Http(String),
    /// 邮件发送错误
    Email(String),
    /// 数据序列化或反序列化错误
    Json(String),
    /// 通知服务商返回的业务错误
    Provider(String),
}

impl fmt::Display for NotifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http(msg) => write!(
                f,
                "HTTP 请求失败: {}",
                crate::dns::trait_def::sanitize_sensitive_url_params(msg)
            ),
            Self::Email(m) => write!(
                f,
                "邮件发送错误: {}",
                crate::dns::trait_def::sanitize_sensitive_url_params(m)
            ),
            Self::Json(msg) => write!(f, "数据序列化错误: {}", msg),
            Self::Provider(m) => write!(
                f,
                "通知服务商返回错误: {}",
                crate::dns::trait_def::sanitize_sensitive_url_params(m)
            ),
        }
    }
}

impl NotifyError {
    /// 判定该错误是否可重试 (P2-8)
    ///
    /// 区分瞬时错误（网络超时、连接抖动、服务不可用）与永久错误（4xx 客户端认证或语法错误、JSON解析失败等）。
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Json(_) => false,
            Self::Http(msg) => {
                let lower = msg.to_lowercase();
                if lower.contains("400 bad request")
                    || lower.contains("401 unauthorized")
                    || lower.contains("403 forbidden")
                    || lower.contains("404 not found")
                {
                    return false;
                }
                true
            }
            Self::Email(msg) => {
                let lower = msg.to_lowercase();
                if lower.contains("authentication failed")
                    || lower.contains("invalid credentials")
                    || lower.contains("535")
                {
                    return false;
                }
                true
            }
            Self::Provider(msg) => {
                let lower = msg.to_lowercase();
                if lower.contains("invalid")
                    || lower.contains("unauthorized")
                    || lower.contains("forbidden")
                    || lower.contains("not found")
                    || lower.contains("errcode\":400")
                    || lower.contains("errcode\":40001")
                    || lower.contains("errcode\":48001")
                    || lower.contains("errcode\":40014")
                {
                    return false;
                }
                true
            }
        }
    }
}

impl std::error::Error for NotifyError {}

impl From<reqwest::Error> for NotifyError {
    fn from(e: reqwest::Error) -> Self {
        Self::Http(e.to_string())
    }
}

impl From<serde_json::Error> for NotifyError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e.to_string())
    }
}

/// HTML 特殊字符转义（防御 XSS 与标签注入）
pub(crate) fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
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
                "- [{}] {} ({}) -> 状态: {}, {}",
                r.record_type, r.domain, r.target_ip, r.status, r.message
            ));
        }
        lines.join("\n")
    }

    /// 获取涉及的所有域名列表（逗号分隔，保持首次出现顺序且全局无重复）
    pub fn domains_comma_separated(&self) -> String {
        let mut seen = std::collections::HashSet::new();
        let domains: Vec<String> = self
            .results
            .iter()
            .filter_map(|r| {
                if seen.insert(&r.domain) {
                    Some(r.domain.clone())
                } else {
                    None
                }
            })
            .collect();
        domains.join(", ")
    }

    /// 获取 IPv4 格式化字符串，未探测到时返回“无”
    pub fn ipv4_str(&self) -> String {
        self.ipv4
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "无".to_string())
    }

    /// 获取 IPv6 格式化字符串，未探测到时返回“无”
    pub fn ipv6_str(&self) -> String {
        self.ipv6
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "无".to_string())
    }

    /// 获取格式化时间文本 (YYYY-MM-DD HH:MM:SS)
    pub fn time_str(&self) -> String {
        self.timestamp.format("%Y-%m-%d %H:%M:%S").to_string()
    }

    /// 统一生成标准 Markdown 通知正文 (P2-14)
    pub fn format_markdown_summary(&self) -> String {
        format!(
            "### rddns 动态解析 [{}]\n\
            > **任务名称**：{}\n\
            > **IPv4 地址**：{}\n\
            > **IPv6 地址**：{}\n\
            > **解析域名**：{}\n\
            > **触发时间**：{}\n\n\
            #### 同步结果：\n{}",
            self.overall_status.as_str(),
            self.task_name,
            self.ipv4_str(),
            self.ipv6_str(),
            self.domains_comma_separated(),
            self.time_str(),
            self.format_details_text()
        )
    }

    /// 统一生成标准纯文本通知摘要 (P2-14)
    pub fn format_plain_summary(&self) -> String {
        format!(
            "任务: {}\nIPv4: {}\nIPv6: {}\n域名: {}\n时间: {}",
            self.task_name,
            self.ipv4_str(),
            self.ipv6_str(),
            self.domains_comma_separated(),
            self.time_str()
        )
    }

    /// 生成用于冷却抑制判断的稳定错误指纹 (P2-9)
    ///
    /// # 设计原理
    /// 各云厂商返回的错误消息中往往包含动态的 RequestId、TraceId、时间戳或随机数。
    /// 若直接拿原始错误文本做全值等值比较，会导致抑制机制完全失效。
    /// 本指纹提取域名、记录类型与规范化后的错误摘要，消除动态易变因子。
    pub fn error_fingerprint(&self) -> String {
        let mut lines = Vec::new();
        for r in &self.results {
            if r.status != crate::dns::trait_def::SyncStatus::Created
                && r.status != crate::dns::trait_def::SyncStatus::Updated
                && r.status != crate::dns::trait_def::SyncStatus::Unchanged
            {
                let normalized_msg = normalize_error_for_fingerprint(&r.message);
                lines.push(format!(
                    "[{}] {}: {}",
                    r.record_type, r.domain, normalized_msg
                ));
            }
        }
        if lines.is_empty() {
            normalize_error_for_fingerprint(&self.format_details_text())
        } else {
            lines.join(";")
        }
    }
}

/// 匹配云服务商错误信息中动态可变成分（RequestId、UUID、纯数字时间戳）的正则表达式
static DYNAMIC_ERROR_VAR_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(request_?id|trace_?id|req_?id|timestamp|nonce)\s*[:=]\s*[^,\s;}]+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|\b\d{10,13}\b")
        .expect("静态错误归一化正则表达式语法必定合法")
});

/// 对错误信息中的动态变量执行归一化，剔除请求 ID、时间戳与 UUID (P2-9)
pub fn normalize_error_for_fingerprint(input: &str) -> String {
    DYNAMIC_ERROR_VAR_REGEX
        .replace_all(input, "<VAR>")
        .to_string()
}

/// 统一的通知发送者接口
#[async_trait]
pub trait Notifier: Send + Sync {
    /// 渠道标识名称
    fn channel_name(&self) -> &'static str;

    /// 发送通知
    async fn send(&self, event: &NotificationEvent) -> Result<(), NotifyError>;
}

/// 发送通用 HTTP 请求并统一处理响应状态与提取响应文本
pub async fn execute_notify_request(
    req: reqwest::RequestBuilder,
    channel_name: &str,
) -> Result<String, NotifyError> {
    let resp = req.send().await?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();

    if status.is_success() {
        Ok(body)
    } else {
        Err(NotifyError::Provider(format!(
            "{} 返回错误 [{}]: {}",
            channel_name, status, body
        )))
    }
}

/// 发送 POST JSON 请求并统一处理响应状态与提取响应文本
pub async fn send_json_post(
    client: &reqwest::Client,
    url: &str,
    payload: &serde_json::Value,
    channel_name: &str,
) -> Result<String, NotifyError> {
    execute_notify_request(client.post(url).json(payload), channel_name).await
}

/// 校验国内常见开放平台 (钉钉/企业微信/微信等) 的 JSON errcode 业务响应
pub fn check_errcode_response(body: &str, platform_name: &str) -> Result<(), NotifyError> {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body)
        && let Some(errcode) = v.get("errcode").and_then(|c| c.as_i64())
        && errcode != 0
    {
        let errmsg = v
            .get("errmsg")
            .and_then(|m| m.as_str())
            .unwrap_or("未知错误");
        return Err(NotifyError::Provider(format!(
            "{}业务错误 [code: {}]: {}",
            platform_name, errcode, errmsg
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::trait_def::{DnsRecordType, SyncStatus};

    #[test]
    fn test_domains_comma_separated_dedup() {
        let event = NotificationEvent {
            overall_status: NotificationOverallStatus::Success,
            task_name: "test".to_string(),
            ipv4: None,
            ipv6: None,
            ip_changed: true,
            results: vec![
                SyncRecordResult {
                    domain: "a.example.com".to_string(),
                    record_type: DnsRecordType::A,
                    target_ip: "1.1.1.1".to_string(),
                    status: SyncStatus::Updated,
                    message: "ok".to_string(),
                },
                SyncRecordResult {
                    domain: "b.example.com".to_string(),
                    record_type: DnsRecordType::A,
                    target_ip: "1.1.1.1".to_string(),
                    status: SyncStatus::Updated,
                    message: "ok".to_string(),
                },
                SyncRecordResult {
                    domain: "a.example.com".to_string(),
                    record_type: DnsRecordType::AAAA,
                    target_ip: "::1".to_string(),
                    status: SyncStatus::Updated,
                    message: "ok".to_string(),
                },
            ],
            timestamp: Local::now(),
        };

        // 非连续出现的 a.example.com 应该被正确去重，且保持 a, b 顺序
        assert_eq!(
            event.domains_comma_separated(),
            "a.example.com, b.example.com"
        );
    }

    #[test]
    fn test_notify_error_masks_sensitive_info() {
        let err = NotifyError::Provider("request failed: https://api.telegram.org/bot123456789:ABCdefGHIjklMNOpqrsTUVwxyz123456/sendMessage?pwd=secret_pass&token=secret_tok".to_string());
        let formatted = err.to_string();
        assert!(!formatted.contains("123456789:ABCdefGHIjklMNOpqrsTUVwxyz123456"));
        assert!(!formatted.contains("secret_pass"));
        assert!(!formatted.contains("secret_tok"));
        assert!(formatted.contains("/bot******"));
        assert!(formatted.contains("pwd=******"));
        assert!(formatted.contains("token=******"));
    }

    #[test]
    fn test_error_fingerprint_normalization() {
        let msg1 = "API 请求失败: Code=InvalidSignature, RequestId: 12345678-1234-1234-1234-1234567890ab, timestamp: 1696500000";
        let msg2 = "API 请求失败: Code=InvalidSignature, RequestId: 87654321-4321-4321-4321-ba0987654321, timestamp: 1696500999";

        let norm1 = normalize_error_for_fingerprint(msg1);
        let norm2 = normalize_error_for_fingerprint(msg2);

        assert_eq!(norm1, norm2);

        let event1 = NotificationEvent {
            overall_status: NotificationOverallStatus::Failed,
            task_name: "test_task".to_string(),
            ipv4: None,
            ipv6: None,
            ip_changed: false,
            results: vec![SyncRecordResult {
                domain: "sub.example.com".to_string(),
                record_type: DnsRecordType::A,
                target_ip: "1.1.1.1".to_string(),
                status: SyncStatus::Failed,
                message: msg1.to_string(),
            }],
            timestamp: Local::now(),
        };

        let event2 = NotificationEvent {
            overall_status: NotificationOverallStatus::Failed,
            task_name: "test_task".to_string(),
            ipv4: None,
            ipv6: None,
            ip_changed: false,
            results: vec![SyncRecordResult {
                domain: "sub.example.com".to_string(),
                record_type: DnsRecordType::A,
                target_ip: "1.1.1.1".to_string(),
                status: SyncStatus::Failed,
                message: msg2.to_string(),
            }],
            timestamp: Local::now(),
        };

        assert_eq!(event1.error_fingerprint(), event2.error_fingerprint());
    }
}
