use crate::config::model::TelegramConfig;
use crate::notifier::trait_def::{NotificationEvent, Notifier, NotifyError};
use async_trait::async_trait;
use log::info;
use reqwest::Client;
use serde_json::json;
use std::time::Duration;

pub struct TelegramNotifier {
    config: TelegramConfig,
    client: Client,
}

impl TelegramNotifier {
    pub fn new(config: TelegramConfig) -> Self {
        let client = crate::util::http::create_http_client_builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        Self { config, client }
    }
    /// HTML 特殊字符转义
    fn escape_html(input: &str) -> String {
        input
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#x27;")
    }
}

#[async_trait]
impl Notifier for TelegramNotifier {
    fn channel_name(&self) -> &'static str {
        "Telegram Bot"
    }

    async fn send(&self, event: &NotificationEvent) -> Result<(), NotifyError> {
        let base_url = self
            .config
            .api_proxy
            .as_deref()
            .filter(|p| !p.trim().is_empty())
            .unwrap_or("https://api.telegram.org");

        let url = format!(
            "{}/bot{}/sendMessage",
            base_url.trim_end_matches('/'),
            self.config.bot_token.trim()
        );

        let text = format!(
            "<b>rddns 域名解析通知</b> [{status}]\n\
            <b>任务</b>: {task_name}\n\
            <b>IPv4</b>: <code>{ipv4}</code>\n\
            <b>IPv6</b>: <code>{ipv6}</code>\n\
            <b>域名</b>: {domains}\n\
            <b>时间</b>: {timestamp}\n\n\
            <b>详情</b>:\n{details}",
            status = event.overall_status.as_str(),
            task_name = Self::escape_html(&event.task_name),
            ipv4 = event
                .ipv4
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "无".to_string()),
            ipv6 = event
                .ipv6
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "无".to_string()),
            domains = Self::escape_html(&event.domains_comma_separated()),
            timestamp = event.timestamp.format("%Y-%m-%d %H:%M:%S"),
            details = Self::escape_html(&event.format_details_text())
        );

        let payload = json!({
            "chat_id": self.config.chat_id,
            "text": text,
            "parse_mode": "HTML"
        });

        let resp = self.client.post(&url).json(&payload).send().await?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();

        if status.is_success() {
            info!("[{}] 消息发送成功", self.channel_name());
            Ok(())
        } else {
            Err(NotifyError::Provider(format!(
                "Telegram 返回错误 [{}]: {}",
                status, body
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::trait_def::{DnsRecordType, SyncRecordResult, SyncStatus};
    use crate::notifier::trait_def::NotificationOverallStatus;
    use chrono::Local;

    #[test]
    fn test_telegram_html_escape() {
        let result = SyncRecordResult {
            domain: "my_domain.com".to_string(),
            record_type: DnsRecordType::A,
            target_ip: "1.1.1.1".to_string(),
            status: SyncStatus::Failed,
            message: "错误: <API Error> & [400]".to_string(),
        };

        let event = NotificationEvent {
            overall_status: NotificationOverallStatus::Failed,
            task_name: "home_nas_task <v1>".to_string(),
            ipv4: None,
            ipv6: None,
            ip_changed: false,
            results: vec![result],
            timestamp: Local::now(),
        };

        let escaped_task = TelegramNotifier::escape_html(&event.task_name);
        assert_eq!(escaped_task, "home_nas_task &lt;v1&gt;");

        let escaped_details = TelegramNotifier::escape_html(&event.format_details_text());
        assert!(escaped_details.contains("&lt;API Error&gt; &amp; [400]"));
    }
}
