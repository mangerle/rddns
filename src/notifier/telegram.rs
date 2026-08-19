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
            "🔔 *rddns 域名解析通知* [{}]\n\
            *任务*: {}\n\
            *IPv4*: `{}`\n\
            *IPv6*: `{}`\n\
            *域名*: {}\n\
            *时间*: {}\n\n\
            *详情*:\n{}",
            event.overall_status.as_str(),
            event.task_name,
            event
                .ipv4
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "无".to_string()),
            event
                .ipv6
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "无".to_string()),
            event.domains_comma_separated(),
            event.timestamp.format("%Y-%m-%d %H:%M:%S"),
            event.format_details_text()
        );

        let payload = json!({
            "chat_id": self.config.chat_id,
            "text": text,
            "parse_mode": "Markdown"
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
