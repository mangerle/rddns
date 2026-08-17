use crate::config::model::BarkConfig;
use crate::notifier::trait_def::{NotificationEvent, Notifier, NotifyError};
use async_trait::async_trait;
use reqwest::Client;
use serde_json::json;
use std::time::Duration;

pub struct BarkNotifier {
    config: BarkConfig,
    client: Client,
}

impl BarkNotifier {
    pub fn new(config: BarkConfig) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        Self { config, client }
    }
}

#[async_trait]
impl Notifier for BarkNotifier {
    fn channel_name(&self) -> &'static str {
        "Bark (iOS)"
    }

    async fn send(&self, event: &NotificationEvent) -> Result<(), NotifyError> {
        let server = self.config.server_url.trim().trim_end_matches('/');
        let key = self.config.device_key.trim();
        let url = format!("{}/push", server);

        let title = format!("🔔 rddns 动态解析 [{}]", event.overall_status.as_str());
        let body = format!(
            "任务: {}\nIPv4: {}\nIPv6: {}\n域名: {}\n时间: {}",
            event.task_name,
            event.ipv4.map(|ip| ip.to_string()).unwrap_or_else(|| "无".to_string()),
            event.ipv6.map(|ip| ip.to_string()).unwrap_or_else(|| "无".to_string()),
            event.domains_comma_separated(),
            event.timestamp.format("%Y-%m-%d %H:%M:%S")
        );

        let mut payload = json!({
            "device_key": key,
            "title": title,
            "body": body,
        });

        if let Some(ref group) = self.config.group {
            payload["group"] = json!(group);
        }
        if let Some(ref sound) = self.config.sound {
            payload["sound"] = json!(sound);
        }

        let resp = self.client.post(&url).json(&payload).send().await?;
        let status = resp.status();
        let resp_body = resp.text().await.unwrap_or_default();

        if status.is_success() {
            tracing::info!("[{}] Bark 消息推送成功", self.channel_name());
            Ok(())
        } else {
            Err(NotifyError::Provider(format!("Bark 返回错误 [{}]: {}", status, resp_body)))
        }
    }
}
