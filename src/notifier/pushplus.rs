use crate::config::model::PushPlusConfig;
use crate::notifier::trait_def::{NotificationEvent, Notifier, NotifyError};
use async_trait::async_trait;
use reqwest::Client;
use serde_json::json;
use std::time::Duration;

pub struct PushPlusNotifier {
    config: PushPlusConfig,
    client: Client,
}

impl PushPlusNotifier {
    pub fn new(config: PushPlusConfig) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        Self { config, client }
    }
}

#[async_trait]
impl Notifier for PushPlusNotifier {
    fn channel_name(&self) -> &'static str {
        "PushPlus (推送加)"
    }

    async fn send(&self, event: &NotificationEvent) -> Result<(), NotifyError> {
        let title = format!("🔔 rddns 动态解析 [{}]", event.overall_status.as_str());
        let content = format!(
            "### 🔔 rddns 动态解析通知\n\
            - **状态**：{}\n\
            - **任务**：{}\n\
            - **IPv4**：{}\n\
            - **IPv6**：{}\n\
            - **域名**：{}\n\
            - **时间**：{}\n\n\
            #### 同步明细：\n{}",
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

        let mut payload = json!({
            "token": self.config.token,
            "title": title,
            "content": content,
            "template": self.config.template.as_deref().unwrap_or("markdown")
        });

        if let Some(ref ch) = self.config.channel {
            payload["channel"] = json!(ch);
        }

        let resp = self
            .client
            .post("https://www.pushplus.plus/send")
            .json(&payload)
            .send()
            .await?;

        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();

        if status.is_success() {
            tracing::info!("[{}] 微信推送成功: {}", self.channel_name(), body);
            Ok(())
        } else {
            Err(NotifyError::Provider(format!(
                "PushPlus 返回错误 [{}]: {}",
                status, body
            )))
        }
    }
}
