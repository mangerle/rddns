use crate::config::model::FeishuConfig;
use crate::notifier::trait_def::{NotificationEvent, Notifier, NotifyError};
use crate::util::crypto::hmac_sha256;
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chrono::Utc;
use reqwest::Client;
use serde_json::json;
use std::time::Duration;

pub struct FeishuNotifier {
    config: FeishuConfig,
    client: Client,
}

impl FeishuNotifier {
    pub fn new(config: FeishuConfig) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        Self { config, client }
    }
}

#[async_trait]
impl Notifier for FeishuNotifier {
    fn channel_name(&self) -> &'static str {
        "飞书机器人"
    }

    async fn send(&self, event: &NotificationEvent) -> Result<(), NotifyError> {
        let title = format!("🔔 rddns 动态解析 [{}]", event.overall_status.as_str());
        let text = format!(
            "任务名称：{}\nIPv4 地址：{}\nIPv6 地址：{}\n涉及域名：{}\n触发时间：{}\n\n明细：\n{}",
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
            "msg_type": "post",
            "content": {
                "post": {
                    "zh_cn": {
                        "title": title,
                        "content": [
                            [
                                {
                                    "tag": "text",
                                    "text": text
                                }
                            ]
                        ]
                    }
                }
            }
        });

        if let Some(ref secret) = self.config.secret
            && !secret.trim().is_empty()
        {
            let timestamp = Utc::now().timestamp();
            let string_to_sign = format!("{}\n{}", timestamp, secret.trim());
            let sign_bytes = hmac_sha256(string_to_sign.as_bytes(), b"");
            let sign_base64 = BASE64_STANDARD.encode(sign_bytes);

            payload["timestamp"] = json!(timestamp.to_string());
            payload["sign"] = json!(sign_base64);
        }

        let resp = self
            .client
            .post(&self.config.webhook_url)
            .json(&payload)
            .send()
            .await?;

        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();

        if status.is_success() {
            tracing::info!("[{}] 飞书消息发送成功", self.channel_name());
            Ok(())
        } else {
            Err(NotifyError::Provider(format!(
                "飞书返回错误 [{}]: {}",
                status, body
            )))
        }
    }
}
