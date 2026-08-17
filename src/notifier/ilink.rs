use crate::config::model::ILinkConfig;
use crate::notifier::trait_def::{NotificationEvent, Notifier, NotifyError};
use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::Client;
use serde_json::json;
use std::time::Duration;

/// 微信官方 iLink Bot 适配器
pub struct ILinkNotifier {
    config: ILinkConfig,
    client: Client,
}

impl ILinkNotifier {
    pub fn new(config: ILinkConfig) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        Self { config, client }
    }
}

#[async_trait]
impl Notifier for ILinkNotifier {
    fn channel_name(&self) -> &'static str {
        "微信官方 iLink"
    }

    async fn send(&self, event: &NotificationEvent) -> Result<(), NotifyError> {
        let content = format!(
            "【rddns 动态解析通知】{}\n任务: {}\nIPv4: {}\nIPv6: {}\n涉及域名: {}\n时间: {}\n\n详情:\n{}",
            event.overall_status.as_str(),
            event.task_name,
            event.ipv4.map(|ip| ip.to_string()).unwrap_or_else(|| "未配置/无".to_string()),
            event.ipv6.map(|ip| ip.to_string()).unwrap_or_else(|| "未配置/无".to_string()),
            event.domains_comma_separated(),
            event.timestamp.format("%Y-%m-%d %H:%M:%S"),
            event.format_details_text()
        );

        let payload = json!({
            "to_user": self.config.to_user_id,
            "msgtype": "text",
            "text": {
                "content": content
            }
        });

        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        );
        if let Ok(auth) = HeaderValue::from_str(&format!("Bearer {}", self.config.bot_token.trim())) {
            headers.insert(AUTHORIZATION, auth);
        }

        let resp = self
            .client
            .post(&self.config.endpoint)
            .headers(headers)
            .json(&payload)
            .send()
            .await?;

        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();

        if status.is_success() {
            tracing::info!("[{}] 通知发送成功: {}", self.channel_name(), body);
            Ok(())
        } else {
            tracing::warn!("[{}] 通知发送失败 [{}]: {}", self.channel_name(), status, body);
            Err(NotifyError::Provider(format!("iLink API 错误 [{}]: {}", status, body)))
        }
    }
}
