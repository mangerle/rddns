use crate::config::model::DingTalkConfig;
use crate::notifier::trait_def::{NotificationEvent, Notifier, NotifyError};
use crate::util::crypto::hmac_sha256;
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chrono::Utc;
use log::info;
use reqwest::Client;
use serde_json::json;
use url::form_urlencoded;

pub struct DingTalkNotifier {
    config: DingTalkConfig,
    client: Client,
}

impl DingTalkNotifier {
    pub fn new(config: DingTalkConfig) -> Self {
        let client = crate::util::http::create_notifier_client();
        Self { config, client }
    }
}

#[async_trait]
impl Notifier for DingTalkNotifier {
    fn channel_name(&self) -> &'static str {
        "钉钉机器人"
    }

    async fn send(&self, event: &NotificationEvent) -> Result<(), NotifyError> {
        let token = self.config.access_token.trim();
        let mut url = format!(
            "https://oapi.dingtalk.com/robot/send?access_token={}",
            token
        );

        if let Some(ref secret) = self.config.secret
            && !secret.trim().is_empty()
        {
            let timestamp = Utc::now().timestamp_millis();
            let string_to_sign = format!("{}\n{}", timestamp, secret.trim());
            let sign_bytes = hmac_sha256(secret.trim().as_bytes(), string_to_sign.as_bytes());
            let sign_base64 = BASE64_STANDARD.encode(sign_bytes);
            let sign_encoded: String =
                form_urlencoded::byte_serialize(sign_base64.as_bytes()).collect();

            url.push_str(&format!("&timestamp={}&sign={}", timestamp, sign_encoded));
        }

        let title = format!("rddns 动态解析 [{}]", event.overall_status.as_str());
        let text = event.format_markdown_summary();

        let payload = json!({
            "msgtype": "markdown",
            "markdown": {
                "title": title,
                "text": text
            }
        });

        let body = crate::notifier::trait_def::send_json_post(
            &self.client,
            &url,
            &payload,
            self.channel_name(),
        )
        .await?;

        crate::notifier::trait_def::check_errcode_response(&body, "钉钉接口")?;
        info!("[{}] 钉钉消息发送成功", self.channel_name());
        Ok(())
    }
}
