use crate::config::model::BarkConfig;
use crate::notifier::trait_def::{NotificationEvent, Notifier, NotifyError};
use async_trait::async_trait;
use log::info;
use reqwest::Client;
use serde_json::json;

pub struct BarkNotifier {
    config: BarkConfig,
    client: Client,
}

impl BarkNotifier {
    pub fn new(config: BarkConfig) -> Self {
        let client = crate::util::http::create_notifier_client();
        Self { config, client }
    }
}

#[async_trait]
impl Notifier for BarkNotifier {
    fn channel_name(&self) -> &'static str {
        "Bark (iOS)"
    }

    async fn send(&self, event: &NotificationEvent) -> Result<(), NotifyError> {
        let server = if self.config.server_url.trim().is_empty() {
            "https://api.day.app"
        } else {
            self.config.server_url.trim().trim_end_matches('/')
        };
        let key = self.config.device_key.trim();
        let url = format!("{}/push", server);

        let title = format!("rddns 动态解析 [{}]", event.overall_status.as_str());
        let body = event.format_plain_summary();

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

        let resp_body = crate::notifier::trait_def::send_json_post(
            &self.client,
            &url,
            &payload,
            self.channel_name(),
        )
        .await?;

        #[derive(serde::Deserialize)]
        struct BarkResponse {
            code: Option<i64>,
            message: Option<String>,
        }

        if let Ok(parsed) = serde_json::from_str::<BarkResponse>(&resp_body)
            && let Some(code) = parsed.code
            && code != 200
        {
            let msg = parsed.message.unwrap_or(resp_body);
            return Err(NotifyError::Provider(format!(
                "Bark 推送返回业务错误 [{}]: {}",
                code, msg
            )));
        }

        info!("[{}] Bark 消息推送成功", self.channel_name());
        Ok(())
    }
}
