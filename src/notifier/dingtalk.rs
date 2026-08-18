use crate::config::model::DingTalkConfig;
use crate::notifier::trait_def::{NotificationEvent, Notifier, NotifyError};
use crate::util::crypto::hmac_sha256;
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chrono::Utc;
use reqwest::Client;
use serde_json::json;
use std::time::Duration;
use url::form_urlencoded;

pub struct DingTalkNotifier {
    config: DingTalkConfig,
    client: Client,
}

impl DingTalkNotifier {
    pub fn new(config: DingTalkConfig) -> Self {
        let client = crate::util::http::create_http_client_builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();
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
        let text = format!(
            "### 🔔 rddns 动态解析通知\n\
            - **状态**：{}\n\
            - **任务**：{}\n\
            - **IPv4**：{}\n\
            - **IPv6**：{}\n\
            - **域名**：{}\n\
            - **时间**：{}\n\n\
            #### 同步结果：\n{}",
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
            "msgtype": "markdown",
            "markdown": {
                "title": title,
                "text": text
            }
        });

        let resp = self.client.post(&url).json(&payload).send().await?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();

        if status.is_success() {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body)
                && let Some(errcode) = v.get("errcode").and_then(|c| c.as_i64())
                && errcode != 0
            {
                let errmsg = v
                    .get("errmsg")
                    .and_then(|m| m.as_str())
                    .unwrap_or("未知错误");
                return Err(NotifyError::Provider(format!(
                    "钉钉接口业务错误 [code: {}]: {}",
                    errcode, errmsg
                )));
            }
            tracing::info!("[{}] 钉钉消息发送成功", self.channel_name());
            Ok(())
        } else {
            Err(NotifyError::Provider(format!(
                "钉钉返回错误 [{}]: {}",
                status, body
            )))
        }
    }
}
