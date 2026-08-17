use crate::config::model::WebhookConfig;
use crate::notifier::trait_def::{NotificationEvent, Notifier, NotifyError};
use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Client, Method};
use std::str::FromStr;
use std::time::Duration;

pub struct CustomWebhookNotifier {
    config: WebhookConfig,
    client: Client,
}

impl CustomWebhookNotifier {
    pub fn new(config: WebhookConfig) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        Self { config, client }
    }

    fn replace_template(template: &str, event: &NotificationEvent) -> String {
        let ipv4_str = event.ipv4.map(|ip| ip.to_string()).unwrap_or_default();
        let ipv6_str = event.ipv6.map(|ip| ip.to_string()).unwrap_or_default();
        let domains_str = event.domains_comma_separated();
        let time_str = event.timestamp.format("%Y-%m-%d %H:%M:%S").to_string();
        let time_unix = event.timestamp.timestamp().to_string();
        let details_str = event.format_details_text();

        template
            .replace("#{status}", event.overall_status.as_str())
            .replace("#{taskName}", &event.task_name)
            .replace("#{ipv4Addr}", &ipv4_str)
            .replace("#{ipv6Addr}", &ipv6_str)
            .replace("#{domains}", &domains_str)
            .replace("#{timestamp}", &time_str)
            .replace("#{timeUnix}", &time_unix)
            .replace("#{details}", &details_str)
    }
}

#[async_trait]
impl Notifier for CustomWebhookNotifier {
    fn channel_name(&self) -> &'static str {
        "通用 Webhook"
    }

    async fn send(&self, event: &NotificationEvent) -> Result<(), NotifyError> {
        let rendered_url = Self::replace_template(&self.config.url, event);
        let http_method = Method::from_str(&self.config.method.to_uppercase())
            .unwrap_or(Method::GET);

        let mut req = self.client.request(http_method, &rendered_url);

        if let Some(ref hdrs) = self.config.headers {
            let mut header_map = HeaderMap::new();
            for (k, v) in hdrs {
                let rendered_v = Self::replace_template(v, event);
                if let (Ok(hk), Ok(hv)) = (HeaderName::from_str(k), HeaderValue::from_str(&rendered_v)) {
                    header_map.insert(hk, hv);
                }
            }
            req = req.headers(header_map);
        }

        if let Some(ref body_tmpl) = self.config.body {
            let rendered_body = Self::replace_template(body_tmpl, event);
            req = req.body(rendered_body);
        }

        let resp = req.send().await?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();

        if status.is_success() {
            tracing::info!("[{}] Webhook 执行成功: {}", self.channel_name(), body);
            Ok(())
        } else {
            Err(NotifyError::Provider(format!("Webhook 返回错误 [{}]: {}", status, body)))
        }
    }
}
