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
        let client = crate::util::http::create_http_client_builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        Self { config, client }
    }

    fn replace_template(template: &str, event: &NotificationEvent, url_encode: bool) -> String {
        let ipv4_str = event.ipv4.map(|ip| ip.to_string()).unwrap_or_default();
        let ipv6_str = event.ipv6.map(|ip| ip.to_string()).unwrap_or_default();
        let domains_str = event.domains_comma_separated();
        let time_str = event.timestamp.format("%Y-%m-%d %H:%M:%S").to_string();
        let time_unix = event.timestamp.timestamp().to_string();
        let details_str = event.format_details_text();

        let encode_fn = |s: &str| -> String {
            if url_encode {
                url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
            } else {
                s.to_string()
            }
        };

        template
            .replace("#{status}", &encode_fn(event.overall_status.as_str()))
            .replace("#{taskName}", &encode_fn(&event.task_name))
            .replace("#{ipv4Addr}", &encode_fn(&ipv4_str))
            .replace("#{ipv6Addr}", &encode_fn(&ipv6_str))
            .replace("#{domains}", &encode_fn(&domains_str))
            .replace("#{timestamp}", &encode_fn(&time_str))
            .replace("#{timeUnix}", &encode_fn(&time_unix))
            .replace("#{details}", &encode_fn(&details_str))
    }
}

#[async_trait]
impl Notifier for CustomWebhookNotifier {
    fn channel_name(&self) -> &'static str {
        "通用 Webhook"
    }

    async fn send(&self, event: &NotificationEvent) -> Result<(), NotifyError> {
        let rendered_url = Self::replace_template(&self.config.url, event, true);
        let http_method =
            Method::from_str(&self.config.method.to_uppercase()).unwrap_or(Method::GET);

        let mut req = self.client.request(http_method, &rendered_url);

        if let Some(ref hdrs) = self.config.headers {
            let mut header_map = HeaderMap::new();
            for (k, v) in hdrs {
                let rendered_v = Self::replace_template(v, event, false);
                match (HeaderName::from_str(k), HeaderValue::from_str(&rendered_v)) {
                    (Ok(hk), Ok(hv)) => {
                        header_map.insert(hk, hv);
                    }
                    _ => {
                        tracing::warn!(
                            "⚠️ Webhook 自定义 Header [{}: {}] 格式不合法，已跳过",
                            k,
                            rendered_v
                        );
                    }
                }
            }
            req = req.headers(header_map);
        }

        if let Some(ref body_tmpl) = self.config.body {
            let rendered_body = Self::replace_template(body_tmpl, event, false);
            req = req.body(rendered_body);
        }

        let resp = req.send().await?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();

        if status.is_success() {
            tracing::info!("[{}] Webhook 执行成功: {}", self.channel_name(), body);
            Ok(())
        } else {
            Err(NotifyError::Provider(format!(
                "Webhook 返回错误 [{}]: {}",
                status, body
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notifier::trait_def::NotificationOverallStatus;
    use chrono::Local;
    use std::net::Ipv4Addr;

    #[test]
    fn test_webhook_url_encoding() {
        let event = NotificationEvent {
            title: "DDNS 同步状态通知".to_string(),
            task_name: "家庭网络".to_string(),
            overall_status: NotificationOverallStatus::Success,
            ip_changed: true,
            ipv4: Some(Ipv4Addr::new(1, 2, 3, 4)),
            ipv6: None,
            results: vec![],
            timestamp: Local::now(),
        };

        // URL 模式下应自动进行 URL Encode 转义
        let url_tmpl = "https://push.example.com/send?title=#{taskName}&desp=#{details}";
        let rendered_url = CustomWebhookNotifier::replace_template(url_tmpl, &event, true);
        assert!(!rendered_url.contains(' '));
        assert!(!rendered_url.contains("家庭网络")); // 应该被编码为 %E5%AE%B6%E5%BA%AD...
        assert!(rendered_url.contains("%E5%AE%B6%E5%BA%AD%E7%BD%91%E7%BB%9C"));

        // Body 模式下应保持原始字符不变
        let body_tmpl = "{\"msg\": \"#{taskName}\"}";
        let rendered_body = CustomWebhookNotifier::replace_template(body_tmpl, &event, false);
        assert!(rendered_body.contains("家庭网络"));
    }
}
