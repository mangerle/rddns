use crate::config::model::WeComConfig;
use crate::notifier::trait_def::{NotificationEvent, Notifier, NotifyError};
use async_trait::async_trait;
use log::info;
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;

pub struct WeComNotifier {
    config: WeComConfig,
    client: Client,
}

impl WeComNotifier {
    pub fn new(config: WeComConfig) -> Self {
        let client = crate::util::http::create_http_client_builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        Self { config, client }
    }

    async fn send_bot(&self, event: &NotificationEvent) -> Result<(), NotifyError> {
        let webhook_url = self
            .config
            .webhook_url
            .as_ref()
            .filter(|u| !u.trim().is_empty())
            .ok_or_else(|| {
                NotifyError::Provider("企业微信群机器人模式未配置 webhook_url".to_string())
            })?;

        // 拼接 Markdown 内容
        let markdown_content = format!(
            "### rddns 域名动态解析通知 <font color=\"{}\">{}</font>\n\
            > **任务名称**：{}\n\
            > **IPv4 地址**：{}\n\
            > **IPv6 地址**：{}\n\
            > **涉及域名**：{}\n\
            > **触发时间**：{}\n\n\
            **详细结果**：\n{}",
            match event.overall_status {
                crate::notifier::trait_def::NotificationOverallStatus::Success => "info",
                crate::notifier::trait_def::NotificationOverallStatus::Failed => "warning",
                crate::notifier::trait_def::NotificationOverallStatus::PartialSuccess => "comment",
            },
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
                "content": markdown_content
            }
        });

        let resp = self.client.post(webhook_url).json(&payload).send().await?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();

        if status.is_success() {
            crate::notifier::trait_def::check_errcode_response(&body, "企业微信机器人")?;
            info!("[{}] 机器人通知发送成功", self.channel_name());
            Ok(())
        } else {
            Err(NotifyError::Provider(format!(
                "企业微信机器人返回错误 [{}]: {}",
                status, body
            )))
        }
    }

    async fn send_app(&self, event: &NotificationEvent) -> Result<(), NotifyError> {
        let corp_id = self
            .config
            .corp_id
            .as_ref()
            .ok_or_else(|| NotifyError::Provider("企业微信自建应用缺少 corp_id".to_string()))?;
        let corp_secret =
            self.config.corp_secret.as_ref().ok_or_else(|| {
                NotifyError::Provider("企业微信自建应用缺少 corp_secret".to_string())
            })?;
        let agent_id = self
            .config
            .agent_id
            .ok_or_else(|| NotifyError::Provider("企业微信自建应用缺少 agent_id".to_string()))?;
        let to_user = self.config.to_user.as_deref().unwrap_or("@all");

        // 1. 获取 access_token
        let token_url = format!(
            "https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid={}&corpsecret={}",
            corp_id, corp_secret
        );
        let token_resp = self.client.get(&token_url).send().await?;
        let token_data: WeComTokenResponse = token_resp.json().await?;

        if token_data.errcode != 0 {
            return Err(NotifyError::Provider(format!(
                "获取企业微信 access_token 失败 [{}]: {}",
                token_data.errcode, token_data.errmsg
            )));
        }

        let access_token = token_data
            .access_token
            .ok_or_else(|| NotifyError::Provider("返回结果中未包含 access_token".to_string()))?;

        // 2. 发送应用消息 (文本卡片)
        let send_url = format!(
            "https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token={}",
            access_token
        );

        let description = format!(
            "<div class=\"gray\">{}</div><div class=\"normal\">任务：{}</div><div class=\"normal\">IPv4：{}</div><div class=\"normal\">IPv6：{}</div><div class=\"normal\">域名：{}</div>\n\n{}",
            event.timestamp.format("%Y-%m-%d %H:%M:%S"),
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
            event.format_details_text()
        );

        let payload = json!({
            "touser": to_user,
            "msgtype": "textcard",
            "agentid": agent_id,
            "textcard": {
                "title": format!("rddns 动态解析 [{}]", event.overall_status.as_str()),
                "description": description,
                "url": "http://127.0.0.1:9876",
                "btntxt": "查看详情"
            }
        });

        let resp = self.client.post(&send_url).json(&payload).send().await?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();

        if status.is_success() {
            crate::notifier::trait_def::check_errcode_response(&body, "企业微信应用消息")?;
            info!("[{}] 应用消息发送成功", self.channel_name());
            Ok(())
        } else {
            Err(NotifyError::Provider(format!(
                "企业微信应用消息返回错误 [{}]: {}",
                status, body
            )))
        }
    }
}

#[async_trait]
impl Notifier for WeComNotifier {
    fn channel_name(&self) -> &'static str {
        "企业微信 (WeCom)"
    }

    async fn send(&self, event: &NotificationEvent) -> Result<(), NotifyError> {
        if self.config.mode == "app" {
            self.send_app(event).await
        } else {
            self.send_bot(event).await
        }
    }
}

#[derive(Debug, Deserialize)]
struct WeComTokenResponse {
    errcode: i64,
    errmsg: String,
    access_token: Option<String>,
}
