use crate::config::model::WeComConfig;
use crate::notifier::trait_def::{NotificationEvent, Notifier, NotifyError};
use async_trait::async_trait;
use log::info;
use parking_lot::RwLock;
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

pub struct WeComNotifier {
    config: WeComConfig,
    client: Client,
}

#[derive(Debug, Clone)]
struct WeComTokenCacheEntry {
    access_token: String,
    expires_at: Instant,
}

static WECOM_TOKEN_CACHE: LazyLock<RwLock<HashMap<String, WeComTokenCacheEntry>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

impl WeComNotifier {
    pub fn new(config: WeComConfig) -> Self {
        let client = crate::util::http::create_notifier_client();
        Self { config, client }
    }

    /// 获取并缓存企业微信自建应用 access_token (有效生命周期内复用，避免频繁请求触发限流)
    async fn get_access_token(
        &self,
        corp_id: &str,
        corp_secret: &str,
    ) -> Result<String, NotifyError> {
        let cache_key = format!("{}:{}", corp_id, corp_secret);

        // 1. 检查有效缓存
        if let Some(entry) = WECOM_TOKEN_CACHE.read().get(&cache_key)
            && entry.expires_at > Instant::now()
        {
            return Ok(entry.access_token.clone());
        }

        // 2. 缓存未命中或已过期，向企业微信官方服务器获取
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

        // 默认 7200 秒有效，提前 300 秒缓冲刷新
        let expires_in_secs = token_data
            .expires_in
            .unwrap_or(7200)
            .saturating_sub(300)
            .max(60);
        let expires_at = Instant::now() + Duration::from_secs(expires_in_secs);

        WECOM_TOKEN_CACHE.write().insert(
            cache_key,
            WeComTokenCacheEntry {
                access_token: access_token.clone(),
                expires_at,
            },
        );

        Ok(access_token)
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

        // 1. 获取 access_token (优先从内存缓存获取)
        let access_token = self.get_access_token(corp_id, corp_secret).await?;

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
    expires_in: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wecom_token_cache_insertion_and_expiry() {
        let key = "test_corp:test_secret".to_string();
        let token = "token_abc_123".to_string();
        let expires_at = Instant::now() + Duration::from_secs(3600);

        WECOM_TOKEN_CACHE.write().insert(
            key.clone(),
            WeComTokenCacheEntry {
                access_token: token.clone(),
                expires_at,
            },
        );

        let cached = WECOM_TOKEN_CACHE.read().get(&key).cloned();
        assert!(cached.is_some());
        let entry = cached.unwrap();
        assert_eq!(entry.access_token, token);
        assert!(entry.expires_at > Instant::now());
    }
}
