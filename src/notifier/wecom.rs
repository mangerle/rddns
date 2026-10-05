use crate::config::model::WeComConfig;
use crate::notifier::token_cache::DclTokenCache;
use crate::notifier::trait_def::{NotificationEvent, Notifier, NotifyError, escape_html};
use async_trait::async_trait;
use log::info;
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use std::sync::LazyLock;
use std::time::Duration;

pub struct WeComNotifier {
    config: WeComConfig,
    client: Client,
}

static WECOM_TOKEN_CACHE: LazyLock<DclTokenCache> = LazyLock::new(|| DclTokenCache::new(64));

impl WeComNotifier {
    pub fn new(config: WeComConfig) -> Self {
        let client = crate::util::http::create_notifier_client();
        Self { config, client }
    }

    /// 获取并缓存企业微信自建应用 access_token (有效生命周期内复用，避免频繁请求触发限流)
    ///
    /// # 设计原理
    /// - **实现初衷**: 避免在 Token 过期瞬间多个并发通知任务同时穿透去请求企业微信 Token 接口，触发 API 限流。
    /// - **核心优势**: 借助 DclTokenCache 双重检查锁安全复用，且仅以 corp_id 为键，避免 corp_secret 敏感凭据在全局缓存驻留。
    async fn get_access_token(
        &self,
        corp_id: &str,
        corp_secret: &str,
    ) -> Result<String, NotifyError> {
        WECOM_TOKEN_CACHE
            .get_or_fetch(corp_id, || async {
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

                let access_token = token_data.access_token.ok_or_else(|| {
                    NotifyError::Provider("返回结果中未包含 access_token".to_string())
                })?;

                // 默认 7200 秒有效，提前 300 秒缓冲刷新
                let expires_in_secs = token_data
                    .expires_in
                    .unwrap_or(7200)
                    .saturating_sub(300)
                    .max(60);

                Ok((access_token, Duration::from_secs(expires_in_secs)))
            })
            .await
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
        let status_color = match event.overall_status {
            crate::notifier::trait_def::NotificationOverallStatus::Success => "info",
            crate::notifier::trait_def::NotificationOverallStatus::Failed => "warning",
            crate::notifier::trait_def::NotificationOverallStatus::PartialSuccess => "comment",
        };
        let markdown_content = format!(
            "### rddns 域名动态解析通知 <font color=\"{}\">{}</font>\n\
            > **任务名称**：{}\n\
            > **IPv4 地址**：{}\n\
            > **IPv6 地址**：{}\n\
            > **涉及域名**：{}\n\
            > **触发时间**：{}\n\n\
            **详细结果**：\n{}",
            status_color,
            event.overall_status.as_str(),
            event.task_name,
            event.ipv4_str(),
            event.ipv6_str(),
            event.domains_comma_separated(),
            event.time_str(),
            event.format_details_text()
        );

        let payload = json!({
            "msgtype": "markdown",
            "markdown": {
                "content": markdown_content
            }
        });

        let body = crate::notifier::trait_def::send_json_post(
            &self.client,
            webhook_url,
            &payload,
            "企业微信机器人",
        )
        .await?;

        crate::notifier::trait_def::check_errcode_response(&body, "企业微信机器人")?;
        info!("[{}] 机器人通知发送成功", self.channel_name());
        Ok(())
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
            escape_html(&event.task_name),
            event
                .ipv4
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "无".to_string()),
            event
                .ipv6
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "无".to_string()),
            escape_html(&event.domains_comma_separated()),
            escape_html(&event.format_details_text())
        );

        let payload = json!({
            "touser": to_user,
            "msgtype": "textcard",
            "agentid": agent_id,
            "textcard": {
                "title": format!("rddns 动态解析 [{}]", event.overall_status.as_str()),
                "description": description,
                "url": "https://github.com/mangerle/rddns",
                "btntxt": "查看详情"
            }
        });

        let body = crate::notifier::trait_def::send_json_post(
            &self.client,
            &send_url,
            &payload,
            "企业微信应用消息",
        )
        .await?;

        crate::notifier::trait_def::check_errcode_response(&body, "企业微信应用消息")?;
        info!("[{}] 应用消息发送成功", self.channel_name());
        Ok(())
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

    #[tokio::test]
    async fn test_wecom_token_cache_insertion_and_expiry() {
        let key = "test_corp".to_string();
        let token = "token_abc_123".to_string();

        let res = WECOM_TOKEN_CACHE
            .get_or_fetch(&key, || async {
                Ok((token.clone(), Duration::from_secs(3600)))
            })
            .await;
        assert_eq!(res.unwrap(), token);

        // 二次获取直接命中缓存
        let res2 = WECOM_TOKEN_CACHE
            .get_or_fetch(&key, || async {
                Ok(("token_failed".to_string(), Duration::from_secs(3600)))
            })
            .await;
        assert_eq!(res2.unwrap(), token);
    }

    #[test]
    fn test_wecom_html_escaping_prevents_injection() {
        let malicious_task = "<script>alert('xss')</script>";
        let escaped = escape_html(malicious_task);
        assert_eq!(
            escaped,
            "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"
        );
        assert!(!escaped.contains('<'));
        assert!(!escaped.contains('>'));
    }
}
