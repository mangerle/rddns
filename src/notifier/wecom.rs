use crate::config::model::{WeComConfig, WeComMode};
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

    /// 构造包含 corp_id 与 corp_secret 摘要的缓存键（避免多应用或更换密钥后命中旧缓存）
    fn token_cache_key(corp_id: &str, corp_secret: &str) -> String {
        let secret_hash = crate::util::crypto::sha256_hex(corp_secret.trim().as_bytes());
        format!("{}:{}", corp_id.trim(), secret_hash)
    }

    /// 判断企业微信响应 JSON 是否表示 access_token 已失效（40001 / 40014 / 42001）
    fn is_token_invalid_response(body: &str) -> bool {
        #[derive(Deserialize)]
        struct ErrCodeOnly {
            #[serde(default)]
            errcode: i64,
        }
        serde_json::from_str::<ErrCodeOnly>(body)
            .is_ok_and(|r| matches!(r.errcode, 40001 | 40014 | 42001))
    }

    /// 对企业微信群机器人 Markdown 动态文本进行安全转义，防止特殊标签或链接注入破坏排版
    fn escape_wecom_markdown(raw: &str) -> String {
        let mut out = String::with_capacity(raw.len());
        for ch in raw.chars() {
            match ch {
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                '[' => out.push_str("\\["),
                ']' => out.push_str("\\]"),
                '`' => out.push_str("\\`"),
                '*' => out.push_str("\\*"),
                _ => out.push(ch),
            }
        }
        out
    }

    /// 获取并缓存企业微信自建应用 access_token (有效生命周期内复用，避免频繁请求触发限流)
    ///
    /// # 设计原理
    /// - **实现初衷**: 避免在 Token 过期瞬间多个并发通知任务同时穿透去请求企业微信 Token 接口，触发 API 限流。
    /// - **核心优势**: 借助 DclTokenCache 双重检查锁安全复用，并以 `corp_id + sha256(corp_secret)` 为键，既隔离多应用又避免明文密钥常驻。
    async fn get_access_token(
        &self,
        corp_id: &str,
        corp_secret: &str,
    ) -> Result<String, NotifyError> {
        let cache_key = Self::token_cache_key(corp_id, corp_secret);
        WECOM_TOKEN_CACHE
            .get_or_fetch(&cache_key, || async {
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
            Self::escape_wecom_markdown(&event.task_name),
            event.ipv4_str(),
            event.ipv6_str(),
            Self::escape_wecom_markdown(&event.domains_comma_separated()),
            event.time_str(),
            Self::escape_wecom_markdown(&event.format_details_text())
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

        let access_token = self.get_access_token(corp_id, corp_secret).await?;
        let send_url = format!(
            "https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token={}",
            access_token
        );
        let mut body = crate::notifier::trait_def::send_json_post(
            &self.client,
            &send_url,
            &payload,
            "企业微信应用消息",
        )
        .await?;

        if Self::is_token_invalid_response(&body) {
            WECOM_TOKEN_CACHE.invalidate(&Self::token_cache_key(corp_id, corp_secret));
            let refreshed_token = self.get_access_token(corp_id, corp_secret).await?;
            let retry_url = format!(
                "https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token={}",
                refreshed_token
            );
            body = crate::notifier::trait_def::send_json_post(
                &self.client,
                &retry_url,
                &payload,
                "企业微信应用消息",
            )
            .await?;
        }

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
        match self.config.mode {
            WeComMode::App => self.send_app(event).await,
            WeComMode::Bot => self.send_bot(event).await,
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

    #[test]
    fn test_wecom_mode_case_insensitivity_and_serialization() {
        // 测试大小写容错反序列化 (P2-10)
        let mode_app: WeComMode = serde_json::from_str("\"App\"").expect("应能解析 App");
        assert_eq!(mode_app, WeComMode::App);

        let mode_app_lower: WeComMode = serde_json::from_str("\"app\"").expect("应能解析 app");
        assert_eq!(mode_app_lower, WeComMode::App);

        let mode_bot: WeComMode = serde_json::from_str("\"Bot\"").expect("应能解析 Bot");
        assert_eq!(mode_bot, WeComMode::Bot);

        let mode_bot_upper: WeComMode = serde_json::from_str("\"BOT\"").expect("应能解析 BOT");
        assert_eq!(mode_bot_upper, WeComMode::Bot);

        // 默认值
        assert_eq!(WeComMode::default(), WeComMode::Bot);

        // 序列化输出全小写标准形式
        assert_eq!(serde_json::to_string(&WeComMode::App).unwrap(), "\"app\"");
        assert_eq!(serde_json::to_string(&WeComMode::Bot).unwrap(), "\"bot\"");

        // 非法模式必须报错拒绝
        let invalid: Result<WeComMode, _> = serde_json::from_str("\"invalid_mode\"");
        assert!(invalid.is_err(), "非法模式应反序列化报错");
    }
}
