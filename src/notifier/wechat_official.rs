use crate::config::model::WechatOfficialConfig;
use crate::notifier::trait_def::{NotificationEvent, Notifier, NotifyError};
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;

/// 微信 Access Token 响应实体
#[derive(Debug, Deserialize)]
struct WechatTokenResponse {
    pub access_token: Option<String>,
    pub errcode: Option<i64>,
    pub errmsg: Option<String>,
}

/// 微信模板消息发送响应实体
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct WechatSendResponse {
    pub errcode: i64,
    pub errmsg: String,
    pub msgid: Option<i64>,
}

/// 微信公众号原生模板消息适配器
pub struct WechatOfficialNotifier {
    config: WechatOfficialConfig,
    client: Client,
}

impl WechatOfficialNotifier {
    pub fn new(config: WechatOfficialConfig) -> Self {
        let client = crate::util::http::create_http_client_builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        Self { config, client }
    }

    /// 获取公众号全局接口调用凭证 access_token
    async fn fetch_access_token(&self) -> Result<String, NotifyError> {
        let url = format!(
            "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid={}&secret={}",
            self.config.app_id.trim(),
            self.config.app_secret.trim()
        );

        let resp = self.client.get(&url).send().await?;
        let token_resp: WechatTokenResponse = resp.json().await?;

        if let Some(token) = token_resp.access_token
            && !token.is_empty()
        {
            return Ok(token);
        }

        let err_code = token_resp.errcode.unwrap_or(-1);
        let err_msg = token_resp
            .errmsg
            .unwrap_or_else(|| "未知凭证错误".to_string());
        Err(NotifyError::Provider(format!(
            "微信公众号获取 AccessToken 失败 [{}]: {}",
            err_code, err_msg
        )))
    }

    /// 构建模板消息 data 字典
    fn build_template_data(&self, event: &NotificationEvent) -> serde_json::Value {
        let ipv4_str = event
            .ipv4
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "未配置/无".to_string());
        let ipv6_str = event
            .ipv6
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "未配置/无".to_string());
        let time_str = event.timestamp.format("%Y-%m-%d %H:%M:%S").to_string();
        let status_str = event.overall_status.as_str();
        let domains_str = event.domains_comma_separated();
        let details_str = event.format_details_text();

        if let Some(ref custom_tmpl) = self.config.template_data
            && !custom_tmpl.trim().is_empty()
        {
            let replaced = custom_tmpl
                .replace("#{status}", status_str)
                .replace("#{taskName}", &event.task_name)
                .replace("#{ipv4Addr}", &ipv4_str)
                .replace("#{ipv6Addr}", &ipv6_str)
                .replace("#{domains}", &domains_str)
                .replace("#{timestamp}", &time_str)
                .replace("#{details}", &details_str);

            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&replaced) {
                return val;
            }
        }

        // 默认标准通用模板结构（多别名全覆盖，无论微信后台使用 keyword/thing/命名变量 均能自动渲染）
        let ip_combined = if event.ipv4.is_some() && event.ipv6.is_some() {
            format!("IPv4: {} | IPv6: {}", ipv4_str, ipv6_str)
        } else if event.ipv4.is_some() {
            ipv4_str.clone()
        } else if event.ipv6.is_some() {
            ipv6_str.clone()
        } else {
            "未探测到有效IP".to_string()
        };

        json!({
            // 经典模板变量
            "first": { "value": format!("【rddns 动态解析通知】{}", status_str), "color": "#173177" },
            "keyword1": { "value": &event.task_name, "color": "#173177" },
            "keyword2": { "value": &ip_combined, "color": "#173177" },
            "keyword3": { "value": &domains_str, "color": "#173177" },
            "keyword4": { "value": &time_str, "color": "#173177" },
            "keyword5": { "value": &status_str, "color": "#173177" },
            "remark": { "value": format!("\n更新详情:\n{}", details_str), "color": "#173177" },

            // 语义化通用变量
            "status": { "value": status_str, "color": "#173177" },
            "task": { "value": &event.task_name, "color": "#173177" },
            "taskName": { "value": &event.task_name, "color": "#173177" },
            "task_name": { "value": &event.task_name, "color": "#173177" },
            "ip": { "value": &ip_combined, "color": "#173177" },
            "ipv4": { "value": &ipv4_str, "color": "#173177" },
            "ipv4Addr": { "value": &ipv4_str, "color": "#173177" },
            "ipv6": { "value": &ipv6_str, "color": "#173177" },
            "ipv6Addr": { "value": &ipv6_str, "color": "#173177" },
            "domain": { "value": &domains_str, "color": "#173177" },
            "domains": { "value": &domains_str, "color": "#173177" },
            "time": { "value": &time_str, "color": "#173177" },
            "timestamp": { "value": &time_str, "color": "#173177" },
            "date": { "value": &time_str, "color": "#173177" },
            "details": { "value": &details_str, "color": "#173177" },
            "content": { "value": &details_str, "color": "#173177" },

            // 微信类目新规范模板变量 (thing / time / phrase)
            "thing1": { "value": &event.task_name, "color": "#173177" },
            "thing2": { "value": if domains_str.len() > 20 { domains_str[..20].to_string() } else { domains_str.clone() }, "color": "#173177" },
            "thing3": { "value": if ip_combined.len() > 20 { ip_combined[..20].to_string() } else { ip_combined.clone() }, "color": "#173177" },
            "character_string1": { "value": &ipv4_str, "color": "#173177" },
            "character_string2": { "value": &domains_str, "color": "#173177" },
            "time1": { "value": &time_str, "color": "#173177" },
            "time2": { "value": &time_str, "color": "#173177" },
            "phrase1": { "value": status_str, "color": "#173177" }
        })
    }
}

#[async_trait]
impl Notifier for WechatOfficialNotifier {
    fn channel_name(&self) -> &'static str {
        "微信公众号原生模板消息"
    }

    async fn send(&self, event: &NotificationEvent) -> Result<(), NotifyError> {
        let token = self.fetch_access_token().await?;
        let data_payload = self.build_template_data(event);
        let send_url = format!(
            "https://api.weixin.qq.com/cgi-bin/message/template/send?access_token={}",
            token
        );

        // 支持逗号分隔的多个 OpenID 接收者
        let users: Vec<&str> = self
            .config
            .to_user
            .split([',', ';'])
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();

        if users.is_empty() {
            return Err(NotifyError::Provider(
                "微信公众号未配置接收用户的 OpenID".to_string(),
            ));
        }

        for user_openid in users {
            let mut payload = json!({
                "touser": user_openid,
                "template_id": self.config.template_id.trim(),
                "data": data_payload
            });

            if let Some(ref jump_url) = self.config.url
                && !jump_url.trim().is_empty()
            {
                payload["url"] = json!(jump_url.trim());
            }

            let resp = self.client.post(&send_url).json(&payload).send().await?;
            let send_result: WechatSendResponse = resp.json().await?;

            if send_result.errcode != 0 {
                tracing::warn!(
                    "[{}] 向用户 {} 推送模板消息失败 [{}]: {}",
                    self.channel_name(),
                    user_openid,
                    send_result.errcode,
                    send_result.errmsg
                );
                return Err(NotifyError::Provider(format!(
                    "微信公众号推送失败 [{}]: {}",
                    send_result.errcode, send_result.errmsg
                )));
            }
        }

        tracing::info!("[{}] 模板消息推送成功", self.channel_name());
        Ok(())
    }
}
