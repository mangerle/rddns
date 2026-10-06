use crate::config::model::WechatOfficialConfig;
use crate::notifier::trait_def::{NotificationEvent, Notifier, NotifyError};
use crate::util::http::create_notifier_client;
use async_trait::async_trait;
use log::{info, warn};
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;

use crate::notifier::token_cache::DclTokenCache;
use std::sync::LazyLock;
use std::time::Duration;

/// 微信 Access Token 响应实体
#[derive(Debug, Deserialize)]
struct WechatTokenResponse {
    pub access_token: Option<String>,
    pub expires_in: Option<u64>,
    pub errcode: Option<i64>,
    pub errmsg: Option<String>,
}

/// 微信模板消息发送响应实体
#[derive(Debug, Deserialize)]
struct WechatSendResponse {
    pub errcode: i64,
    pub errmsg: String,
}

/// 全局微信公众号 AccessToken 缓存池，通过 DclTokenCache 实现双重检查锁与防并发击穿
static WECHAT_TOKEN_CACHE: LazyLock<DclTokenCache> = LazyLock::new(|| DclTokenCache::new(64));

/// 微信公众号原生模板消息适配器
pub struct WechatOfficialNotifier {
    config: WechatOfficialConfig,
    client: Client,
}

impl WechatOfficialNotifier {
    pub fn new(config: WechatOfficialConfig) -> Self {
        let client = create_notifier_client();
        Self { config, client }
    }

    /// 获取公众号全局接口调用凭证 access_token (优先从内存缓存中获取)
    ///
    /// # 设计原理
    /// - **实现初衷**: 避免在 Token 过期瞬间多个并发任务同时穿透去请求微信 Token 接口，造成缓存击穿并触发微信 API 限流。
    /// - **核心优势**: 采用双重检查锁 (Double-Checked Locking) 模式，锁前快速读取，锁后二次确认，确保同一时刻仅单个协程向远端刷新。
    async fn fetch_access_token(&self) -> Result<String, NotifyError> {
        let app_id = self.config.app_id.trim();
        let app_secret = self.config.app_secret.trim();

        WECHAT_TOKEN_CACHE
            .get_or_fetch(app_id, || async {
                let url = format!(
                    "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid={}&secret={}",
                    app_id,
                    app_secret
                );

                let resp = self.client.get(&url).send().await?;
                let token_resp: WechatTokenResponse = resp.json().await?;

                if let Some(token) = token_resp.access_token
                    && !token.is_empty()
                {
                    let ttl_secs = token_resp.expires_in.unwrap_or(7200).saturating_sub(300); // 预留 5 分钟缓冲
                    let ttl = Duration::from_secs(ttl_secs.max(60));
                    return Ok((token, ttl));
                }

                let err_code = token_resp.errcode.unwrap_or(-1);
                let err_msg = token_resp
                    .errmsg
                    .unwrap_or_else(|| "未知凭证错误".to_string());
                Err(NotifyError::Provider(format!(
                    "微信公众号获取 AccessToken 失败 [{}]: {}",
                    err_code, err_msg
                )))
            })
            .await
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

        let task_name_20: String = event.task_name.chars().take(20).collect();

        json!({
            // 经典模板变量
            "first": { "value": format!("【rddns 动态解析通知】{}", status_str), "color": "#173177" },
            "keyword1": { "value": &task_name_20, "color": "#173177" },
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
            "thing1": { "value": &task_name_20, "color": "#173177" },
            "thing2": { "value": domains_str.chars().take(20).collect::<String>(), "color": "#173177" },
            "thing3": { "value": ip_combined.chars().take(20).collect::<String>(), "color": "#173177" },
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

        let mut success_count = 0;
        let mut last_error = None;

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

            match self.client.post(&send_url).json(&payload).send().await {
                Ok(resp) => match resp.json::<WechatSendResponse>().await {
                    Ok(send_result) => {
                        if send_result.errcode == 0 {
                            success_count += 1;
                        } else {
                            warn!(
                                "[{}] 向用户 {} 推送模板消息失败 [{}]: {}",
                                self.channel_name(),
                                user_openid,
                                send_result.errcode,
                                send_result.errmsg
                            );
                            last_error = Some(format!(
                                "微信推送失败 [{}]: {}",
                                send_result.errcode, send_result.errmsg
                            ));
                        }
                    }
                    Err(e) => {
                        // 脱敏后再入库 (P1-3)：Decode 错误文本通常不含凭据，
                        // 但统一走脱敏出口可避免未来错误类型变更导致泄漏回归
                        let safe_text =
                            crate::dns::trait_def::sanitize_sensitive_url_params(&e.to_string());
                        warn!(
                            "[{}] 解析向用户 {} 推送响应失败: {}",
                            self.channel_name(),
                            user_openid,
                            safe_text
                        );
                        last_error = Some(safe_text);
                    }
                },
                Err(e) => {
                    // reqwest::Error 的 Display 会输出完整请求 URL，其中含
                    // `access_token=<明文>` 查询参数。直接格式化将导致微信
                    // access_token 每次网络失败都明文写入日志文件，而日志文件
                    // 权限为 0644（见 util/logging/file.rs），本地任意用户可读。
                    // 此处必须经脱敏出口 (P1-3)。
                    let safe_text =
                        crate::dns::trait_def::sanitize_sensitive_url_params(&e.to_string());
                    warn!(
                        "[{}] 向用户 {} 发送网络请求失败: {}",
                        self.channel_name(),
                        user_openid,
                        safe_text
                    );
                    last_error = Some(safe_text);
                }
            }
        }

        if success_count > 0 {
            info!(
                "[{}] 模板消息推送完成 (成功: {} 位用户)",
                self.channel_name(),
                success_count
            );
            Ok(())
        } else {
            Err(NotifyError::Provider(
                last_error.unwrap_or_else(|| "全部接收者推送均失败".to_string()),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::WechatOfficialConfig;
    use crate::dns::trait_def::{SyncRecordResult, SyncStatus};
    use crate::notifier::trait_def::{NotificationEvent, NotificationOverallStatus};
    use chrono::Local;

    #[test]
    fn test_wechat_template_utf8_truncation() {
        let config = WechatOfficialConfig {
            enabled: true,
            app_id: "test".to_string(),
            app_secret: "test".to_string(),
            template_id: "test".to_string(),
            to_user: "openid".to_string(),
            url: None,
            template_data: None,
        };
        let notifier = WechatOfficialNotifier::new(config);

        let event = NotificationEvent {
            overall_status: NotificationOverallStatus::Failed,
            task_name: "超长中文任务名称测试——这是一个超过二十个汉字的特殊任务名字".to_string(),
            ipv4: None,
            ipv6: None,
            ip_changed: false,
            results: vec![SyncRecordResult {
                domain: "超长中文域名测试.测试.中国.com".to_string(),
                record_type: crate::dns::trait_def::DnsRecordType::A,
                target_ip: "未知".to_string(),
                status: SyncStatus::Failed,
                message: "错误信息".to_string(),
            }],
            timestamp: Local::now(),
        };

        let data = notifier.build_template_data(&event);
        let thing1 = data["thing1"]["value"].as_str().unwrap();
        let keyword1 = data["keyword1"]["value"].as_str().unwrap();
        let thing2 = data["thing2"]["value"].as_str().unwrap();
        let thing3 = data["thing3"]["value"].as_str().unwrap();

        assert_eq!(thing1.chars().count(), 20);
        assert_eq!(keyword1.chars().count(), 20);
        assert!(thing2.chars().count() <= 20);
        assert!(thing3.chars().count() <= 20);
    }
}
