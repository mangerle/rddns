use crate::config::model::FeishuConfig;
use crate::dns::trait_def::SyncStatus;
use crate::notifier::trait_def::{
    NotificationEvent, NotificationOverallStatus, Notifier, NotifyError,
};
use crate::util::crypto::hmac_sha256;
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chrono::Utc;
use log::info;
use reqwest::Client;
use serde_json::{Value, json};

pub struct FeishuNotifier {
    config: FeishuConfig,
    client: Client,
}

impl FeishuNotifier {
    pub fn new(config: FeishuConfig) -> Self {
        let client = crate::util::http::create_notifier_client();
        Self { config, client }
    }

    /// 构建飞书交互式卡片（Schema 2.0）消息载荷，使用原生 Table 表格完美对齐邮件样式
    pub fn build_card_payload(event: &NotificationEvent) -> Value {
        let (header_template, status_color, status_title) = match event.overall_status {
            NotificationOverallStatus::Success => ("green", "green", "● 全部同步成功"),
            NotificationOverallStatus::PartialSuccess => ("orange", "orange", "● 部分同步成功"),
            NotificationOverallStatus::Failed => ("red", "red", "● 同步出现错误"),
        };

        let ipv4_str = event
            .ipv4
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "未获取 / 未启用".to_string());
        let ipv6_str = event
            .ipv6
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "未获取 / 未启用".to_string());
        let time_str = event.timestamp.format("%Y-%m-%d %H:%M:%S").to_string();

        let mut table_rows = Vec::new();
        for r in &event.results {
            let (status_color, status_text) = match r.status {
                SyncStatus::Created => ("green", "新建"),
                SyncStatus::Updated => ("blue", "更新"),
                SyncStatus::Unchanged => ("grey", "保持"),
                SyncStatus::Failed => ("red", "失败"),
            };

            table_rows.push(json!({
                "domain": r.domain,
                "record_type": r.record_type.to_string(),
                "target_ip": r.target_ip,
                "status": format!("<font color='{}'>{}</font>", status_color, status_text),
                "message": r.message,
            }));
        }

        let page_size = event.results.len().max(5);

        json!({
            "msg_type": "interactive",
            "card": {
                "schema": "2.0",
                "config": {
                    "wide_screen_mode": true
                },
                "header": {
                    "template": header_template,
                    "title": {
                        "tag": "plain_text",
                        "content": "rddns 动态域名解析通知"
                    }
                },
                "body": {
                    "elements": [
                        {
                            "tag": "div",
                            "fields": [
                                {
                                    "is_short": true,
                                    "text": {
                                        "tag": "lark_md",
                                        "content": format!("**任务名称**\n{}", event.task_name)
                                    }
                                },
                                {
                                    "is_short": true,
                                    "text": {
                                        "tag": "lark_md",
                                        "content": format!("**同步状态**\n<font color='{}'>{}</font>", status_color, status_title)
                                    }
                                }
                            ]
                        },
                        {
                            "tag": "div",
                            "text": {
                                "tag": "lark_md",
                                "content": format!(
                                    "**IPv4 地址**：{}\n**IPv6 地址**：{}\n**触发时间**：{}",
                                    ipv4_str, ipv6_str, time_str
                                )
                            }
                        },
                        {
                            "tag": "hr"
                        },
                        {
                            "tag": "div",
                            "text": {
                                "tag": "lark_md",
                                "content": "**解析明细结果**"
                            }
                        },
                        {
                            "tag": "table",
                            "page_size": page_size,
                            "row_height": "low",
                            "header_style": {
                                "bold": true,
                                "text_align": "left"
                            },
                            "columns": [
                                {
                                    "name": "domain",
                                    "display_name": "域名",
                                    "data_type": "text",
                                    "width": "auto"
                                },
                                {
                                    "name": "record_type",
                                    "display_name": "类型",
                                    "data_type": "text",
                                    "width": "auto"
                                },
                                {
                                    "name": "target_ip",
                                    "display_name": "目标 IP",
                                    "data_type": "text",
                                    "width": "auto"
                                },
                                {
                                    "name": "status",
                                    "display_name": "状态",
                                    "data_type": "lark_md",
                                    "width": "auto"
                                },
                                {
                                    "name": "message",
                                    "display_name": "详情",
                                    "data_type": "text",
                                    "width": "auto"
                                }
                            ],
                            "rows": table_rows
                        },
                        {
                            "tag": "hr"
                        },
                        {
                            "tag": "div",
                            "text": {
                                "tag": "lark_md",
                                "content": "<font color='grey'>本通知由 rddns (基于 Rust 的高性能 DDNS 引擎) 自动发出</font>"
                            }
                        }
                    ]
                }
            }
        })
    }
}

#[async_trait]
impl Notifier for FeishuNotifier {
    fn channel_name(&self) -> &'static str {
        "飞书机器人"
    }

    async fn send(&self, event: &NotificationEvent) -> Result<(), NotifyError> {
        let mut payload = Self::build_card_payload(event);

        if let Some(ref secret) = self.config.secret
            && !secret.trim().is_empty()
        {
            let timestamp = Utc::now().timestamp();
            let string_to_sign = format!("{}\n{}", timestamp, secret.trim());
            let sign_bytes = hmac_sha256(string_to_sign.as_bytes(), b"");
            let sign_base64 = BASE64_STANDARD.encode(sign_bytes);

            payload["timestamp"] = json!(timestamp.to_string());
            payload["sign"] = json!(sign_base64);
        }

        let resp = self
            .client
            .post(&self.config.webhook_url)
            .json(&payload)
            .send()
            .await?;

        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();

        if status.is_success() {
            if let Ok(v) = serde_json::from_str::<Value>(&body)
                && let Some(code) = v.get("code").and_then(|c| c.as_i64())
                && code != 0
            {
                let msg = v.get("msg").and_then(|m| m.as_str()).unwrap_or("未知错误");
                return Err(NotifyError::Provider(format!(
                    "飞书接口业务错误 [code: {}]: {}",
                    code, msg
                )));
            }
            info!("[{}] 飞书消息发送成功", self.channel_name());
            Ok(())
        } else {
            Err(NotifyError::Provider(format!(
                "飞书返回错误 [{}]: {}",
                status, body
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::trait_def::{DnsRecordType, SyncRecordResult};
    use chrono::Local;
    use std::net::Ipv4Addr;

    #[test]
    fn test_build_card_payload_success() {
        let result1 = SyncRecordResult {
            domain: "test4.mangerle.cn".to_string(),
            record_type: DnsRecordType::A,
            target_ip: "13.115.228.110".to_string(),
            status: SyncStatus::Updated,
            message: "通知通道测试消息（真实 IPv4 数据）".to_string(),
        };
        let result2 = SyncRecordResult {
            domain: "test.mangerle.cn".to_string(),
            record_type: DnsRecordType::AAAA,
            target_ip: "::1".to_string(),
            status: SyncStatus::Updated,
            message: "通知通道测试消息（真实 IPv6 数据）".to_string(),
        };

        let event = NotificationEvent {
            overall_status: NotificationOverallStatus::Success,
            task_name: "腾讯云".to_string(),
            ipv4: Some(Ipv4Addr::new(13, 115, 228, 110)),
            ipv6: None,
            ip_changed: true,
            results: vec![result1, result2],
            timestamp: Local::now(),
        };

        let payload = FeishuNotifier::build_card_payload(&event);
        assert_eq!(payload["msg_type"], "interactive");
        assert_eq!(payload["card"]["schema"], "2.0");
        assert_eq!(payload["card"]["header"]["template"], "green");
        assert_eq!(
            payload["card"]["header"]["title"]["content"],
            "rddns 动态域名解析通知"
        );

        let card_json = payload.to_string();
        assert!(card_json.contains("腾讯云"));
        assert!(card_json.contains("全部同步成功"));
        assert!(card_json.contains("13.115.228.110"));
        assert!(card_json.contains("未获取 / 未启用"));
        assert!(card_json.contains("test4.mangerle.cn"));
        assert!(card_json.contains("\"table\""));
        assert!(card_json.contains("更新"));
    }

    #[test]
    fn test_build_card_payload_failed() {
        let result = SyncRecordResult {
            domain: "fail.example.com".to_string(),
            record_type: DnsRecordType::A,
            target_ip: "1.2.3.4".to_string(),
            status: SyncStatus::Failed,
            message: "认证失败".to_string(),
        };

        let event = NotificationEvent {
            overall_status: NotificationOverallStatus::Failed,
            task_name: "阿里云".to_string(),
            ipv4: None,
            ipv6: None,
            ip_changed: false,
            results: vec![result],
            timestamp: Local::now(),
        };

        let payload = FeishuNotifier::build_card_payload(&event);
        assert_eq!(payload["card"]["header"]["template"], "red");
        let card_json = payload.to_string();
        assert!(card_json.contains("同步出现错误"));
        assert!(card_json.contains("失败"));
    }
}
