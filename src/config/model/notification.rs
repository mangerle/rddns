use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 通知告警总配置
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct NotificationConfig {
    /// 仅当 IP 发生实际变动时才发送通知（默认开启）
    #[serde(default = "default_true")]
    pub on_ip_change_only: bool,

    /// 同步成功时是否发送通知
    #[serde(default = "default_true")]
    pub on_success: bool,

    /// 同步失败时是否报警
    #[serde(default = "default_true")]
    pub on_failure: bool,

    /// 微信公众号原生模板消息配置
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wechat_official: Option<WechatOfficialConfig>,

    /// 企业微信配置
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wecom: Option<WeComConfig>,

    /// Telegram 机器人配置
    #[serde(skip_serializing_if = "Option::is_none")]
    pub telegram: Option<TelegramConfig>,

    /// 钉钉机器人配置
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dingtalk: Option<DingTalkConfig>,

    /// 飞书机器人配置
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feishu: Option<FeishuConfig>,

    /// Bark (iOS) 推送配置
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bark: Option<BarkConfig>,

    /// SMTP 邮件通知配置
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<EmailConfig>,

    /// 通用自定义 Webhook
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook: Option<WebhookConfig>,
}

/// 微信公众号原生模板消息推送配置
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct WechatOfficialConfig {
    pub enabled: bool,
    /// 微信公众号 AppID
    pub app_id: String,
    /// 微信公众号 AppSecret
    pub app_secret: String,
    /// 模板消息 ID (template_id)
    pub template_id: String,
    /// 接收用户的 OpenID
    pub to_user: String,
    /// 点击卡片跳转 URL (可选)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// 自定义模板字段 JSON 结构（可选，为空时使用标准通用格式）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_data: Option<String>,
}

fn default_true() -> bool {
    true
}

/// 企业微信配置
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WeComConfig {
    pub enabled: bool,
    /// 模式: "bot" (群机器人 Webhook) 或 "app" (自建应用消息推送)
    #[serde(default = "default_wecom_mode")]
    pub mode: String,
    /// 群机器人 Webhook Key 或完整 URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
    /// 自建应用参数
    #[serde(skip_serializing_if = "Option::is_none")]
    pub corp_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub corp_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_user: Option<String>,
}

fn default_wecom_mode() -> String {
    "bot".to_string()
}

/// Telegram 配置
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TelegramConfig {
    pub enabled: bool,
    pub bot_token: String,
    pub chat_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_proxy: Option<String>,
}

/// 钉钉机器人配置
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DingTalkConfig {
    pub enabled: bool,
    pub access_token: String,
    /// 加签 Secret（可选）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
}

/// 飞书机器人配置
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FeishuConfig {
    pub enabled: bool,
    pub webhook_url: String,
    /// 签名校验 Secret（可选）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
}

/// Bark 配置
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BarkConfig {
    pub enabled: bool,
    pub server_url: String,
    pub device_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sound: Option<String>,
}

/// SMTP 邮件配置
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EmailConfig {
    pub enabled: bool,
    pub smtp_server: String,
    pub smtp_port: u16,
    pub use_ssl: bool,
    pub username: String,
    pub password: String,
    pub from_address: String,
    pub to_addresses: Vec<String>,
}

/// 通用自定义 Webhook
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WebhookConfig {
    pub enabled: bool,
    pub url: String,
    #[serde(default = "default_http_method")]
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
}

fn default_http_method() -> String {
    "GET".to_string()
}
