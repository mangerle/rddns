use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 应用全局配置结构
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AppConfig {
    /// Web 服务监听端口，默认 9876
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,

    /// 全局同步检查间隔时间（秒），默认 300 秒（5分钟）
    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,

    /// 间隔 N 次与服务商强制校对云端真实记录，默认 10 次
    #[serde(default = "default_cache_times")]
    pub cache_times: u32,

    /// 是否禁止公网访问 Web UI（未设置用户名密码时默认强制禁止）
    #[serde(default = "default_not_allow_wan_access")]
    pub not_allow_wan_access: bool,

    /// Web 管理员登录凭证
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<UserAuthConfig>,

    /// DNS 解析任务列表
    #[serde(default)]
    pub dns_tasks: Vec<DnsTaskConfig>,

    /// 自定义公共 DNS 递归解析服务器 (如 "223.5.5.5", "1.1.1.1:53")，用于防 Local DNS 缓存污染
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_server: Option<String>,

    /// 通知渠道配置
    #[serde(default)]
    pub notifications: NotificationConfig,
}

fn default_listen_port() -> u16 {
    9876
}

fn default_interval_secs() -> u64 {
    300
}

fn default_cache_times() -> u32 {
    10
}

fn default_not_allow_wan_access() -> bool {
    true
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            listen_port: default_listen_port(),
            interval_secs: default_interval_secs(),
            cache_times: default_cache_times(),
            not_allow_wan_access: default_not_allow_wan_access(),
            auth: None,
            dns_server: None,
            dns_tasks: vec![DnsTaskConfig::default()],
            notifications: NotificationConfig::default(),
        }
    }
}

/// Web 管理员登录凭据
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserAuthConfig {
    pub username: String,
    /// 经过 bcrypt 哈希后的密码
    pub password_hash: String,
}

/// 单个 DNS 同步任务配置
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DnsTaskConfig {
    /// 任务名称标识（例如 "家用 NAS 解析"）
    #[serde(default = "default_task_name")]
    pub name: String,

    /// 是否启用此任务（默认 true 启用）
    #[serde(default = "default_task_enabled")]
    pub enabled: bool,

    /// DNS 服务商配置
    pub provider: ProviderConfig,

    /// IPv4 获取配置
    #[serde(default)]
    pub ipv4: IpFetchConfig,

    /// IPv6 获取配置
    #[serde(default)]
    pub ipv6: IpFetchConfig,

    /// 自定义 TTL（秒），None 或 0 表示使用服务商默认或自动 (Auto)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,

    /// 发送 HTTP 请求时绑定的出站网卡名称（可选）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_interface: Option<String>,
}

impl DnsTaskConfig {
    /// 检查任务是否配置了待解析的域名
    pub fn has_domains(&self) -> bool {
        (self.ipv4.enabled && !self.ipv4.domains.is_empty())
            || (self.ipv6.enabled && !self.ipv6.domains.is_empty())
    }
}

fn default_task_name() -> String {
    "默认任务".to_string()
}

fn default_task_enabled() -> bool {
    true
}

impl Default for DnsTaskConfig {
    fn default() -> Self {
        Self {
            name: default_task_name(),
            enabled: default_task_enabled(),
            provider: ProviderConfig::Cloudflare {
                api_token: None,
                api_key: None,
                email: None,
            },
            ipv4: IpFetchConfig {
                enabled: true,
                source_type: IpSourceType::Url,
                url_endpoints: vec![
                    "https://api.ipify.org".to_string(),
                    "https://myip.ipip.net/ip".to_string(),
                    "https://ddns.oray.com/checkip".to_string(),
                ],
                net_interface: None,
                cmd: None,
                regex: None,
                domains: vec![],
            },
            ipv6: IpFetchConfig {
                enabled: false,
                source_type: IpSourceType::Url,
                url_endpoints: vec![
                    "https://api64.ipify.org".to_string(),
                    "https://speed.neu6.edu.cn/getIP.php".to_string(),
                ],
                net_interface: None,
                cmd: None,
                regex: None,
                domains: vec![],
            },
            ttl: None,
            http_interface: None,
        }
    }
}

/// IP 提取来源类型
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IpSourceType {
    /// 通过 HTTP(S) URL 请求远程 API 获取
    Url,
    /// 通过网卡设备 (Network Interface) 读取
    NetInterface,
    /// 通过执行外部命令或脚本获取
    Command,
}

/// IP 提取具体配置
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IpFetchConfig {
    /// 是否启用
    #[serde(default)]
    pub enabled: bool,

    /// 提取方式类型
    #[serde(default = "default_source_type")]
    pub source_type: IpSourceType,

    /// URL 接口地址列表（支持配置备用 URL 回退）
    #[serde(default)]
    pub url_endpoints: Vec<String>,

    /// 网卡名称（当 source_type 为 net_interface 时生效）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub net_interface: Option<String>,

    /// 外部命令与参数（当 source_type 为 command 时生效）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmd: Option<String>,

    /// 自定义正则表达式（用于从响应或网卡中筛选目标 IP）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,

    /// 绑定的域名列表（如 "sub:example.com", "@:example.com", "*.example.com"）
    #[serde(default)]
    pub domains: Vec<String>,
}

fn default_source_type() -> IpSourceType {
    IpSourceType::Url
}

impl Default for IpFetchConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            source_type: default_source_type(),
            url_endpoints: vec![],
            net_interface: None,
            cmd: None,
            regex: None,
            domains: vec![],
        }
    }
}

/// DNS 提供商配置枚举（强类型 Tagged Union）
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProviderConfig {
    /// Cloudflare 服务商
    Cloudflare {
        /// API Token（推荐，最安全）
        #[serde(skip_serializing_if = "Option::is_none")]
        api_token: Option<String>,
        /// Global API Key（与 email 配合使用）
        #[serde(skip_serializing_if = "Option::is_none")]
        api_key: Option<String>,
        /// 注册邮箱（配合 Global API Key 使用）
        #[serde(skip_serializing_if = "Option::is_none")]
        email: Option<String>,
    },
    /// 阿里云 (AliDNS / 阿里云 ESA)
    AliDns {
        access_key_id: String,
        access_key_secret: String,
        /// 自定义 API Endpoint（可选）
        #[serde(skip_serializing_if = "Option::is_none")]
        endpoint: Option<String>,
    },
    /// 腾讯云 (DNSPod / Tencent Cloud API v3)
    TencentCloud {
        secret_id: String,
        secret_key: String,
    },
    /// 华为云
    HuaweiCloud {
        access_key_id: String,
        secret_access_key: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        region: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        endpoint: Option<String>,
    },
    /// Porkbun
    Porkbun { api_key: String, secret_key: String },
    /// GoDaddy
    GoDaddy { api_key: String, api_secret: String },
    /// Dynv6
    Dynv6 { token: String },
    /// 百度智能云
    BaiduCloud {
        access_key_id: String,
        secret_access_key: String,
    },
    /// 火山引擎
    TrafficRoute {
        access_key_id: String,
        secret_access_key: String,
    },
    /// Namecheap
    Namecheap { password: String },
    /// NameSilo
    NameSilo { api_key: String },
    /// Spaceship
    Spaceship { api_key: String, api_secret: String },
    /// Dynadot
    Dynadot { password: String },
    /// Vercel DNS
    /// Vercel DNS
    /// Vercel DNS
    Vercel {
        token: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        team_id: Option<String>,
    },
    /// 雨云 (RainYun)
    RainYun {
        api_key: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        domain_id: Option<String>,
    },
    /// ClouDNS
    ClouDNS {
        auth_id: String,
        auth_password: String,
    },
    /// Gcore DNS
    Gcore { api_key: String },
    /// Name.com
    NameCom { username: String, api_token: String },
    /// DNS.LA
    DnsLa { api_id: String, api_secret: String },
    /// 阿里云 ESA (Edge Security Acceleration)
    AliEsa {
        access_key_id: String,
        access_key_secret: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        endpoint: Option<String>,
    },
    /// 腾讯云 EdgeOne (EO)
    EdgeOne {
        secret_id: String,
        secret_key: String,
    },
    /// 时代互联 (NowCN)
    NowCn { id: String, secret: String },
    /// 时代互联国际版 (Eranet)
    Eranet { id: String, secret: String },
    /// TNetHK
    TNetHk { id: String, secret: String },
    /// IBM NS1 Connect
    NsOne { api_key: String },
    /// HiPM DNSMgr
    HipmDnsMgr {
        #[serde(skip_serializing_if = "Option::is_none")]
        endpoint: Option<String>,
        api_token: String,
    },
    /// 自定义通用 Callback / Webhook 驱动
    Callback {
        url: String,
        #[serde(default = "default_http_method")]
        method: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        headers: Option<HashMap<String, String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        body: Option<String>,
    },
}

impl ProviderConfig {
    /// 判断是否已配置了有效的认证凭据
    pub fn is_configured(&self) -> bool {
        match self {
            Self::Cloudflare {
                api_token,
                api_key,
                email,
            } => {
                let has_token = api_token
                    .as_ref()
                    .map(|t| !t.trim().is_empty())
                    .unwrap_or(false);
                let has_key = api_key
                    .as_ref()
                    .map(|k| !k.trim().is_empty())
                    .unwrap_or(false);
                let has_email = email
                    .as_ref()
                    .map(|e| !e.trim().is_empty())
                    .unwrap_or(false);
                has_token || (has_key && has_email)
            }
            Self::AliDns {
                access_key_id,
                access_key_secret,
                ..
            } => !access_key_id.trim().is_empty() && !access_key_secret.trim().is_empty(),
            Self::TencentCloud {
                secret_id,
                secret_key,
            } => !secret_id.trim().is_empty() && !secret_key.trim().is_empty(),
            Self::HuaweiCloud {
                access_key_id,
                secret_access_key,
                ..
            } => !access_key_id.trim().is_empty() && !secret_access_key.trim().is_empty(),
            Self::Porkbun {
                api_key,
                secret_key,
            } => !api_key.trim().is_empty() && !secret_key.trim().is_empty(),
            Self::GoDaddy {
                api_key,
                api_secret,
            } => !api_key.trim().is_empty() && !api_secret.trim().is_empty(),
            Self::Dynv6 { token } => !token.trim().is_empty(),
            Self::BaiduCloud {
                access_key_id,
                secret_access_key,
            } => !access_key_id.trim().is_empty() && !secret_access_key.trim().is_empty(),
            Self::TrafficRoute {
                access_key_id,
                secret_access_key,
            } => !access_key_id.trim().is_empty() && !secret_access_key.trim().is_empty(),
            Self::Namecheap { password } => !password.trim().is_empty(),
            Self::NameSilo { api_key } => !api_key.trim().is_empty(),
            Self::Spaceship {
                api_key,
                api_secret,
            } => !api_key.trim().is_empty() && !api_secret.trim().is_empty(),
            Self::Dynadot { password } => !password.trim().is_empty(),
            Self::Vercel { token, .. } => !token.trim().is_empty(),
            Self::RainYun { api_key, .. } => !api_key.trim().is_empty(),
            Self::ClouDNS {
                auth_id,
                auth_password,
            } => !auth_id.trim().is_empty() && !auth_password.trim().is_empty(),
            Self::Gcore { api_key } => !api_key.trim().is_empty(),
            Self::NameCom {
                username,
                api_token,
            } => !username.trim().is_empty() && !api_token.trim().is_empty(),
            Self::DnsLa { api_id, api_secret } => {
                !api_id.trim().is_empty() && !api_secret.trim().is_empty()
            }
            Self::AliEsa {
                access_key_id,
                access_key_secret,
                ..
            } => !access_key_id.trim().is_empty() && !access_key_secret.trim().is_empty(),
            Self::EdgeOne {
                secret_id,
                secret_key,
            } => !secret_id.trim().is_empty() && !secret_key.trim().is_empty(),
            Self::NowCn { id, secret } => !id.trim().is_empty() && !secret.trim().is_empty(),
            Self::Eranet { id, secret } => !id.trim().is_empty() && !secret.trim().is_empty(),
            Self::TNetHk { id, secret } => !id.trim().is_empty() && !secret.trim().is_empty(),
            Self::NsOne { api_key } => !api_key.trim().is_empty(),
            Self::HipmDnsMgr { api_token, .. } => !api_token.trim().is_empty(),
            Self::Callback { url, .. } => !url.trim().is_empty(),
        }
    }
}

fn default_http_method() -> String {
    "GET".to_string()
}

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
