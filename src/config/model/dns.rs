use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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

#[inline]
fn not_empty(s: &str) -> bool {
    !s.trim().is_empty()
}

#[inline]
fn opt_not_empty(s: &Option<String>) -> bool {
    s.as_deref().map(not_empty).unwrap_or(false)
}

impl ProviderConfig {
    /// 判断是否已配置了有效的认证凭据
    pub fn is_configured(&self) -> bool {
        match self {
            Self::Cloudflare {
                api_token,
                api_key,
                email,
            } => opt_not_empty(api_token) || (opt_not_empty(api_key) && opt_not_empty(email)),
            Self::AliDns {
                access_key_id,
                access_key_secret,
                ..
            }
            | Self::AliEsa {
                access_key_id,
                access_key_secret,
                ..
            } => not_empty(access_key_id) && not_empty(access_key_secret),
            Self::TencentCloud {
                secret_id,
                secret_key,
            }
            | Self::EdgeOne {
                secret_id,
                secret_key,
            } => not_empty(secret_id) && not_empty(secret_key),
            Self::HuaweiCloud {
                access_key_id,
                secret_access_key,
                ..
            }
            | Self::BaiduCloud {
                access_key_id,
                secret_access_key,
            }
            | Self::TrafficRoute {
                access_key_id,
                secret_access_key,
            } => not_empty(access_key_id) && not_empty(secret_access_key),
            Self::Porkbun {
                api_key,
                secret_key,
            } => not_empty(api_key) && not_empty(secret_key),
            Self::GoDaddy {
                api_key,
                api_secret,
            }
            | Self::Spaceship {
                api_key,
                api_secret,
            }
            | Self::DnsLa {
                api_id: api_key,
                api_secret,
            } => not_empty(api_key) && not_empty(api_secret),
            Self::ClouDNS {
                auth_id,
                auth_password,
            } => not_empty(auth_id) && not_empty(auth_password),
            Self::NameCom {
                username,
                api_token,
            } => not_empty(username) && not_empty(api_token),
            Self::NowCn { id, secret }
            | Self::Eranet { id, secret }
            | Self::TNetHk { id, secret } => not_empty(id) && not_empty(secret),
            Self::Namecheap { password } | Self::Dynadot { password } => not_empty(password),
            Self::Dynv6 { token } | Self::Vercel { token, .. } => not_empty(token),
            Self::NameSilo { api_key }
            | Self::RainYun { api_key, .. }
            | Self::Gcore { api_key }
            | Self::NsOne { api_key } => not_empty(api_key),
            Self::HipmDnsMgr { api_token, .. } => not_empty(api_token),
            Self::Callback { url, .. } => not_empty(url),
        }
    }
}

fn default_http_method() -> String {
    "GET".to_string()
}
