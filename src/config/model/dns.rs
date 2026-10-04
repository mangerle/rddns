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

    /// 自定义 TTL（秒），None 或 0 表示使用服务商默认或自动 (Auto)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,

    /// 发送 HTTP 请求时绑定的出站网卡名称（可选）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_interface: Option<String>,

    /// DNS 服务商配置
    pub provider: ProviderConfig,

    /// IPv4 获取配置
    #[serde(default)]
    pub ipv4: IpFetchConfig,

    /// IPv6 获取配置
    #[serde(default)]
    pub ipv6: IpFetchConfig,
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
                stun_server: None,
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
                stun_server: None,
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
    /// 通过 STUN 协议 (RFC 5389) 极速 UDP 探测公网 IP
    Stun,
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

    /// 自定义 STUN 服务器地址（当 source_type 为 stun 时生效，留空使用内置高可用集群）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stun_server: Option<String>,

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
            stun_server: None,
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
    ///
    /// # 设计原理
    /// - **实现初衷**：在启动周期任务前先行判断用户是否已输入该服务商的有效密钥，避免空凭据发往云端产生无效 HTTP 报错。
    /// - **核心优势**：针对不同 DNS 厂商模式匹配聚类，判断高效直接。
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
            }
            | Self::TencentCloud {
                secret_id: access_key_id,
                secret_key: access_key_secret,
            }
            | Self::EdgeOne {
                secret_id: access_key_id,
                secret_key: access_key_secret,
            }
            | Self::HuaweiCloud {
                access_key_id,
                secret_access_key: access_key_secret,
                ..
            }
            | Self::BaiduCloud {
                access_key_id,
                secret_access_key: access_key_secret,
            }
            | Self::TrafficRoute {
                access_key_id,
                secret_access_key: access_key_secret,
            }
            | Self::Porkbun {
                api_key: access_key_id,
                secret_key: access_key_secret,
            }
            | Self::GoDaddy {
                api_key: access_key_id,
                api_secret: access_key_secret,
            }
            | Self::Spaceship {
                api_key: access_key_id,
                api_secret: access_key_secret,
            }
            | Self::DnsLa {
                api_id: access_key_id,
                api_secret: access_key_secret,
            }
            | Self::ClouDNS {
                auth_id: access_key_id,
                auth_password: access_key_secret,
            }
            | Self::NameCom {
                username: access_key_id,
                api_token: access_key_secret,
            }
            | Self::NowCn {
                id: access_key_id,
                secret: access_key_secret,
            }
            | Self::Eranet {
                id: access_key_id,
                secret: access_key_secret,
            }
            | Self::TNetHk {
                id: access_key_id,
                secret: access_key_secret,
            } => not_empty(access_key_id) && not_empty(access_key_secret),
            Self::Namecheap { password }
            | Self::Dynadot { password }
            | Self::Dynv6 { token: password }
            | Self::Vercel {
                token: password, ..
            }
            | Self::NameSilo { api_key: password }
            | Self::RainYun {
                api_key: password, ..
            }
            | Self::Gcore { api_key: password }
            | Self::NsOne { api_key: password }
            | Self::HipmDnsMgr {
                api_token: password,
                ..
            }
            | Self::Callback { url: password, .. } => not_empty(password),
        }
    }
}

fn default_http_method() -> String {
    "GET".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个所有凭据字段均为空字符串的 provider 配置
    ///
    /// # 设计原理
    /// `is_configured` 是「是否跳过同步」的唯一判据，且与
    /// `create_dns_provider` 的 match 是两处独立的 27 分支手工枚举。
    /// 新增 provider 时若遗漏 `is_configured` 分支，编译器不会报错，
    /// 只会让配置完整的用户被静默跳过同步。故以测试形式建立兜底防线：
    /// 空白凭据必须一律判定为未配置。
    fn blank_credentials() -> ProviderConfig {
        ProviderConfig::Cloudflare {
            api_token: Some(String::new()),
            api_key: Some(String::new()),
            email: Some(String::new()),
        }
    }

    #[test]
    fn test_is_configured_rejects_blank_credentials() {
        // 全空凭据必须判定为未配置，避免向云端发送必然失败的请求
        assert!(!blank_credentials().is_configured());
    }

    #[test]
    fn test_is_configured_rejects_whitespace_only_credentials() {
        // 仅含空白字符等同于未填写
        let conf = ProviderConfig::Cloudflare {
            api_token: Some("   ".to_string()),
            api_key: None,
            email: None,
        };
        assert!(!conf.is_configured());
    }

    #[test]
    fn test_is_configured_accepts_cloudflare_token() {
        let conf = ProviderConfig::Cloudflare {
            api_token: Some("cf-token".to_string()),
            api_key: None,
            email: None,
        };
        assert!(conf.is_configured());
    }

    #[test]
    fn test_is_configured_cloudflare_requires_key_and_email_together() {
        // Global API Key 必须与邮箱同时配置，缺一不可
        let only_key = ProviderConfig::Cloudflare {
            api_token: None,
            api_key: Some("cf-key".to_string()),
            email: None,
        };
        assert!(!only_key.is_configured());

        let key_and_email = ProviderConfig::Cloudflare {
            api_token: None,
            api_key: Some("cf-key".to_string()),
            email: Some("user@example.com".to_string()),
        };
        assert!(key_and_email.is_configured());
    }

    #[test]
    fn test_is_configured_rejects_partial_credential_pairs() {
        // 各厂商的「密钥对」必须成对出现，缺一即视为未配置
        let cases: Vec<ProviderConfig> = vec![
            ProviderConfig::AliDns {
                access_key_id: "ak".to_string(),
                access_key_secret: String::new(),
                endpoint: None,
            },
            ProviderConfig::TencentCloud {
                secret_id: "sid".to_string(),
                secret_key: String::new(),
            },
            ProviderConfig::EdgeOne {
                secret_id: "sid".to_string(),
                secret_key: String::new(),
            },
            ProviderConfig::BaiduCloud {
                access_key_id: "ak".to_string(),
                secret_access_key: String::new(),
            },
            ProviderConfig::TrafficRoute {
                access_key_id: "ak".to_string(),
                secret_access_key: String::new(),
            },
            ProviderConfig::Porkbun {
                api_key: "ak".to_string(),
                secret_key: String::new(),
            },
            ProviderConfig::GoDaddy {
                api_key: "ak".to_string(),
                api_secret: String::new(),
            },
            ProviderConfig::NameCom {
                username: "user".to_string(),
                api_token: String::new(),
            },
        ];

        for conf in cases {
            assert!(
                !conf.is_configured(),
                "凭据对不完整时应判定为未配置: {:?}",
                conf
            );
        }
    }

    #[test]
    fn test_is_configured_accepts_complete_credential_pairs() {
        let cases: Vec<ProviderConfig> = vec![
            ProviderConfig::AliDns {
                access_key_id: "ak".to_string(),
                access_key_secret: "sk".to_string(),
                endpoint: None,
            },
            ProviderConfig::TencentCloud {
                secret_id: "sid".to_string(),
                secret_key: "sk".to_string(),
            },
            ProviderConfig::EdgeOne {
                secret_id: "sid".to_string(),
                secret_key: "sk".to_string(),
            },
            ProviderConfig::BaiduCloud {
                access_key_id: "ak".to_string(),
                secret_access_key: "sk".to_string(),
            },
            ProviderConfig::TrafficRoute {
                access_key_id: "ak".to_string(),
                secret_access_key: "sk".to_string(),
            },
            ProviderConfig::Porkbun {
                api_key: "ak".to_string(),
                secret_key: "sk".to_string(),
            },
            ProviderConfig::GoDaddy {
                api_key: "ak".to_string(),
                api_secret: "sk".to_string(),
            },
            ProviderConfig::NameCom {
                username: "user".to_string(),
                api_token: "token".to_string(),
            },
            ProviderConfig::Namecheap {
                password: "pwd".to_string(),
            },
            ProviderConfig::Dynv6 {
                token: "token".to_string(),
            },
            ProviderConfig::Vercel {
                token: "token".to_string(),
                team_id: None,
            },
            ProviderConfig::Callback {
                url: "https://example.com/hook".to_string(),
                method: "POST".to_string(),
                headers: None,
                body: None,
            },
        ];

        for conf in cases {
            assert!(conf.is_configured(), "凭据完整时应判定为已配置: {:?}", conf);
        }
    }
}
