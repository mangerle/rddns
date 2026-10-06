use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// DNS 提供商配置枚举（强类型 Tagged Union）
///
/// # 设计原理
/// - **实现初衷**: DDNS 支持 20 余种国内外主流及小众云解析平台，各平台鉴权凭据差异显著（如 AccessKey 对、API Token、账号密码等）。
///   采用 Tagged Union（内部带有 `"type"` 标识字段）能够在序列化与反序列化时精准映射各平台配置，且编译期排他。
/// - **核心优势**: 消除非法配置状态；配合 Serde 的 `tag = "type"`，与 Web 前后端 JSON 契约无缝对齐。
/// - **代价与局限**: 变体较多导致模式匹配时需覆盖较多分枝，可通过公共辅助函数聚合相同鉴权特征的平台。
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
    #[serde(alias = "godaddy")]
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
    #[serde(alias = "namesilo")]
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
    #[serde(alias = "rainyun")]
    RainYun {
        api_key: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        domain_id: Option<String>,
    },
    /// ClouDNS
    #[serde(alias = "cloudns")]
    ClouDNS {
        auth_id: String,
        auth_password: String,
    },
    /// Gcore DNS
    Gcore { api_key: String },
    /// Name.com
    NameCom { username: String, api_token: String },
    /// DNS.LA
    #[serde(alias = "dnsla")]
    DnsLa { api_id: String, api_secret: String },
    /// 阿里云 ESA (Edge Security Acceleration)
    #[serde(alias = "aliesa")]
    AliEsa {
        access_key_id: String,
        access_key_secret: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        endpoint: Option<String>,
    },
    /// 腾讯云 EdgeOne (EO)
    #[serde(alias = "edgeone")]
    EdgeOne {
        secret_id: String,
        secret_key: String,
    },
    /// 时代互联 (NowCN)
    #[serde(alias = "nowcn")]
    NowCn { id: String, secret: String },
    /// 时代互联国际版 (Eranet)
    Eranet { id: String, secret: String },
    /// TNetHK
    #[serde(alias = "tnethk")]
    TNetHk { id: String, secret: String },
    /// IBM NS1 Connect
    #[serde(alias = "nsone")]
    NsOne { api_key: String },
    /// HiPM DNSMgr
    #[serde(alias = "hipm_dnsmgr")]
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
            | Self::Callback { url: password, .. } => not_empty(password),
            Self::HipmDnsMgr {
                endpoint,
                api_token,
            } => opt_not_empty(endpoint) && not_empty(api_token),
        }
    }
}

fn default_http_method() -> String {
    "GET".to_string()
}

#[cfg(test)]
#[path = "provider_tests.rs"]
mod tests;
