use serde::{Deserialize, Serialize};

pub use crate::config::model::provider::ProviderConfig;

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
