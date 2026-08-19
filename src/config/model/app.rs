use crate::config::model::dns::DnsTaskConfig;
use crate::config::model::notification::NotificationConfig;
use serde::{Deserialize, Serialize};

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
    /// 经过 bcrypt 哈希后的密码 (返回给前端时清空并不序列化，存盘到本地时持久化)
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password_hash: String,
}
