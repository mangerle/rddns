use crate::config::model::dns::{DnsTaskConfig, IpSourceType};
use crate::config::model::notification::NotificationConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

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

    /// 自定义公共 DNS 递归解析服务器 (如 "223.5.5.5", "1.1.1.1:53")，用于防 Local DNS 缓存污染
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_server: Option<String>,

    /// Web 管理员登录凭证
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<UserAuthConfig>,

    /// 通知渠道配置
    #[serde(default)]
    pub notifications: NotificationConfig,

    /// DNS 解析任务列表
    #[serde(default)]
    pub dns_tasks: Vec<DnsTaskConfig>,
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

impl AppConfig {
    /// 校验配置的边界与合法性
    ///
    /// # 设计原理
    /// - **实现初衷**：统一 Web API 保存、CLI 启动与直接修改磁盘文件三种场景的配置校验，消除规则双写与绕过风险。
    /// - **核心优势**：在数据边界直接发现错误，返回详尽的中文错误原因列表。
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errs = Vec::new();
        if self.interval_secs < 5 {
            errs.push(format!(
                "同步检查间隔时间必须大于或等于 5 秒，当前为 {}",
                self.interval_secs
            ));
        }
        if self.cache_times < 1 {
            errs.push(format!(
                "强制校对云端记录间隔次数必须大于或等于 1 次，当前为 {}",
                self.cache_times
            ));
        }
        if self.listen_port == 0 {
            errs.push("Web 服务监听端口必须在 1 到 65535 之间".to_string());
        }

        let mut task_names = HashSet::with_capacity(self.dns_tasks.len());
        for task in &self.dns_tasks {
            let name = task.name.trim();
            if name.is_empty() {
                errs.push("任务名称不能为空".to_string());
            } else if !task_names.insert(name) {
                errs.push(format!("任务名称 [{}] 存在重复，各任务名称必须唯一", name));
            }

            for ip_cfg in [&task.ipv4, &task.ipv6] {
                if ip_cfg.source_type == IpSourceType::Url {
                    for url in &ip_cfg.url_endpoints {
                        let trimmed = url.trim();
                        if !trimmed.is_empty()
                            && !trimmed.starts_with("http://")
                            && !trimmed.starts_with("https://")
                        {
                            errs.push(format!(
                                "任务 [{}] 中的 URL 端点 [{}] 协议非法，仅允许 http:// 或 https:// 开头的地址",
                                name, trimmed
                            ));
                        }
                    }
                } else if ip_cfg.source_type == IpSourceType::Command {
                    if let Some(ref cmd_str) = ip_cfg.cmd {
                        let trimmed = cmd_str.trim();
                        if trimmed.is_empty() {
                            errs.push(format!(
                                "任务 [{}] 配置为命令提取 IP，但指定的命令内容为空",
                                name
                            ));
                        }
                        const DANGEROUS_SHELL_CHARS: &[char] =
                            &['|', ';', '&', '`', '$', '>', '<', '\n', '\r'];
                        if trimmed.chars().any(|c| DANGEROUS_SHELL_CHARS.contains(&c)) {
                            errs.push(format!(
                                "任务 [{}] 中的命令包含高风险 Shell 注入字符 (|;&`$><)，仅允许执行单个独立脚本或可执行文件及参数",
                                name
                            ));
                        }
                    } else {
                        errs.push(format!(
                            "任务 [{}] 配置为命令提取 IP，但未指定执行命令",
                            name
                        ));
                    }
                }
            }
        }

        if errs.is_empty() { Ok(()) } else { Err(errs) }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_config_validation() {
        let mut config = AppConfig::default();
        assert!(config.validate().is_ok());

        config.interval_secs = 4;
        assert!(config.validate().is_err());
        config.interval_secs = 5;

        config.cache_times = 0;
        assert!(config.validate().is_err());
        config.cache_times = 1;

        config.listen_port = 0;
        assert!(config.validate().is_err());
    }
}
