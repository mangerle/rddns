use crate::config::model::dns::{DnsTaskConfig, IpSourceType};
use crate::config::model::notification::NotificationConfig;
use crate::config::model::provider::ProviderConfig;
use crate::util::command::validate_command_str;
use crate::util::domain::parse_domain;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use url::Url;

/// 应用全局配置结构
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AppConfig {
    /// 配置文件格式版本号，用于显式的跨版本迁移 (P1-4)
    ///
    /// # 设计原理
    /// 缺失时按 0 视为最老版本。字段级 `#[serde(default = ...)]` 只能解决
    /// 「新增字段」的向前兼容，无法处理字段语义变更或类型调整——后者会导致
    /// 旧配置直接反序列化失败，甚至更危险地被静默按默认值处理（用户配置
    /// 无声丢失）。引入显式版本号后，可在加载时按版本执行迁移链。
    #[serde(default)]
    pub config_version: u32,

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

/// Web 服务默认监听端口
pub const DEFAULT_LISTEN_PORT: u16 = 9876;

/// 全局默认同步检查间隔（秒）
pub const DEFAULT_INTERVAL_SECS: u64 = 300;

/// 强制校对云端记录默认周期轮数
pub const DEFAULT_CACHE_TIMES: u32 = 10;

/// 当前配置文件格式版本号 (P1-4)
///
/// # 版本演进约定
/// - 新增可选字段：直接以 `#[serde(default = ...)]` 兜底，无需提升版本
/// - 字段语义变更、类型调整、结构拆分：必须提升本常量并在
///   [`AppConfig::migrate`] 中追加对应的迁移步骤
pub const CURRENT_CONFIG_VERSION: u32 = 1;

/// 同步检查间隔最小允许值（秒）
pub const MIN_INTERVAL_SECS: u64 = 5;

/// 强制校对云端记录最小允许周期数
pub const MIN_CACHE_TIMES: u32 = 1;

fn default_listen_port() -> u16 {
    DEFAULT_LISTEN_PORT
}

fn default_interval_secs() -> u64 {
    DEFAULT_INTERVAL_SECS
}

fn default_cache_times() -> u32 {
    DEFAULT_CACHE_TIMES
}

fn default_not_allow_wan_access() -> bool {
    true
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            config_version: CURRENT_CONFIG_VERSION,
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
    /// 按版本号执行配置迁移链 (P1-4)
    ///
    /// # 设计原理
    /// - **实现初衷**：字段级 `#[serde(default)]` 只能兜住「新增字段」，无法
    ///   表达字段语义变更。旧版本配置在缺少显式版本标记时会被当作 version=0
    ///   处理，从而为迁移链留出唯一入口。
    /// - **核心优势**：迁移逻辑集中于此，新增版本时只需追加一个match 分支，
    ///   无需改动加载流程。
    /// - **代价与局限**：当前尚无字段需要语义迁移（v0 本身即为基线），
    ///   故本函数目前仅负责版本号归一化。迁移步骤应以
    ///   `if conf.config_version < N { ... }` 的形式追加。
    ///
    /// # 返回值
    /// 返回迁移过程中的中文提示信息（为空表示无需迁移），供调用方记录日志。
    pub fn migrate(&mut self) -> Vec<String> {
        let mut notes = Vec::new();

        if self.config_version > CURRENT_CONFIG_VERSION {
            // 高版本配置降级读取：字段级 default 兜底，但显式告警以免静默丢配置
            notes.push(format!(
                "配置文件版本号 {} 高于当前程序支持的版本 {}，可能有部分配置项未被识别而回退为默认值",
                self.config_version, CURRENT_CONFIG_VERSION
            ));
        }

        if self.config_version < CURRENT_CONFIG_VERSION {
            // 迁移步骤追加位置：按版本号升序追加
            // if self.config_version < 1 { ... }
            notes.push(format!(
                "配置已从版本 {} 迁移至版本 {}",
                self.config_version, CURRENT_CONFIG_VERSION
            ));
        }

        self.config_version = CURRENT_CONFIG_VERSION;
        notes
    }

    /// 对全量配置中的敏感凭据执行掩码化 (P1-5)
    pub fn mask_credentials(&mut self) {
        if let Some(ref mut auth) = self.auth {
            auth.password_hash.clear();
        }
        for task in &mut self.dns_tasks {
            task.provider.mask_credentials();
        }
        self.notifications.mask_credentials();
    }

    /// 保存配置时根据旧配置还原掩码凭据 (P1-5)
    pub fn restore_masked_credentials(&mut self, old: &Self) {
        for (i, new_task) in self.dns_tasks.iter_mut().enumerate() {
            let matched_old = old
                .dns_tasks
                .iter()
                .find(|t| t.name == new_task.name)
                .or_else(|| old.dns_tasks.get(i));
            if let Some(old_task) = matched_old {
                new_task
                    .provider
                    .restore_masked_credentials(&old_task.provider);
            }
        }
        self.notifications
            .restore_masked_credentials(&old.notifications);
    }

    /// 校验配置的边界与合法性
    ///
    /// # 设计原理
    /// - **实现初衷**：统一 Web API 保存、CLI 启动与直接修改磁盘文件三种场景的配置校验，消除规则双写与绕过风险 (P-8)。
    /// - **核心优势**：在系统数据边界直接拦截非法配置（覆盖数值边界、任务名唯一性、域名根解析、命令防注入、URL 协议及 Callback 安全约束），返回详尽的中文错误列表。
    /// - **代价与局限**：仅执行纯 CPU 静态规则解析；涉及网络探测与 DNS 穿透校验由 Web 层独立异步执行。
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errs = Vec::new();
        if self.interval_secs < MIN_INTERVAL_SECS {
            errs.push(format!(
                "同步检查间隔时间必须大于或等于 {} 秒，当前为 {}",
                MIN_INTERVAL_SECS, self.interval_secs
            ));
        }
        if self.cache_times < MIN_CACHE_TIMES {
            errs.push(format!(
                "强制校对云端记录间隔次数必须大于或等于 {} 次，当前为 {}",
                MIN_CACHE_TIMES, self.cache_times
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
            validate_task_item(task, &mut errs);
        }

        validate_notifications(&self.notifications, &mut errs);

        if errs.is_empty() { Ok(()) } else { Err(errs) }
    }
}

/// 校验单个 URL 的静态协议与合法格式
fn check_static_url(url: &str, field_name: &str, errs: &mut Vec<String>) {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return;
    }
    if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
        errs.push(format!(
            "{}: URL 端点 [{}] 协议非法，仅允许 http:// 或 https:// 开头的地址",
            field_name, trimmed
        ));
        return;
    }
    if let Err(e) = Url::parse(trimmed) {
        errs.push(format!("{}: URL [{}] 格式无效: {}", field_name, trimmed, e));
    }
}

/// 校验通知渠道的静态参数与协议边界
fn validate_notifications(notif: &NotificationConfig, errs: &mut Vec<String>) {
    if let Some(ref bark) = notif.bark {
        check_static_url(&bark.server_url, "Bark 通知服务器地址", errs);
    }
    if let Some(ref webhook) = notif.webhook {
        check_static_url(&webhook.url, "自定义 Webhook 地址", errs);
    }
    if let Some(ref tg) = notif.telegram
        && let Some(ref proxy) = tg.api_proxy
    {
        check_static_url(proxy, "Telegram API 代理地址", errs);
    }
    if let Some(ref wecom) = notif.wecom
        && let Some(ref webhook_url) = wecom.webhook_url
    {
        check_static_url(webhook_url, "企业微信机器人 Webhook 地址", errs);
    }
    if let Some(ref feishu) = notif.feishu {
        check_static_url(&feishu.webhook_url, "飞书机器人 Webhook 地址", errs);
    }
    if let Some(ref email) = notif.email {
        let host = email.smtp_server.trim();
        if !host.is_empty() && email.smtp_port == 0 {
            errs.push("SMTP 邮件服务器端口不能为 0".to_string());
        }
    }
}

/// 校验单个 DNS 任务中的域名、端点、命令及 Provider 静态配置边界
fn validate_task_item(task: &DnsTaskConfig, errs: &mut Vec<String>) {
    let name = task.name.trim();

    // 1. IP 提取配置与域名合法性
    for ip_cfg in [&task.ipv4, &task.ipv6] {
        if ip_cfg.enabled {
            for domain_str in &ip_cfg.domains {
                let trimmed = domain_str.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
                    continue;
                }
                if parse_domain(trimmed).is_none() {
                    errs.push(format!(
                        "任务 [{}] 配置的域名 [{}] 格式非法或无法识别根域名，请核对输入",
                        name, trimmed
                    ));
                }
            }
        }
        if ip_cfg.source_type == IpSourceType::Url {
            for url in &ip_cfg.url_endpoints {
                let trimmed = url.trim();
                if !trimmed.is_empty() {
                    check_static_url(trimmed, &format!("任务 [{}] URL 端点", name), errs);
                }
            }
        } else if ip_cfg.source_type == IpSourceType::Command {
            if let Some(ref cmd_str) = ip_cfg.cmd {
                if let Err(e) = validate_command_str(cmd_str) {
                    errs.push(format!("任务 [{}] 配置的命令无效: {}", name, e));
                }
            } else {
                errs.push(format!(
                    "任务 [{}] 配置为命令提取 IP，但未指定执行命令",
                    name
                ));
            }
        }
    }

    // 2. Callback DNS 服务商安全约束与协议校验
    if let ProviderConfig::Callback {
        ref url,
        ref method,
        ref headers,
        ref body,
    } = task.provider
    {
        let trimmed_url = url.trim();
        if trimmed_url.is_empty() {
            errs.push(format!("任务 [{}] 配置的 Callback URL 不能为空", name));
        } else {
            check_static_url(trimmed_url, &format!("任务 [{}] Callback", name), errs);
        }

        let method_upper = method.trim().to_ascii_uppercase();
        const ALLOWED_METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE"];
        if !ALLOWED_METHODS.contains(&method_upper.as_str()) {
            errs.push(format!(
                "任务 [{}] 的 Callback HTTP 方法 [{}] 不受支持，仅允许 GET、POST、PUT、PATCH、DELETE",
                name, method
            ));
        }

        if let Some(hdrs) = headers {
            for header_key in hdrs.keys() {
                let key_lower = header_key.trim().to_ascii_lowercase();
                if key_lower == "host"
                    || key_lower == "content-length"
                    || key_lower == "transfer-encoding"
                    || key_lower == "connection"
                    || key_lower == "upgrade"
                {
                    errs.push(format!(
                        "任务 [{}] 的 Callback 请求头包含高风险敏感标头 [{}]，已被安全策略禁止",
                        name, header_key
                    ));
                }
            }
        }

        const MAX_CALLBACK_BODY_BYTES: usize = 65536;
        if let Some(b) = body
            && b.len() > MAX_CALLBACK_BODY_BYTES
        {
            errs.push(format!(
                "任务 [{}] 的 Callback 请求体大小 ({} 字节) 超出 64KB 安全上限",
                name,
                b.len()
            ));
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
