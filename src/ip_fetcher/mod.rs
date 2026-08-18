pub mod command;
pub mod net_interface;
pub mod trait_def;
pub mod url;

pub use command::*;
pub use net_interface::*;
pub use trait_def::*;
pub use url::*;

use crate::config::model::{IpFetchConfig, IpSourceType};
use std::sync::Arc;

/// 根据配置构建具体的 IP 提取器实例 (支持绑定任务指定的出站物理网卡)
pub fn create_ip_fetcher(
    config: &IpFetchConfig,
    http_interface: Option<&str>,
) -> Option<Arc<dyn IpFetcher>> {
    if !config.enabled {
        return None;
    }

    match config.source_type {
        IpSourceType::Url => Some(Arc::new(UrlIpFetcher::new(
            config.url_endpoints.clone(),
            config.regex.clone(),
            http_interface,
        ))),
        IpSourceType::NetInterface => {
            if let Some(ref iface) = config.net_interface {
                if !iface.trim().is_empty() {
                    Some(Arc::new(NetInterfaceIpFetcher::new(
                        iface.trim().to_string(),
                        config.regex.clone(),
                    )))
                } else {
                    None
                }
            } else {
                None
            }
        }
        IpSourceType::Command => {
            if let Some(ref cmd) = config.cmd {
                if !cmd.trim().is_empty() {
                    Some(Arc::new(CommandIpFetcher::new(
                        cmd.trim().to_string(),
                        config.regex.clone(),
                        10,
                    )))
                } else {
                    tracing::warn!("配置为命令获取但指定的命令为空");
                    None
                }
            } else {
                tracing::warn!("配置为命令获取但未指定命令");
                None
            }
        }
    }
}
