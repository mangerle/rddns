pub mod command;
pub mod net_interface;
pub mod stun;
pub mod trait_def;
pub mod url;

pub use command::*;
pub use net_interface::*;
pub use stun::*;
pub use trait_def::*;
pub use url::*;

use crate::config::model::{IpFetchConfig, IpSourceType};
use log::warn;
use std::sync::Arc;

/// 根据配置构建具体的 IP 提取器实例 (支持绑定任务指定的出站物理网卡)
///
/// # 设计原理
/// - **实现初衷**: 作为工厂方法统一解耦上层任务调度与具体探测器实现的构建细节，支持配置热加载与网卡绑定。
/// - **核心优势**: 统一管理各类数据源的参数预处理（如空白字符清理、降级校验）与线程安全 `Arc<dyn IpFetcher>` 包装。
/// - **代价与局限**: 返回特征对象（Trait Object）产生轻微的虚表分发（vtable dispatch）开销。
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
        IpSourceType::Stun => Some(Arc::new(StunIpFetcher::new(
            config.stun_server.clone(),
            http_interface,
        ))),
        IpSourceType::NetInterface => config
            .net_interface
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|iface| {
                Arc::new(NetInterfaceIpFetcher::new(
                    iface.to_string(),
                    config.regex.clone(),
                )) as Arc<dyn IpFetcher>
            }),
        IpSourceType::Command => match config.cmd.as_deref().map(str::trim) {
            Some(cmd) if !cmd.is_empty() => Some(Arc::new(CommandIpFetcher::new(
                cmd.to_string(),
                config.regex.clone(),
                10,
            ))),
            Some(_) => {
                warn!("配置为命令获取但指定的命令为空");
                None
            }
            None => {
                warn!("配置为命令获取但未指定命令");
                None
            }
        },
    }
}
