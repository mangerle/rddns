use crate::ip_fetcher::linux_inet6::{
    LinuxIfInet6Entry, read_linux_if_inet6, sort_linux_interface_ipv6s,
};
use crate::ip_fetcher::trait_def::{FetchError, IpFetcher};
use crate::util::net::{
    extract_ipv4, extract_ipv6, is_global_unicast_ipv6, is_public_ipv4, select_best_ipv6,
};
use async_trait::async_trait;
use log::warn;
use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::task::spawn_blocking;

/// 基于本地网卡设备提取 IP
pub struct NetInterfaceIpFetcher {
    interface_name: String,
    regex: Option<String>,
}

impl NetInterfaceIpFetcher {
    /// 创建网卡 IP 提取器
    ///
    /// # 设计原理
    /// - **实现初衷**: 适用于具有公网 IPv4 或原生运营商公网 IPv6 直接分配到主机的环境（如光猫桥接软路由、VPS、原生双栈服务器），无需向外部服务发起 HTTP/STUN 探测。
    /// - **核心优势**: 零网络请求开销、探测纳秒级响应，并在 Linux 平台深度对接 `/proc/net/if_inet6` 解析内核地址标志，优先提取稳定非废弃的全球单播 IPv6。
    /// - **代价与局限**: 若主机处于多层 NAT 内网且未分配公网 IP，本提取器只能获取到内网局域网私网 IP，无法探测公网反射 IP。
    pub fn new(interface_name: String, regex: Option<String>) -> Self {
        Self {
            interface_name,
            regex,
        }
    }

    /// 异步查找并获取指定名称的目标网卡设备 (移入后台阻塞线程池)
    async fn get_target_interface(&self) -> Result<NetworkInterface, FetchError> {
        let name = self.interface_name.clone();
        spawn_blocking(move || {
            let interfaces = NetworkInterface::show()
                .map_err(|e| FetchError::Other(format!("获取系统网卡列表失败: {}", e)))?;

            interfaces
                .into_iter()
                .find(|iface| iface.name.eq_ignore_ascii_case(&name))
                .ok_or_else(|| FetchError::InterfaceNotFound(name))
        })
        .await
        .map_err(|e| FetchError::Other(format!("异步执行网卡查询任务失败: {}", e)))?
    }

    /// 从 Linux `/proc/net/if_inet6` 读取指定网卡的 IPv6 候选集并按稳定性排序
    async fn collect_linux_ipv6_candidates(if_name: &str) -> Option<Vec<Ipv6Addr>> {
        let target_name = if_name.to_string();
        let entries = spawn_blocking(move || read_linux_if_inet6(Some(&target_name)))
            .await
            .unwrap_or(None)?;

        let mut stable = Vec::new();
        let mut temp = Vec::new();
        for entry in entries {
            if entry.is_stable_global() {
                stable.push(entry.ip);
            } else if entry.is_global_scope()
                && !entry.is_deprecated()
                && !entry.is_tentative_or_failed()
                && is_global_unicast_ipv6(&entry.ip)
            {
                temp.push(entry.ip);
            }
        }

        let mut candidates = Vec::new();
        if let Some(best) = select_best_ipv6(&stable) {
            candidates.push(best);
            for ip in stable {
                if ip != best {
                    candidates.push(ip);
                }
            }
        } else {
            candidates.extend(stable);
        }

        for ip in temp {
            if !candidates.contains(&ip) {
                candidates.push(ip);
            }
        }
        Some(candidates)
    }

    /// 跨平台从网卡绑定地址列表中提取并优选全球单播 IPv6 候选集
    fn collect_fallback_ipv6_candidates(target_if: &NetworkInterface) -> Vec<Ipv6Addr> {
        let mut raw_addrs = Vec::new();
        for addr in &target_if.addr {
            if let Addr::V6(v6_addr) = addr {
                let ip = v6_addr.ip;
                if is_global_unicast_ipv6(&ip) {
                    raw_addrs.push(ip);
                }
            }
        }

        if let Some(best) = select_best_ipv6(&raw_addrs) {
            let mut candidates = Vec::with_capacity(raw_addrs.len());
            candidates.push(best);
            for ip in raw_addrs {
                if ip != best {
                    candidates.push(ip);
                }
            }
            candidates
        } else {
            raw_addrs
        }
    }
}

#[async_trait]
impl IpFetcher for NetInterfaceIpFetcher {
    async fn fetch_ipv4(&self) -> Result<Option<Ipv4Addr>, FetchError> {
        let target_if = self.get_target_interface().await?;

        let mut candidates = Vec::new();
        for addr in target_if.addr {
            if let Addr::V4(v4_addr) = addr {
                let ip = v4_addr.ip;
                if !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified() {
                    candidates.push(ip);
                }
            }
        }

        if let Some(ref r) = self.regex {
            if let Some(ip) = select_ip_by_ordinal_or_regex(&candidates, Some(r), |t, re| {
                extract_ipv4(t, Some(re))
            }) {
                return Ok(Some(ip));
            }
        } else if let Some(&pub_ip) = candidates.iter().find(|ip| is_public_ipv4(ip)) {
            return Ok(Some(pub_ip));
        } else if let Some(&first) = candidates.first() {
            return Ok(Some(first));
        }

        Ok(None)
    }

    async fn fetch_ipv6(&self) -> Result<Option<Ipv6Addr>, FetchError> {
        let target_if = self.get_target_interface().await?;

        // 1. Linux 环境：优先尝试从 /proc/net/if_inet6 精准读取并构建有序候选集
        let mut candidates = Self::collect_linux_ipv6_candidates(&target_if.name)
            .await
            .unwrap_or_default();

        // 2. 跨平台通用兜底（非 Linux 环境，或 Linux 下 procfs 解析为空/网卡别名无法匹配时）
        if candidates.is_empty() {
            candidates = Self::collect_fallback_ipv6_candidates(&target_if);
        }

        if let Some(ref r) = self.regex {
            Ok(select_ip_by_ordinal_or_regex(
                &candidates,
                Some(r),
                |t, re| extract_ipv6(t, Some(re)),
            ))
        } else {
            Ok(candidates.first().copied())
        }
    }
}

/// 依据序号 (@n) 或正则表达式从候选 IP 列表中筛选目标 IP
///
/// # 参数
/// - `candidates`: 候选 IP 列表
/// - `rule`: 规则字符串，支持 `@1` / `@2` 序号索引语法，或标准正则表达式
/// - `custom_extractor`: 自定义提取回调函数
pub fn select_ip_by_ordinal_or_regex<T: Clone + Display>(
    candidates: &[T],
    rule: Option<&str>,
    custom_extractor: impl Fn(&str, &str) -> Option<T>,
) -> Option<T> {
    if candidates.is_empty() {
        return None;
    }

    if let Some(r) = rule {
        let trimmed = r.trim();
        // 匹配 @1, @2, @N 序号语法 (从 1 开始计)
        if let Some(rest) = trimmed.strip_prefix('@')
            && let Ok(idx) = rest.parse::<usize>()
        {
            return if idx == 0 {
                warn!("指定的序号 @0 非法（序号从 @1 开始），将回退使用第 1 个地址");
                Some(candidates[0].clone())
            } else if idx <= candidates.len() {
                Some(candidates[idx - 1].clone())
            } else {
                warn!(
                    "指定的序号 @{} 超出可用 IP 数量 ({})，将回退使用第 1 个地址",
                    idx,
                    candidates.len()
                );
                Some(candidates[0].clone())
            };
        }

        // 普通正则表达式匹配
        for ip in candidates {
            if let Some(matched) = custom_extractor(&ip.to_string(), trimmed) {
                return Some(matched);
            }
        }
        None
    } else {
        None
    }
}

/// 网卡信息结构体
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceInfo {
    pub name: String,
    pub display_name: String,
    pub ipv4s: Vec<String>,
    pub ipv6s: Vec<String>,
}

/// 构建单个网卡的信息展示对象
fn build_interface_info(
    iface: NetworkInterface,
    linux_entries: Option<&[LinuxIfInet6Entry]>,
) -> InterfaceInfo {
    let mut ipv4s = Vec::new();
    let mut ipv6s = Vec::new();
    for addr in &iface.addr {
        match addr {
            Addr::V4(v4) => {
                let ip = v4.ip;
                if !ip.is_loopback() {
                    ipv4s.push(ip.to_string());
                }
            }
            Addr::V6(v6) => {
                let ip = v6.ip;
                if is_global_unicast_ipv6(&ip) {
                    ipv6s.push(ip.to_string());
                }
            }
        }
    }

    if let Some(all_entries) = linux_entries {
        ipv6s = sort_linux_interface_ipv6s(&iface.name, ipv6s, all_entries);
    }

    let mut desc_parts = Vec::new();
    if !ipv4s.is_empty() {
        desc_parts.push(format!("IPv4: {}", ipv4s.join(", ")));
    }
    if !ipv6s.is_empty() {
        desc_parts.push(format!("IPv6: {}", ipv6s.join(", ")));
    }
    let display_name = if desc_parts.is_empty() {
        iface.name.clone()
    } else {
        format!("{} ({})", iface.name, desc_parts.join(" | "))
    };

    InterfaceInfo {
        name: iface.name,
        display_name,
        ipv4s,
        ipv6s,
    }
}

/// 枚举当前系统上所有可用的物理与虚拟网卡
pub fn list_system_interfaces() -> Vec<InterfaceInfo> {
    let linux_entries = read_linux_if_inet6(None);
    match NetworkInterface::show() {
        Ok(interfaces) => interfaces
            .into_iter()
            .map(|iface| build_interface_info(iface, linux_entries.as_deref()))
            .collect(),
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_select_ip_by_ordinal() {
        let ip1 = Ipv6Addr::from_str("2408:8207:78cd:1234::1").unwrap();
        let ip2 = Ipv6Addr::from_str("2408:8207:78cd:1234::2").unwrap();
        let ip3 = Ipv6Addr::from_str("2408:8207:78cd:1234::3").unwrap();
        let candidates = vec![ip1, ip2, ip3];

        // @0 非法序号回退到第 1 个
        let sel0 = select_ip_by_ordinal_or_regex(&candidates, Some("@0"), |t, re| {
            extract_ipv6(t, Some(re))
        });
        assert_eq!(sel0, Some(ip1));

        // @1 选第 1 个
        let sel1 = select_ip_by_ordinal_or_regex(&candidates, Some("@1"), |t, re| {
            extract_ipv6(t, Some(re))
        });
        assert_eq!(sel1, Some(ip1));

        // @2 选第 2 个
        let sel2 = select_ip_by_ordinal_or_regex(&candidates, Some("@2"), |t, re| {
            extract_ipv6(t, Some(re))
        });
        assert_eq!(sel2, Some(ip2));

        // @3 选第 3 个
        let sel3 = select_ip_by_ordinal_or_regex(&candidates, Some("@3"), |t, re| {
            extract_ipv6(t, Some(re))
        });
        assert_eq!(sel3, Some(ip3));

        // 超出索引回退到第 1 个
        let sel_overflow = select_ip_by_ordinal_or_regex(&candidates, Some("@99"), |t, re| {
            extract_ipv6(t, Some(re))
        });
        assert_eq!(sel_overflow, Some(ip1));

        // 正则表达式匹配
        let sel_regex = select_ip_by_ordinal_or_regex(&candidates, Some(".*::2"), |t, re| {
            extract_ipv6(t, Some(re))
        });
        assert_eq!(sel_regex, Some(ip2));
    }
}
