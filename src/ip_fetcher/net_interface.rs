use crate::ip_fetcher::trait_def::{FetchError, IpFetcher};
use crate::util::net::{
    extract_ipv4, extract_ipv6, is_global_unicast_ipv6, is_public_ipv4, select_best_ipv6,
};
use async_trait::async_trait;
use log::warn;
use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};
use std::net::{Ipv4Addr, Ipv6Addr};

/// 基于本地网卡设备提取 IP
pub struct NetInterfaceIpFetcher {
    interface_name: String,
    regex: Option<String>,
}

impl NetInterfaceIpFetcher {
    pub fn new(interface_name: String, regex: Option<String>) -> Self {
        Self {
            interface_name,
            regex,
        }
    }

    /// 查找并获取指定名称的目标网卡设备
    fn get_target_interface(&self) -> Result<NetworkInterface, FetchError> {
        let interfaces = NetworkInterface::show()
            .map_err(|e| FetchError::Other(format!("获取系统网卡列表失败: {}", e)))?;

        interfaces
            .into_iter()
            .find(|iface| iface.name.eq_ignore_ascii_case(&self.interface_name))
            .ok_or_else(|| FetchError::InterfaceNotFound(self.interface_name.clone()))
    }
}

#[async_trait]
impl IpFetcher for NetInterfaceIpFetcher {
    async fn fetch_ipv4(&self) -> Result<Option<Ipv4Addr>, FetchError> {
        let target_if = self.get_target_interface()?;

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
        let target_if = self.get_target_interface()?;

        let mut candidates = Vec::new();

        for addr in target_if.addr {
            if let Addr::V6(v6_addr) = addr {
                let ip = v6_addr.ip;
                // 必须是全球单播 IPv6（过滤 link-local 与 ULA）
                if is_global_unicast_ipv6(&ip) {
                    candidates.push(ip);
                }
            }
        }

        if let Some(ref r) = self.regex {
            if let Some(ip) = select_ip_by_ordinal_or_regex(&candidates, Some(r), |t, re| {
                extract_ipv6(t, Some(re))
            }) {
                return Ok(Some(ip));
            }
        } else if let Some(best_ip) = select_best_ipv6(&candidates) {
            return Ok(Some(best_ip));
        }

        Ok(None)
    }
}

/// 依据序号 (@n) 或正则表达式从候选 IP 列表中筛选目标 IP
pub fn select_ip_by_ordinal_or_regex<T: Clone + std::fmt::Display>(
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
            if idx >= 1 && idx <= candidates.len() {
                return Some(candidates[idx - 1].clone());
            } else if idx > candidates.len() {
                warn!(
                    "指定的序号 @{} 超出可用 IP 数量 ({})，将回退使用第 1 个地址",
                    idx,
                    candidates.len()
                );
                return Some(candidates[0].clone());
            }
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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InterfaceInfo {
    pub name: String,
    pub display_name: String,
    pub ipv4s: Vec<String>,
    pub ipv6s: Vec<String>,
}

/// 枚举当前系统上所有可用的物理与虚拟网卡
pub fn list_system_interfaces() -> Vec<InterfaceInfo> {
    let mut result = Vec::new();
    if let Ok(interfaces) = NetworkInterface::show() {
        for iface in interfaces {
            let mut ipv4s = Vec::new();
            let mut ipv6s = Vec::new();
            for addr in iface.addr {
                match addr {
                    Addr::V4(v4) => {
                        let ip = v4.ip;
                        if !ip.is_loopback() {
                            ipv4s.push(ip.to_string());
                        }
                    }
                    Addr::V6(v6) => {
                        let ip = v6.ip;
                        if is_global_unicast_ipv6(&ip) || !ip.is_loopback() {
                            ipv6s.push(ip.to_string());
                        }
                    }
                }
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
            result.push(InterfaceInfo {
                name: iface.name,
                display_name,
                ipv4s,
                ipv6s,
            });
        }
    }
    result
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
