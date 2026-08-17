use crate::ip_fetcher::trait_def::{FetchError, IpFetcher};
use crate::util::net::{extract_ipv4, extract_ipv6, is_global_unicast_ipv6, is_public_ipv4};
use async_trait::async_trait;
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
}

#[async_trait]
impl IpFetcher for NetInterfaceIpFetcher {
    async fn fetch_ipv4(&self) -> Result<Option<Ipv4Addr>, FetchError> {
        let interfaces = NetworkInterface::show()
            .map_err(|e| FetchError::Other(format!("获取系统网卡列表失败: {}", e)))?;

        let target_if = interfaces
            .into_iter()
            .find(|iface| iface.name.eq_ignore_ascii_case(&self.interface_name))
            .ok_or_else(|| FetchError::InterfaceNotFound(self.interface_name.clone()))?;

        for addr in target_if.addr {
            if let Addr::V4(v4_addr) = addr {
                let ip = v4_addr.ip;
                // 如果有自定义正则，优先用正则判断
                if let Some(ref re) = self.regex {
                    if let Some(matched_ip) = extract_ipv4(&ip.to_string(), Some(re)) {
                        return Ok(Some(matched_ip));
                    }
                } else if is_public_ipv4(&ip) || !ip.is_loopback() {
                    // 没有正则时返回第一个非回环 IPv4
                    return Ok(Some(ip));
                }
            }
        }

        Ok(None)
    }

    async fn fetch_ipv6(&self) -> Result<Option<Ipv6Addr>, FetchError> {
        let interfaces = NetworkInterface::show()
            .map_err(|e| FetchError::Other(format!("获取系统网卡列表失败: {}", e)))?;

        let target_if = interfaces
            .into_iter()
            .find(|iface| iface.name.eq_ignore_ascii_case(&self.interface_name))
            .ok_or_else(|| FetchError::InterfaceNotFound(self.interface_name.clone()))?;

        for addr in target_if.addr {
            if let Addr::V6(v6_addr) = addr {
                let ip = v6_addr.ip;
                // 必须是全球单播 IPv6（过滤 link-local 与 ULA）
                if is_global_unicast_ipv6(&ip) {
                    if let Some(ref re) = self.regex {
                        if let Some(matched_ip) = extract_ipv6(&ip.to_string(), Some(re)) {
                            return Ok(Some(matched_ip));
                        }
                    } else {
                        return Ok(Some(ip));
                    }
                }
            }
        }

        Ok(None)
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
