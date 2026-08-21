use crate::ip_fetcher::trait_def::{FetchError, IpFetcher};
use crate::util::net::{
    extract_ipv4, extract_ipv6, is_global_unicast_ipv6, is_public_ipv4, select_best_ipv6,
};
use async_trait::async_trait;
use log::warn;
use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

/// Linux 内核 IPv6 地址标志位常量 (定义于 include/uapi/linux/if_addr.h，使用 32 位掩码避免高位溢出)
pub const IFA_F_TEMPORARY: u32 = 0x01; // RFC 4941 临时隐私地址
pub const IFA_F_DADFAILED: u32 = 0x08; // DAD 冲突检测失败
pub const IFA_F_DEPRECATED: u32 = 0x20; // 已过期的废弃地址
pub const IFA_F_TENTATIVE: u32 = 0x40; // DAD 冲突检测中

/// Linux `/proc/net/if_inet6` 单条 IPv6 地址条目
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxIfInet6Entry {
    pub ip: Ipv6Addr,
    pub if_index: u32,
    pub prefix_len: u8,
    pub scope: u8,
    pub flags: u32,
    pub if_name: String,
}

impl LinuxIfInet6Entry {
    /// 是否为全球单播作用域 (Scope 0x00)
    pub fn is_global_scope(&self) -> bool {
        self.scope == 0x00
    }

    /// 是否为临时隐私地址 (IFA_F_TEMPORARY = 0x01)
    pub fn is_temporary(&self) -> bool {
        (self.flags & IFA_F_TEMPORARY) != 0
    }

    /// 是否已废弃 (IFA_F_DEPRECATED = 0x20)
    pub fn is_deprecated(&self) -> bool {
        (self.flags & IFA_F_DEPRECATED) != 0
    }

    /// 是否处于 DAD 探测或失败状态 (IFA_F_TENTATIVE = 0x40 或 IFA_F_DADFAILED = 0x08)
    pub fn is_tentative_or_failed(&self) -> bool {
        (self.flags & (IFA_F_TENTATIVE | IFA_F_DADFAILED)) != 0
    }

    /// 是否为适合入站 DDNS 的稳定全球单播地址 (非临时、未废弃、非冲突且为全球单播)
    pub fn is_stable_global(&self) -> bool {
        self.is_global_scope()
            && !self.is_temporary()
            && !self.is_deprecated()
            && !self.is_tentative_or_failed()
            && is_global_unicast_ipv6(&self.ip)
    }
}

/// 解析单行 `/proc/net/if_inet6` 内容
/// 格式示例：`2408820778cd12340200f8fffed144ff 02 40 00 80 eth0`
pub fn parse_if_inet6_line(line: &str) -> Option<LinuxIfInet6Entry> {
    let mut parts = line.split_whitespace();
    let hex_ip = parts.next()?;
    let hex_ifindex = parts.next()?;
    let hex_prefix = parts.next()?;
    let hex_scope = parts.next()?;
    let hex_flags = parts.next()?;
    let if_name = parts.next()?;

    if hex_ip.len() != 32 {
        return None;
    }

    let mut segments = [0u16; 8];
    for i in 0..8 {
        segments[i] = u16::from_str_radix(&hex_ip[i * 4..(i + 1) * 4], 16).ok()?;
    }
    let ip = Ipv6Addr::new(
        segments[0],
        segments[1],
        segments[2],
        segments[3],
        segments[4],
        segments[5],
        segments[6],
        segments[7],
    );

    let if_index = u32::from_str_radix(hex_ifindex, 16).ok()?;
    let prefix_len = u8::from_str_radix(hex_prefix, 16).ok()?;
    let scope = u8::from_str_radix(hex_scope, 16).ok()?;
    let flags = u32::from_str_radix(hex_flags, 16).ok()?;

    Some(LinuxIfInet6Entry {
        ip,
        if_index,
        prefix_len,
        scope,
        flags,
        if_name: if_name.to_string(),
    })
}

/// 从 `/proc/net/if_inet6` 文本中解析指定网卡的所有 IPv6 条目
pub fn parse_if_inet6_content(
    content: &str,
    target_ifname: Option<&str>,
) -> Vec<LinuxIfInet6Entry> {
    content
        .lines()
        .filter_map(parse_if_inet6_line)
        .filter(|entry| {
            if let Some(target) = target_ifname {
                entry.if_name.eq_ignore_ascii_case(target)
            } else {
                true
            }
        })
        .collect()
}

/// 读取并解析 Linux 系统 `/proc/net/if_inet6` 文件（仅在 Linux 或文件存在时有效）
pub fn read_linux_if_inet6(target_ifname: Option<&str>) -> Option<Vec<LinuxIfInet6Entry>> {
    let content = fs::read_to_string(Path::new("/proc/net/if_inet6")).ok()?;
    Some(parse_if_inet6_content(&content, target_ifname))
}

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

    /// 异步查找并获取指定名称的目标网卡设备 (移入后台阻塞线程池)
    async fn get_target_interface(&self) -> Result<NetworkInterface, FetchError> {
        let name = self.interface_name.clone();
        tokio::task::spawn_blocking(move || {
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

        let mut candidates = Vec::new();

        // 1. Linux 环境：优先尝试从 /proc/net/if_inet6 精准读取并构建有序候选集
        if let Some(entries) = read_linux_if_inet6(Some(&target_if.name)) {
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
                    // 仅将健康的临时隐私地址加入备选，明确排除已废弃和 DAD 冲突中的地址
                    temp.push(entry.ip);
                }
            }

            // 稳定集合内部再做一次启发式优选置顶 (优先 EUI-64 与静态分配短后缀)
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

            // 追加健康的临时全球单播备选
            for ip in temp {
                if !candidates.contains(&ip) {
                    candidates.push(ip);
                }
            }
        }

        // 2. 跨平台通用兜底（非 Linux 环境，或 Linux 下 procfs 解析为空/网卡别名无法匹配时）
        if candidates.is_empty() {
            let mut raw_addrs = Vec::new();
            for addr in target_if.addr {
                if let Addr::V6(v6_addr) = addr {
                    let ip = v6_addr.ip;
                    if is_global_unicast_ipv6(&ip) {
                        raw_addrs.push(ip);
                    }
                }
            }
            if let Some(best) = select_best_ipv6(&raw_addrs) {
                candidates.push(best);
                for ip in raw_addrs {
                    if ip != best {
                        candidates.push(ip);
                    }
                }
            } else {
                candidates = raw_addrs;
            }
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
    let linux_entries = read_linux_if_inet6(None);

    if let Ok(interfaces) = NetworkInterface::show() {
        for iface in interfaces {
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

            // 如果在 Linux 下读取到了 if_inet6 信息，对 ipv6s 按照稳定性重排（稳定地址排在最前面）
            if let Some(ref all_entries) = linux_entries {
                let if_entries: Vec<&LinuxIfInet6Entry> = all_entries
                    .iter()
                    .filter(|e| e.if_name.eq_ignore_ascii_case(&iface.name))
                    .collect();

                if !if_entries.is_empty() {
                    let mut sorted_v6 = Vec::new();
                    let mut push_unique = |ip_str: String| {
                        if !sorted_v6.contains(&ip_str) {
                            sorted_v6.push(ip_str);
                        }
                    };

                    // 1. 优先加入稳定全球单播地址
                    for e in if_entries.iter().filter(|e| e.is_stable_global()) {
                        push_unique(e.ip.to_string());
                    }
                    // 2. 其次加入健康的临时全球单播地址 (排除废弃与 DAD 冲突)
                    for e in if_entries.iter().filter(|e| {
                        e.is_global_scope()
                            && !e.is_stable_global()
                            && !e.is_deprecated()
                            && !e.is_tentative_or_failed()
                    }) {
                        push_unique(e.ip.to_string());
                    }
                    // 3. 补充其它非全局单播
                    for v6_str in ipv6s {
                        push_unique(v6_str);
                    }
                    ipv6s = sorted_v6;
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

    #[test]
    fn test_parse_if_inet6_line() {
        // 永久稳定公网 IPv6
        let line_perm = "2408820778cd12340200f8fffed144ff 02 40 00 80 eth0";
        let entry_perm = parse_if_inet6_line(line_perm).expect("解析失败");
        assert_eq!(
            entry_perm.ip,
            Ipv6Addr::from_str("2408:8207:78cd:1234:200:f8ff:fed1:44ff").unwrap()
        );
        assert_eq!(entry_perm.if_index, 2);
        assert_eq!(entry_perm.prefix_len, 64);
        assert_eq!(entry_perm.scope, 0);
        assert_eq!(entry_perm.flags, 0x80);
        assert_eq!(entry_perm.if_name, "eth0");
        assert!(entry_perm.is_stable_global());
        assert!(!entry_perm.is_temporary());
        assert!(!entry_perm.is_deprecated());

        // 现代内核高位 Stable Privacy IPv6 (flags 0x880，超过 u8 范围)
        let line_high_flags = "2408820778cd12340200f8fffed144ff 02 40 00 880 eth0";
        let entry_high = parse_if_inet6_line(line_high_flags).expect("高位 Flags 解析失败");
        assert_eq!(entry_high.flags, 0x880);
        assert!(entry_high.is_stable_global());

        // 临时隐私 IPv6 (flags 0x01)
        let line_temp = "2408820778cd1234a5d34199c03b1234 02 40 00 01 eth0";
        let entry_temp = parse_if_inet6_line(line_temp).expect("解析失败");
        assert!(entry_temp.is_temporary());
        assert!(!entry_temp.is_stable_global());

        // 废弃 IPv6 (flags 0x20)
        let line_dep = "2408820778cd1234b4c23100a12b5678 02 40 00 20 eth0";
        let entry_dep = parse_if_inet6_line(line_dep).expect("解析失败");
        assert!(entry_dep.is_deprecated());
        assert!(!entry_dep.is_stable_global());

        // DAD 探测中 IPv6 (flags 0x40)
        let line_tent = "2408820778cd12341111222233334444 02 40 00 40 eth0";
        let entry_tent = parse_if_inet6_line(line_tent).expect("解析失败");
        assert!(entry_tent.is_tentative_or_failed());
        assert!(!entry_tent.is_stable_global());

        // 链路本地 fe80:: (scope 0x20)
        let line_ll = "fe800000000000000200f8fffed144ff 02 40 20 80 eth0";
        let entry_ll = parse_if_inet6_line(line_ll).expect("解析失败");
        assert!(!entry_ll.is_global_scope());
        assert!(!entry_ll.is_stable_global());
    }

    #[test]
    fn test_parse_if_inet6_content_filtering() {
        let content = r#"
00000000000000000000000000000001 01 80 10 80       lo
2408820778cd12340200f8fffed144ff 02 40 00 80     eth0
2408820778cd1234a5d34199c03b1234 02 40 00 01     eth0
2408820778cd1234b4c23100a12b5678 02 40 00 20     eth0
fe800000000000000200f8fffed144ff 02 40 20 80     eth0
24098900123456780000000000000001 03 40 00 880    wlan0
"#;

        let entries_eth0 = parse_if_inet6_content(content, Some("eth0"));
        assert_eq!(entries_eth0.len(), 4);

        let stable_eth0: Vec<Ipv6Addr> = entries_eth0
            .iter()
            .filter(|e| e.is_stable_global())
            .map(|e| e.ip)
            .collect();
        assert_eq!(stable_eth0.len(), 1);
        assert_eq!(
            stable_eth0[0],
            Ipv6Addr::from_str("2408:8207:78cd:1234:200:f8ff:fed1:44ff").unwrap()
        );

        let entries_wlan0 = parse_if_inet6_content(content, Some("wlan0"));
        assert_eq!(entries_wlan0.len(), 1);
        assert_eq!(entries_wlan0[0].flags, 0x880);
        assert!(entries_wlan0[0].is_stable_global());
    }
}
