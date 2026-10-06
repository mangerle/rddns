use crate::ip_fetcher::linux_inet6::{
    LinuxIfInet6Entry, read_linux_if_inet6, sort_linux_interface_ipv6s,
};
use crate::ip_fetcher::trait_def::{FetchError, IpFetcher};
use crate::util::interface::get_cached_system_interfaces;
use crate::util::net::{
    extract_ipv4, extract_ipv6, is_global_unicast_ipv6, is_public_ipv4, select_best_ipv6,
};
use async_trait::async_trait;
use log::warn;
use network_interface::{Addr, NetworkInterface};
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::task::spawn_blocking;
use tokio::time::{Duration, timeout};

/// 网卡阻塞系统调用查询超时时间 (P2-2)
const INTERFACE_OP_TIMEOUT: Duration = Duration::from_secs(3);

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

    /// 异步查找并获取指定名称的目标网卡设备 (移入后台阻塞线程池并附加超时保护，复用带 TTL 的系统网卡缓存)
    async fn get_target_interface(&self) -> Result<NetworkInterface, FetchError> {
        let name = self.interface_name.clone();
        timeout(
            INTERFACE_OP_TIMEOUT,
            spawn_blocking(move || {
                let interfaces = get_cached_system_interfaces();

                interfaces
                    .into_iter()
                    .find(|iface| iface.name.eq_ignore_ascii_case(&name))
                    .ok_or(FetchError::InterfaceNotFound(name))
            }),
        )
        .await
        .map_err(|_| FetchError::Other("查询网卡设备超时 (超过 3 秒)".to_string()))?
        .map_err(|e| FetchError::Other(format!("异步执行网卡查询任务失败: {}", e)))?
    }

    /// 从 Linux `/proc/net/if_inet6` 读取指定网卡的 IPv6 候选集并按稳定性排序
    async fn collect_linux_ipv6_candidates(if_name: &str) -> Option<Vec<Ipv6Addr>> {
        let target_name = if_name.to_string();
        let entries = timeout(
            INTERFACE_OP_TIMEOUT,
            spawn_blocking(move || read_linux_if_inet6(Some(&target_name))),
        )
        .await
        .ok()
        .and_then(|res| res.unwrap_or(None))?;

        let entries_count = entries.len();
        let mut stable = Vec::with_capacity(entries_count);
        let mut temp = Vec::with_capacity(entries_count);
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

        let mut candidates = Vec::with_capacity(stable.len() + temp.len());
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
        let mut raw_addrs = Vec::with_capacity(target_if.addr.len());
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
    /// 探测指定网卡的公网 IPv4 地址
    ///
    /// # 公网地址校验契约 (P1-5)
    /// 无论走自定义正则还是默认筛选分支，返回值**必然**满足
    /// [`is_public_ipv4`]。本项目其余三个探测器（`url.rs` / `command.rs` /
    /// `stun.rs`）均强制执行该校验；原实现却在无公网地址时回退返回首个
    /// 私网地址，会把 RFC1918 地址提交到公网 DNS，导致域名对外完全不可达。
    /// 此处必须与三者保持一致：无公网地址时返回 `Ok(None)`，交由上层按
    /// 探测失败处理（累加失败计数、退避、告警），而非静默写入无效记录。
    async fn fetch_ipv4(&self) -> Result<Option<Ipv4Addr>, FetchError> {
        let target_if = self.get_target_interface().await?;

        let mut candidates = Vec::with_capacity(target_if.addr.len());
        for addr in target_if.addr {
            if let Addr::V4(v4_addr) = addr {
                let ip = v4_addr.ip;
                if !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified() {
                    candidates.push(ip);
                }
            }
        }

        // 正则分支同样必须受公网校验约束：正则仅用于从候选集中挑选，
        // 不得成为绕过公网地址限制的旁路 (P1-5)
        Ok(select_public_ipv4(&candidates, self.regex.as_deref()))
    }

    /// 探测指定网卡的公网 IPv6 地址
    ///
    /// # 公网地址校验契约 (P1-5)
    /// 与 IPv4 分支保持一致，仅返回全球单播地址（[`is_global_unicast_ipv6`]），
    /// 拒绝 ULA(fc00::/7)、链路本地(fe80::/10) 等内网地址。
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

        // 候选集已由 select_best_ipv6 完成优选，此处仅需做公网性兜底校验 (P1-5)
        if let Some(ref r) = self.regex {
            Ok(
                select_ip_by_ordinal_or_regex(&candidates, Some(r), |t, re| {
                    extract_ipv6(t, Some(re))
                })
                .filter(is_global_unicast_ipv6),
            )
        } else {
            Ok(candidates.first().copied().filter(is_global_unicast_ipv6))
        }
    }
}

/// 从候选集中挑选出公网可达的 IPv4 地址 (P1-5)
///
/// # 设计原理
/// 抽为独立纯函数以便可脱离真实网卡环境直接单元测试。
///
/// # 不变式保证
/// 返回值**必然**满足 [`is_public_ipv4`]，无公网地址时返回 `None`。
/// 严禁在此处回退返回首个私网地址——那会把 RFC1918 地址提交到公网 DNS，
/// 使域名对外完全不可达。无公网地址时交由上层按探测失败处理（累加失败
/// 计数、指数退避、告警），而非静默写入无效记录。
pub fn select_public_ipv4(candidates: &[Ipv4Addr], regex: Option<&str>) -> Option<Ipv4Addr> {
    match regex {
        // 正则分支：先按用户规则从候选集中挑选，再对挑选结果做公网校验。
        // 正则仅决定「挑哪个」，绝不可决定「是否受公网约束」。
        Some(r) => {
            select_ip_by_ordinal_or_regex(candidates, Some(r), |t, re| extract_ipv4(t, Some(re)))
                .filter(is_public_ipv4)
        }
        // 无正则分支：取首个公网地址。不可直接取 candidates.first()，
        // 否则私网地址排在首位时会被误选并提交到公网 DNS。
        None => candidates.iter().copied().find(is_public_ipv4),
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
    let addr_count = iface.addr.len();
    let mut ipv4s = Vec::with_capacity(addr_count);
    let mut ipv6s = Vec::with_capacity(addr_count);
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

    let mut desc_parts = Vec::with_capacity(2);
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

/// 枚举当前系统上所有可用的物理与虚拟网卡 (复用带 TTL 的系统网卡内存缓存以减轻底层系统调用)
pub fn list_system_interfaces() -> Vec<InterfaceInfo> {
    let linux_entries = read_linux_if_inet6(None);
    let interfaces = get_cached_system_interfaces();
    interfaces
        .into_iter()
        .map(|iface| build_interface_info(iface, linux_entries.as_deref()))
        .collect()
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
    fn test_select_public_ipv4_never_returns_private_address() {
        // 回归用例 (P1-5)：原实现在无公网地址时回退返回 `candidates.first()`，
        // 会把 RFC1918 私网地址提交到公网 DNS，使域名对外完全不可达。
        // 本用例锁死契约：无公网地址时必须返回 None。
        use std::net::Ipv4Addr;

        // 典型家庭/内网网段
        let private_only = vec![
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(172, 16, 3, 4),
        ];
        assert_eq!(
            select_public_ipv4(&private_only, None),
            None,
            "纯私网候选集绝不可返回任何地址"
        );

        // CGNAT 段（100.64.0.0/10）同样不属于公网可解析地址
        let cgnat = vec![Ipv4Addr::new(100, 64, 1, 1)];
        assert_eq!(
            select_public_ipv4(&cgnat, None),
            None,
            "CGNAT 地址不得作为公网 IPv4 返回"
        );

        // 空候选集
        assert_eq!(select_public_ipv4(&[], None), None);
    }

    #[test]
    fn test_select_public_ipv4_returns_public_address() {
        use std::net::Ipv4Addr;

        // 混合候选集：文档保留段在前、真实公网段在后
        let mixed = vec![
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(203, 0, 113, 9),
        ];
        // 203.0.113.0/24 属 RFC 6890 文档保留段，不可路由，应被拒绝
        assert_eq!(select_public_ipv4(&mixed, None), None);

        // 混入可路由公网段后应正确选出
        let with_public = vec![Ipv4Addr::new(192, 168, 1, 100), Ipv4Addr::new(8, 8, 8, 8)];
        assert_eq!(
            select_public_ipv4(&with_public, None),
            Some(Ipv4Addr::new(8, 8, 8, 8))
        );
    }

    #[test]
    fn test_select_public_ipv4_regex_cannot_bypass_validation() {
        // 回归用例 (P1-5)：正则仅用于从候选集中挑选，
        // 绝不可成为绕过公网地址限制的旁路
        use std::net::Ipv4Addr;

        let private_only = vec![Ipv4Addr::new(192, 168, 1, 100), Ipv4Addr::new(10, 0, 0, 5)];

        // 正则命中私网地址时必须被公网校验拦截
        assert_eq!(
            select_public_ipv4(&private_only, Some(r"192\.168\..*")),
            None,
            "正则命中私网地址时不得绕过公网校验"
        );
        assert_eq!(
            select_public_ipv4(&private_only, Some(r"10\..*")),
            None,
            "正则命中私网地址时不得绕过公网校验"
        );
    }
}
