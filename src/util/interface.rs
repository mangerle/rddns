use crate::util::net::{is_global_unicast_ipv6, is_public_ipv4, select_best_ipv6};
use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};
use parking_lot::RwLock;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

/// 网卡列表缓存条目 TTL 设定 (默认 3 秒，既保证网络变更及时感知，又杜绝并发系统调用风暴)
const IFACE_CACHE_TTL: Duration = Duration::from_secs(3);

#[derive(Clone)]
struct InterfacesCacheEntry {
    last_updated: Instant,
    interfaces: Vec<NetworkInterface>,
}

static SYSTEM_INTERFACES_CACHE: LazyLock<RwLock<Option<InterfacesCacheEntry>>> =
    LazyLock::new(|| RwLock::new(None));

/// 获取系统网卡列表 (带 3 秒 TTL 内存缓存以减轻内核系统调用与驱动负载)
///
/// # 设计原理
/// - **实现初衷**：`NetworkInterface::show()` 涉及底层系统调用（Windows `GetAdaptersAddresses`、Linux `/proc/net/dev` 与 `getifaddrs`），耗时可达数毫秒至数十毫秒。在多任务并发启动或高频探测时频繁裸调会导致 Tokio 工作线程延迟尖刺。
/// - **核心优势**：通过短期 TTL 缓存，在突发密集查询时实现纳秒级内存读取；TTL 过期后自动刷新，且网络状态变化能在 3 秒内平滑同步。
/// - **代价与局限**：物理网卡拔插或 IP 变更在最长 3 秒的 TTL 窗口内存在微小感知延迟，对 DDNS 周期（通常 >= 10 秒）完全无负面影响。
pub fn get_cached_system_interfaces() -> Vec<NetworkInterface> {
    // 1. 快速路径：读锁快照检查
    {
        let read_guard = SYSTEM_INTERFACES_CACHE.read();
        if let Some(ref entry) = *read_guard
            && entry.last_updated.elapsed() < IFACE_CACHE_TTL
        {
            return entry.interfaces.clone();
        }
    }

    // 2. 缓存过期或为空：在无锁状态下执行耗时的底层系统调用 (P2-1)
    let fresh_interfaces = NetworkInterface::show().unwrap_or_default();
    let now = Instant::now();

    // 3. 极小化临界区：仅在纯内存指针更新时短暂持有写锁（微秒级）
    let mut write_guard = SYSTEM_INTERFACES_CACHE.write();
    // 双重检查：若并发线程已在此期间写入更新且未过期，优先复用已缓存数据
    if let Some(ref entry) = *write_guard
        && entry.last_updated.elapsed() < IFACE_CACHE_TTL
    {
        return entry.interfaces.clone();
    }

    *write_guard = Some(InterfacesCacheEntry {
        last_updated: now,
        interfaces: fresh_interfaces.clone(),
    });
    fresh_interfaces
}

/// 清理系统网卡列表缓存 (在网络重置或测试断言时调用)
pub fn clear_system_interfaces_cache() {
    *SYSTEM_INTERFACES_CACHE.write() = None;
}

/// 根据指定网卡设备名称寻找出站 IPv4 地址 (排除 Loopback 与未指定地址)
///
/// # 设计原理
/// - **实现初衷**：在多网卡/软路由多 WAN 环境下，精确获取用户指定的出口网卡当前绑定的 IPv4 地址。
/// - **核心优势**：优先选取公网 IPv4，在无公网时安全降级为局域网首个有效地址。
pub fn find_interface_ipv4(iface_name: &str) -> Option<Ipv4Addr> {
    let interfaces = get_cached_system_interfaces();
    for iface in interfaces {
        if iface.name.eq_ignore_ascii_case(iface_name) {
            let mut fallback = None;
            for addr in iface.addr {
                if let Addr::V4(v4) = addr
                    && !v4.ip.is_loopback()
                    && !v4.ip.is_unspecified()
                {
                    if is_public_ipv4(&v4.ip) {
                        return Some(v4.ip);
                    }
                    if fallback.is_none() {
                        fallback = Some(v4.ip);
                    }
                }
            }
            if fallback.is_some() {
                return fallback;
            }
        }
    }
    None
}

/// 根据指定网卡设备名称寻找出站 IPv6 地址 (必须为全球单播地址，过滤 Link-Local 与 ULA)
///
/// # 设计原理
/// - **实现初衷**：针对双栈或纯 IPv6 宽带环境，挑选出该网卡绑定的最稳定全球单播 IPv6（避开临时隐私地址）。
pub fn find_interface_ipv6(iface_name: &str) -> Option<Ipv6Addr> {
    let interfaces = get_cached_system_interfaces();
    for iface in interfaces {
        if iface.name.eq_ignore_ascii_case(iface_name) {
            let mut v6_candidates = Vec::new();
            for addr in iface.addr {
                if let Addr::V6(v6) = addr
                    && is_global_unicast_ipv6(&v6.ip)
                {
                    v6_candidates.push(v6.ip);
                }
            }
            if let Some(best) = select_best_ipv6(&v6_candidates) {
                return Some(best);
            }
        }
    }
    None
}

/// 根据指定网卡设备名称寻找最佳出站 IP 地址 (智能优选: 公网 IPv4 > 全球单播 IPv6 > 局域网 IPv4)
///
/// # 设计原理
/// - **实现初衷**：为多 WAN 出口绑定提供通用的本地 IP 探测机制，无需外部配置即可自动选用最优出口协议。
pub fn find_interface_ip(iface_name: &str) -> Option<IpAddr> {
    let interfaces = get_cached_system_interfaces();
    for iface in interfaces {
        if iface.name.eq_ignore_ascii_case(iface_name) {
            let mut public_v4 = None;
            let mut private_v4 = None;
            let mut v6_candidates = Vec::new();

            for addr in iface.addr {
                match addr {
                    Addr::V4(v4) => {
                        if !v4.ip.is_loopback() && !v4.ip.is_unspecified() {
                            if is_public_ipv4(&v4.ip) {
                                if public_v4.is_none() {
                                    public_v4 = Some(v4.ip);
                                }
                            } else if private_v4.is_none() {
                                private_v4 = Some(v4.ip);
                            }
                        }
                    }
                    Addr::V6(v6) => {
                        if is_global_unicast_ipv6(&v6.ip) {
                            v6_candidates.push(v6.ip);
                        }
                    }
                }
            }

            // 1. 优先使用公网 IPv4
            if let Some(pub_v4) = public_v4 {
                return Some(IpAddr::V4(pub_v4));
            }

            // 2. 其次使用优选的全球单播 IPv6 (智能避开临时隐私地址)
            if let Some(best_v6) = select_best_ipv6(&v6_candidates) {
                return Some(IpAddr::V6(best_v6));
            }

            // 3. 兜底使用局域网/私网 IPv4
            if let Some(priv_v4) = private_v4 {
                return Some(IpAddr::V4(priv_v4));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_CACHE_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    #[test]
    fn test_nonexistent_interface_returns_none() {
        let ip = find_interface_ip("nonexistent_interface_999");
        assert!(ip.is_none());
        let v4 = find_interface_ipv4("nonexistent_interface_999");
        assert!(v4.is_none());
        let v6 = find_interface_ipv6("nonexistent_interface_999");
        assert!(v6.is_none());
    }

    #[test]
    fn test_cached_system_interfaces_reuses_within_ttl() {
        let _guard = TEST_CACHE_LOCK.lock();
        clear_system_interfaces_cache();

        let ifaces1 = get_cached_system_interfaces();
        let ifaces2 = get_cached_system_interfaces();
        assert_eq!(ifaces1.len(), ifaces2.len(), "缓存命中时网卡数量应完全一致");

        // 主动清理缓存后依然能正常获取
        clear_system_interfaces_cache();
        let ifaces3 = get_cached_system_interfaces();
        assert_eq!(
            ifaces1.len(),
            ifaces3.len(),
            "主动清理后重新查询仍能正常返回"
        );
    }
}
