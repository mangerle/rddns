use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// 全局跳过 TLS 证书验证开关
static SKIP_VERIFY: AtomicBool = AtomicBool::new(false);

/// 设置全局是否跳过 TLS 证书验证
pub fn set_skip_verify(skip: bool) {
    SKIP_VERIFY.store(skip, Ordering::SeqCst);
    if skip {
        tracing::warn!("⚠️ 已开启 --skipVerify 跳过 TLS 证书验证模式，请注意网络通信安全");
    }
}

/// 获取全局是否跳过 TLS 证书验证
pub fn is_skip_verify() -> bool {
    SKIP_VERIFY.load(Ordering::SeqCst)
}

/// 创建预置安全/跳过证书策略的 Reqwest ClientBuilder
pub fn create_http_client_builder() -> reqwest::ClientBuilder {
    let mut builder = reqwest::Client::builder();
    if is_skip_verify() {
        builder = builder.danger_accept_invalid_certs(true);
    }
    builder
}

/// 根据指定网卡设备名称寻找出站 IP 地址
pub fn find_interface_ip(iface_name: &str) -> Option<IpAddr> {
    if let Ok(interfaces) = NetworkInterface::show() {
        for iface in interfaces {
            if iface.name.eq_ignore_ascii_case(iface_name) {
                // 优先选择第一个有效 IP
                for addr in iface.addr {
                    match addr {
                        Addr::V4(v4) => {
                            if !v4.ip.is_loopback() {
                                return Some(IpAddr::V4(v4.ip));
                            }
                        }
                        Addr::V6(v6) => {
                            if !v6.ip.is_loopback() {
                                return Some(IpAddr::V6(v6.ip));
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

/// 创建绑定了指定出站物理网卡 / 源 IP 的 ClientBuilder (多 WAN 软路由多出口支持)
pub fn create_task_http_client_builder(interface_name: Option<&str>) -> reqwest::ClientBuilder {
    let mut builder = create_http_client_builder();
    if let Some(iface) = interface_name {
        let clean = iface.trim();
        if !clean.is_empty() {
            if let Some(local_ip) = find_interface_ip(clean) {
                tracing::info!(
                    "🔗 任务绑定出站物理网卡 [{}] (本地源 IP: {})",
                    clean,
                    local_ip
                );
                builder = builder.local_address(Some(local_ip));
            } else {
                tracing::warn!(
                    "⚠️ 未能在系统网卡中找到 [{}] 对应的出站 IP，将回退至系统默认路由",
                    clean
                );
            }
        }
    }
    builder
}

/// 创建带指定超时的 Reqwest Client
pub fn create_http_client(timeout: Duration) -> Result<reqwest::Client, reqwest::Error> {
    create_http_client_builder().timeout(timeout).build()
}
