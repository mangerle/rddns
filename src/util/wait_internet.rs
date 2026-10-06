use log::{info, warn};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::join;
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};

use crate::util::http::create_http_client;

/// 常用高可用 DNS 探测端点 (涵盖 IPv4 与 IPv6 双栈)
const PROBE_DNS_TARGETS: &[&str] = &[
    "223.5.5.5:53",              // 阿里云公共 DNS (IPv4)
    "119.29.29.29:53",           // 腾讯云 DNSPod DNS (IPv4)
    "1.1.1.1:53",                // Cloudflare DNS (IPv4)
    "8.8.8.8:53",                // Google DNS (IPv4)
    "[2400:3200::1]:53",         // 阿里云公共 DNS (IPv6)
    "[2001:4860:4860::8888]:53", // Google DNS (IPv6)
];

/// 常用高可用连通性 HTTP 204 端点 (覆盖国内双栈及国际主流网络)
const PROBE_HTTP_TARGETS: &[&str] = &[
    "http://connect.rom.miui.com/generate_204",
    "http://connectivitycheck.platform.hicloud.com/generate_204",
    "http://cp.cloudflare.com/generate_204",
];

/// 开机网络恢复后稳态宽限等待时限
#[cfg(not(test))]
const SETTLE_DELAY: Duration = Duration::from_secs(2);
#[cfg(test)]
const SETTLE_DELAY: Duration = Duration::from_millis(10);

/// 单次探测指定 HTTP 端点是否连通
async fn probe_http_target(client: &reqwest::Client, url: &str) -> bool {
    if let Ok(resp) = client.head(url).send().await
        && (resp.status().is_success() || resp.status().is_redirection())
    {
        return true;
    }
    false
}

/// 快速单次探测网络是否已就绪
///
/// # 设计原理
/// - **实现初衷**：开机自启动时宽带拨号与系统 DNS Client 服务往往存在数秒延迟，若仅探测裸 IP 端口
///   容易被本地路由拦截产生“假阳性”，导致后续 DDNS API 域名解析连续失败。
/// - **核心优势**：优先并发探测国内与国际高可用 HTTP 204 端点，强校验系统 DNS 解析与出站 HTTP 连通性；
///   受限环境下平滑降级至全球顶级 IPv4/IPv6 DNS 53 端口并发探测。
pub async fn check_internet_once() -> bool {
    // 1. 优先并发发起高可用 HTTP 204 端点探测（超时 1500ms），强校验系统 DNS 解析与 HTTP 栈连通性
    if let Ok(client) = create_http_client(Duration::from_millis(1500)) {
        let (h1, h2, h3) = join!(
            probe_http_target(&client, PROBE_HTTP_TARGETS[0]),
            probe_http_target(&client, PROBE_HTTP_TARGETS[1]),
            probe_http_target(&client, PROBE_HTTP_TARGETS[2]),
        );
        if h1 || h2 || h3 {
            return true;
        }
    }

    // 2. 若 HTTP 204 端点被局域网拦截或受限，回退并发探测 TCP 53 端口 (超时 800ms)
    async fn probe_target(target: &str) -> bool {
        if let Ok(addr) = target.parse::<SocketAddr>()
            && let Ok(Ok(_)) = timeout(Duration::from_millis(800), TcpStream::connect(addr)).await
        {
            return true;
        }
        false
    }

    let (r1, r2, r3, r4, r5, r6) = join!(
        probe_target(PROBE_DNS_TARGETS[0]),
        probe_target(PROBE_DNS_TARGETS[1]),
        probe_target(PROBE_DNS_TARGETS[2]),
        probe_target(PROBE_DNS_TARGETS[3]),
        probe_target(PROBE_DNS_TARGETS[4]),
        probe_target(PROBE_DNS_TARGETS[5]),
    );

    r1 || r2 || r3 || r4 || r5 || r6
}

/// 开机等待网络连通
///
/// # 设计原理
/// - **实现初衷**：在开机启动阶段以优雅轮询阻塞主事件，待广域网与系统 DNS 栈就绪后再启动 DDNS 周期任务。
/// - **核心优势**：网络就绪后提供短暂稳态宽限期，消除开机阶段拨号与协议栈瞬态波动抖动。
///
/// * `max_wait_secs`: 最大允许等待的总秒数（超时后将退出等待并继续执行）
/// * `probe_interval_secs`: 每次探测失败后的休眠重试间隔（秒）
pub async fn wait_for_internet(max_wait_secs: u64, probe_interval_secs: u64) -> bool {
    let start_time = Instant::now();
    let interval = Duration::from_secs(probe_interval_secs.max(1));
    let max_wait = Duration::from_secs(max_wait_secs);

    let mut attempt = 1;

    // 首次快速检查：若网络已经连通，给予稳态缓冲后直接返回
    if check_internet_once().await {
        info!(
            "[网络就绪探测] 网络已连通，给予 {} 秒稳态宽限期以确保系统 DNS 与网络协议栈稳定...",
            SETTLE_DELAY.as_secs()
        );
        sleep(SETTLE_DELAY).await;
        return true;
    }

    warn!("[网络就绪探测] 检测到当前网络未连通（可能刚开机处于宽带拨号中），正在进入等待队列...");

    loop {
        let elapsed = start_time.elapsed();
        if elapsed >= max_wait {
            warn!(
                "[网络就绪探测] 已达到最大等待时限 ({} 秒)，网络仍未就绪，继续尝试启动业务...",
                max_wait_secs
            );
            return false;
        }

        sleep(interval).await;

        if check_internet_once().await {
            let total_waited = start_time.elapsed().as_secs();
            info!(
                "[网络就绪探测] 网络连接已恢复就绪！(累计等待 {} 秒，尝试 {} 次)，正在进行稳态缓冲...",
                total_waited, attempt
            );
            sleep(SETTLE_DELAY).await;
            return true;
        }

        let current_waited = start_time.elapsed().as_secs();
        info!(
            "[网络就绪探测] 正在等待网络连通 (已等待 {}/{} 秒，第 {} 次重试)...",
            current_waited, max_wait_secs, attempt
        );

        attempt += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_check_internet_once_executable() {
        // 验证探测函数可正常执行且不会发生 panic
        let _ = check_internet_once().await;
    }
}
