use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// 常用高可用 DNS 探测端点
const PROBE_DNS_TARGETS: &[&str] = &[
    "223.5.5.5:53",    // 阿里云公共 DNS
    "119.29.29.29:53", // 腾讯云 DNSPod DNS
    "1.1.1.1:53",      // Cloudflare DNS
    "8.8.8.8:53",      // Google DNS
];

/// 常用连通性 HTTP 204 端点
const PROBE_HTTP_TARGETS: &[&str] = &[
    "http://connectivitycheck.gstatic.com/generate_204",
    "http://cp.cloudflare.com/generate_204",
];

/// 快速单次探测网络是否已就绪
pub async fn check_internet_once() -> bool {
    // 1. 并发发起 TCP 端口连接探测 (超时 800ms)
    async fn probe_target(target: &str) -> bool {
        if let Ok(addr) = target.parse::<SocketAddr>()
            && let Ok(Ok(_)) = timeout(Duration::from_millis(800), TcpStream::connect(addr)).await
        {
            return true;
        }
        false
    }

    let (r1, r2, r3, r4) = tokio::join!(
        probe_target(PROBE_DNS_TARGETS[0]),
        probe_target(PROBE_DNS_TARGETS[1]),
        probe_target(PROBE_DNS_TARGETS[2]),
        probe_target(PROBE_DNS_TARGETS[3]),
    );

    if r1 || r2 || r3 || r4 {
        return true;
    }

    // 2. 如果 TCP 端口被局域网防火墙阻断，尝试极简 HTTP 探测 (超时 1500ms)
    let client = match crate::util::http::create_http_client(Duration::from_millis(1500)) {
        Ok(c) => c,
        Err(_) => return false,
    };

    for &url in PROBE_HTTP_TARGETS {
        if let Ok(resp) = client.head(url).send().await
            && (resp.status().is_success() || resp.status().is_redirection())
        {
            return true;
        }
    }

    false
}

/// 开机等待网络连通
///
/// * `max_wait_secs`: 最大允许等待的总秒数（超时后将退出等待并继续执行）
/// * `probe_interval_secs`: 每次探测失败后的休眠重试间隔（秒）
pub async fn wait_for_internet(max_wait_secs: u64, probe_interval_secs: u64) -> bool {
    let start_time = std::time::Instant::now();
    let interval = Duration::from_secs(probe_interval_secs.max(1));
    let max_wait = Duration::from_secs(max_wait_secs);

    let mut attempt = 1;

    // 首次快速检查：若网络已经连通，立即无感知返回
    if check_internet_once().await {
        return true;
    }

    tracing::warn!(
        "⏳ [网络就绪探测] 检测到当前网络未连通（可能刚开机处于宽带拨号中），正在进入等待队列..."
    );

    loop {
        let elapsed = start_time.elapsed();
        if elapsed >= max_wait {
            tracing::warn!(
                "⚠️ [网络就绪探测] 已达到最大等待时限 ({} 秒)，网络仍未就绪，继续尝试启动业务...",
                max_wait_secs
            );
            return false;
        }

        tokio::time::sleep(interval).await;

        if check_internet_once().await {
            let total_waited = start_time.elapsed().as_secs();
            tracing::info!(
                "✅ [网络就绪探测] 网络连接已恢复就绪！(累计等待 {} 秒，尝试 {} 次)",
                total_waited,
                attempt
            );
            return true;
        }

        let current_waited = start_time.elapsed().as_secs();
        tracing::info!(
            "⏳ [网络就绪探测] 正在等待网络连通 (已等待 {}/{} 秒，第 {} 次重试)...",
            current_waited,
            max_wait_secs,
            attempt
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
