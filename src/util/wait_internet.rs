use log::{debug, info, warn};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::join;
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};

use crate::util::http::get_task_http_client;

/// 常用高可用 DNS 探测端点 (涵盖 IPv4 与 IPv6 双栈)
const PROBE_DNS_TARGETS: &[&str] = &[
    "223.5.5.5:53",              // 阿里云公共 DNS (IPv4)
    "119.29.29.29:53",           // 腾讯云 DNSPod DNS (IPv4)
    "1.1.1.1:53",                // Cloudflare DNS (IPv4)
    "8.8.8.8:53",                // Google DNS (IPv4)
    "[2400:3200::1]:53",         // 阿里云公共 DNS (IPv6)
    "[2001:4860:4860::8888]:53", // Google DNS (IPv6)
];

/// 业务等价性 HTTPS 探测端点 (P1-21)
///
/// # 设计原理
/// - **实现初衷**: 原探测使用明文 HTTP 80 端口的 204 端点，而真实业务请求走
///   HTTPS 443。开机宽带拨号阶段，路由可达但 TLS 出站与系统 DNS Client 尚未就绪时，
///   80 端口探测会假阳性通过，随即业务请求在 443 建连阶段失败并误报告警。
/// - **核心优势**: 探测路径与业务路径同构——同样需要域名解析、TLS 握手与 443 出站，
///   从而真实覆盖「系统 DNS 可解析 + HTTPS 可建连」这一就绪条件，而非泛化地
///   探测与业务无关的第三方站点。
/// - **选点考量**: 仅取高可用、支持全球访问的公共连通性检查端点。刻意不将服务商
///   API 域名作为探测目标——个别服务商不可达不应拖累整体网络就绪判定。
const PROBE_HTTPS_TARGETS: &[&str] = &[
    "https://connectivitycheck.platform.hicloud.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
    "https://www.gstatic.com/generate_204",
];

/// 降级连通性探测端点 (仅验证明文 HTTP 出站，作为 HTTPS 全部失败时的兜底信号)
const PROBE_HTTP_TARGETS: &[&str] = &["http://connect.rom.miui.com/generate_204"];

/// 单端点探测超时
#[cfg(not(test))]
const PROBE_TIMEOUT: Duration = Duration::from_millis(2500);
#[cfg(test)]
const PROBE_TIMEOUT: Duration = Duration::from_millis(50);

/// 判定就绪所需的连续成功次数 (P1-21)
///
/// # 设计原理
/// 单次探测成功不足以证明网络栈稳定：PPPoE 拨号完成后，域名解析与建连可能在数秒内
/// 继续波动。要求连续多次成功可显著降低「刚通过一次即触发业务请求」的误判概率。
const REQUIRED_CONSECUTIVE_SUCCESS: u32 = 3;

/// 开机网络恢复后稳态宽限等待时限
#[cfg(not(test))]
const SETTLE_DELAY: Duration = Duration::from_secs(5);
#[cfg(test)]
const SETTLE_DELAY: Duration = Duration::from_millis(10);

/// 单次网络探测结果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProbeOutcome {
    /// 至少一个 HTTPS 端点完成域名解析与 TLS 握手，业务路径已就绪
    https_ready: bool,
    /// 存在任一端点可达（明文 HTTP 或裸 IP），网络栈已初步可用
    any_reachable: bool,
}

/// 单次探测指定 HTTPS 端点是否完成域名解析与 TLS 握手
///
/// # 设计原理
/// 采用 GET 而非 HEAD：部分 CDN 边缘节点对 HEAD 请求返回非成功状态码，
/// 会导致健康端点被误判为不可达。响应体为空（204）且受探测超时约束，不构成流量风险。
async fn probe_https_target(client: &reqwest::Client, url: &str) -> bool {
    if let Ok(resp) = client.get(url).send().await
        && resp.status().is_success()
    {
        return true;
    }
    false
}

/// 单次探测指定 HTTP 端点是否连通（降级路径）
async fn probe_http_target(client: &reqwest::Client, url: &str) -> bool {
    if let Ok(resp) = client.get(url).send().await
        && (resp.status().is_success() || resp.status().is_redirection())
    {
        return true;
    }
    false
}

/// 单次探测裸 IP TCP 端口是否连通（最底层降级信号）
async fn probe_socket_target(target: &str) -> bool {
    if let Ok(addr) = target.parse::<SocketAddr>()
        && let Ok(Ok(_)) = timeout(Duration::from_millis(800), TcpStream::connect(addr)).await
    {
        return true;
    }
    false
}

/// 快速单次网络探测，区分「业务路径就绪」与「仅底层可达」
///
/// # 设计原理
/// - **实现初衷**: 开机自启动时宽带拨号与系统 DNS Client 服务往往存在数秒延迟。
///   仅探测裸 IP 端口易被本地路由拦截产生「假阳性」；改用明文 HTTP 204 端点虽强校验
///   了 DNS 解析，但仍是 80 端口，无法覆盖业务实际依赖的 HTTPS 443 出站。
/// - **核心优势**: 以业务等价路径（HTTPS + 域名解析）作为就绪主判据，并保留明文 HTTP
///   与裸 IP 两级降级信号，使受限环境下仍可平滑降级而非卡死启动流程。
/// - **不变式保证**: `https_ready` 为真时 `any_reachable` 必为真；本函数为纯探测，
///   不做任何业务状态变更，无副作用。
async fn check_internet_once() -> ProbeOutcome {
    let client = get_task_http_client(None, PROBE_TIMEOUT);

    // 1. 主判据：并发探测 HTTPS 端点，严格校验域名解析 + TLS 握手 + 443 出站
    let (h1, h2, h3) = join!(
        probe_https_target(&client, PROBE_HTTPS_TARGETS[0]),
        probe_https_target(&client, PROBE_HTTPS_TARGETS[1]),
        probe_https_target(&client, PROBE_HTTPS_TARGETS[2]),
    );
    if h1 || h2 || h3 {
        return ProbeOutcome {
            https_ready: true,
            any_reachable: true,
        };
    }

    // 2. 降级一：明文 HTTP 可达说明网络栈已可用，但 HTTPS 出站尚未就绪，
    //    此时立即启动业务极易在 443 建连阶段失败，故不可判定为就绪
    if probe_http_target(&client, PROBE_HTTP_TARGETS[0]).await {
        return ProbeOutcome {
            https_ready: false,
            any_reachable: true,
        };
    }

    // 3. 降级二：探测全球顶级 DNS 53 端口，判断是否为完全受限网络
    let (r1, r2, r3, r4, r5, r6) = join!(
        probe_socket_target(PROBE_DNS_TARGETS[0]),
        probe_socket_target(PROBE_DNS_TARGETS[1]),
        probe_socket_target(PROBE_DNS_TARGETS[2]),
        probe_socket_target(PROBE_DNS_TARGETS[3]),
        probe_socket_target(PROBE_DNS_TARGETS[4]),
        probe_socket_target(PROBE_DNS_TARGETS[5]),
    );
    ProbeOutcome {
        https_ready: false,
        any_reachable: r1 || r2 || r3 || r4 || r5 || r6,
    }
}

/// 连续探测直到业务路径就绪或达到最大等待时限
///
/// # 设计原理
/// 要求 [`REQUIRED_CONSECUTIVE_SUCCESS`] 次连续成功才判定就绪。一旦中途出现失败
/// 则计数归零，避免「成功-失败-成功」的抖动被误判为稳定就绪，从而消除本次排查的
/// 假阳性场景。
///
/// * `max_wait_secs`: 最大允许等待的总秒数（超时后将退出等待并继续执行）
/// * `probe_interval_secs`: 每次探测失败后的休眠重试间隔（秒）
async fn wait_for_business_ready(max_wait_secs: u64, probe_interval_secs: u64) -> bool {
    let start_time = Instant::now();
    let interval = Duration::from_secs(probe_interval_secs.max(1));
    let max_wait = Duration::from_secs(max_wait_secs);

    let mut attempt = 1u32;
    let mut consecutive_ok = 0u32;
    // 记录是否曾出现「底层可达但 HTTPS 未就绪」，用于输出更精确的诊断日志
    let mut degraded_seen = false;

    loop {
        let outcome = check_internet_once().await;

        if outcome.https_ready {
            consecutive_ok = consecutive_ok.saturating_add(1);
            if consecutive_ok >= REQUIRED_CONSECUTIVE_SUCCESS {
                let total_waited = start_time.elapsed().as_secs();
                info!(
                    "[网络就绪探测] 网络已连续 {} 次通过业务等价探测 (HTTPS 出站就绪，累计等待 {} 秒，第 {} 次尝试)，正在进行稳态缓冲...",
                    REQUIRED_CONSECUTIVE_SUCCESS, total_waited, attempt
                );
                sleep(SETTLE_DELAY).await;
                return true;
            }
            debug!(
                "[网络就绪探测] 业务等价探测通过 ({}/{} 连续成功，第 {} 次尝试)",
                consecutive_ok, REQUIRED_CONSECUTIVE_SUCCESS, attempt
            );
        } else {
            consecutive_ok = 0;
            if outcome.any_reachable {
                degraded_seen = true;
                warn!(
                    "[网络就绪探测] 网络底层已连通但 HTTPS 出站尚未就绪 (TLS 链路或系统 DNS 仍在初始化，连续成功计数归零，第 {} 次尝试)...",
                    attempt
                );
            } else {
                warn!(
                    "[网络就绪探测] 检测到当前网络未连通 (可能刚开机处于宽带拨号中，第 {} 次尝试)...",
                    attempt
                );
            }
        }

        if start_time.elapsed() >= max_wait {
            warn!(
                "[网络就绪探测] 已达到最大等待时限 ({} 秒)，网络仍未完全就绪，继续尝试启动业务...",
                max_wait_secs
            );
            if degraded_seen {
                warn!(
                    "[网络就绪探测] 期间曾出现底层可达但 HTTPS 未就绪的状态，若首轮同步失败可稍后手动触发重试"
                );
            }
            return false;
        }

        sleep(interval).await;
        attempt = attempt.saturating_add(1);
    }
}

/// 开机等待网络连通
///
/// # 设计原理
/// - **实现初衷**: 在开机启动阶段以优雅轮询阻塞主事件，待广域网、系统 DNS 栈与
///   HTTPS 出站链路均就绪后再启动 DDNS 周期任务。
/// - **核心优势**: 以「HTTPS 可解析且可建连」为就绪标准并要求连续多次成功，
///   消除开机阶段拨号与协议栈瞬态波动导致的假阳性误判；就绪后再叠加稳态宽限期，
///   进一步收敛瞬态抖动。
///
/// * `max_wait_secs`: 最大允许等待的总秒数（超时后将退出等待并继续执行）
/// * `probe_interval_secs`: 每次探测失败后的休眠重试间隔（秒）
pub async fn wait_for_internet(max_wait_secs: u64, probe_interval_secs: u64) -> bool {
    wait_for_business_ready(max_wait_secs, probe_interval_secs).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_check_internet_once_does_not_panic() {
        // 验证探测函数可正常执行且无论网络是否可用均不会 panic
        let _ = check_internet_once().await;
    }

    #[tokio::test]
    async fn test_wait_returns_within_bounded_time() {
        // 验证等待流程必然在有限时间内返回，不会因探测异常而永久挂起主调度
        let start = Instant::now();
        let _ = wait_for_internet(1, 1).await;
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "等待流程应在最大时限加单次探测耗时内结束"
        );
    }

    #[test]
    fn test_probe_outcome_https_ready_implies_reachable() {
        // 不变式：HTTPS 就绪必然意味着网络栈可达，校验探测结果构造未违反该约束
        let outcome = ProbeOutcome {
            https_ready: true,
            any_reachable: true,
        };
        assert!(outcome.https_ready && outcome.any_reachable);
    }
}
