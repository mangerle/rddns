use crate::config::model::DnsTaskConfig;
use crate::core::domain::ParsedDomain;
use crate::core::engine::decision::is_protocol_all_ok;
use crate::core::engine::params::{ProtocolSyncParams, SyncStateUpdateParams};
use crate::dns::trait_def::{
    DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult, SyncStatus,
};
use crate::ip_fetcher::create_ip_fetcher;
use crate::notifier::dispatcher::NotificationDispatcher;
use crate::notifier::trait_def::{NotificationEvent, NotificationOverallStatus};
use chrono::Local;
use log::{debug, error, info, warn};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Instant;
use tokio::task::JoinSet;
use tokio::time::{Duration, timeout};

/// 单次 DNS 服务商同步请求的全局兜底超时时间
#[cfg(not(test))]
const DNS_SYNC_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(test)]
const DNS_SYNC_TIMEOUT: Duration = Duration::from_millis(100);

/// 瞬时网络抖动最大重试次数（总尝试次数 = 1 + MAX_RETRIES = 3）
const MAX_RETRIES: usize = 2;

/// 瞬时网络抖动自动重试梯级退避间隔 (P1-11)
#[cfg(not(test))]
const RETRY_DELAYS: [Duration; 2] = [Duration::from_millis(2000), Duration::from_millis(3000)];
#[cfg(test)]
const RETRY_DELAYS: [Duration; 2] = [Duration::from_millis(10), Duration::from_millis(20)];

/// 并发探测任务所需的公网 IPv4 与 IPv6 地址
///
/// # 设计原理
/// - **实现初衷**: 利用 Tokio 异步并发能力（`tokio::join!`），双栈同时发包探测出站 IP，将网络延迟降低至最慢单协议耗时。
/// - **核心优势**: 容错隔离，单一协议提取失败不影响另一协议的正常解析与后续同步。
pub(crate) async fn probe_task_ips(task: &DnsTaskConfig) -> (Option<Ipv4Addr>, Option<Ipv6Addr>) {
    let v4_fetcher = create_ip_fetcher(&task.ipv4, task.http_interface.as_deref());
    let v6_fetcher = create_ip_fetcher(&task.ipv6, task.http_interface.as_deref());

    tokio::join!(
        async {
            if let Some(fetcher) = v4_fetcher {
                match fetcher.fetch_ipv4().await {
                    Ok(ip) => {
                        if let Some(ref v4) = ip {
                            info!("[{}] 探测到当前公网 IPv4: {}", task.name, v4);
                        }
                        ip
                    }
                    Err(e) => {
                        error!("[{}] 获取 IPv4 失败: {}", task.name, e);
                        None
                    }
                }
            } else {
                None
            }
        },
        async {
            if let Some(fetcher) = v6_fetcher {
                match fetcher.fetch_ipv6().await {
                    Ok(ip) => {
                        if let Some(ref v6) = ip {
                            info!("[{}] 探测到当前公网 IPv6: {}", task.name, v6);
                        }
                        ip
                    }
                    Err(e) => {
                        error!("[{}] 获取 IPv6 失败: {}", task.name, e);
                        None
                    }
                }
            } else {
                None
            }
        }
    )
}

/// 调度单个网络协议 (IPv4/IPv6) 下所有域名的并发同步任务
///
/// # 设计原理
/// - **实现初衷**: 将该协议下的所有待同步域名分别派生为异步协程并发请求。
/// - **核心优势**: 通过共享信号量控制最大并发度（默认 5），兼顾同步吞吐量与平台 QPS 防限流；已同步且本地未变域名跳过网络请求直接产出 `Unchanged` 结果。
pub(crate) fn spawn_protocol_sync_tasks(
    sync_join_set: &mut JoinSet<SyncRecordResult>,
    params: ProtocolSyncParams<'_>,
) {
    if !params.enabled {
        return;
    }

    let type_str = match params.record_type {
        DnsRecordType::A => "A 记录",
        DnsRecordType::AAAA => "AAAA 记录",
    };

    if let Some(ip) = params.ip_opt {
        let ip_str = ip.to_string();
        for domain in params.domains {
            let full_domain = domain.full_domain();
            let domain_key = format!("{}:{:?}", full_domain, params.record_type);

            if !params.force_sync_all && params.synced_domains.get(&domain_key) == Some(&ip_str) {
                debug!(
                    "[{}] 域名 {} ({}) 本地 IP 未变且已处于同步状态，跳过云端请求",
                    params.task_name, full_domain, type_str
                );
                let ip_str_clone = ip_str.clone();
                let rec_type = params.record_type;
                sync_join_set.spawn(async move {
                    SyncRecordResult::unchanged(full_domain, rec_type, ip_str_clone)
                });
                continue;
            }

            let domain = domain.clone();
            let provider = params.provider.clone();
            let task_name = params.task_name.clone();
            let sem = params.semaphore.clone();
            let rec_type = params.record_type;
            let ttl = params.ttl;
            sync_join_set.spawn(async move {
                let _permit = sem.acquire().await.ok();
                let start_time = Instant::now();
                let full_domain = domain.full_domain();
                let sync_future =
                    sync_record_with_retry(&provider, &task_name, &domain, rec_type, &ip, ttl);
                match timeout(DNS_SYNC_TIMEOUT, sync_future).await {
                    Ok(Ok(res)) => {
                        let cost_ms = start_time.elapsed().as_millis();
                        info!(
                            "[{}] 同步域名 {} ({}) 完成: {} (耗时 {}ms)",
                            task_name,
                            full_domain,
                            type_str,
                            res.status.as_str(),
                            cost_ms
                        );
                        res
                    }
                    Ok(Err(e)) => {
                        let cost_ms = start_time.elapsed().as_millis();
                        error!(
                            "[{}] 同步域名 {} ({}) 失败: {} (耗时 {}ms)",
                            task_name, full_domain, type_str, e, cost_ms
                        );
                        SyncRecordResult::failed(
                            full_domain,
                            rec_type,
                            ip.to_string(),
                            e.to_string(),
                        )
                    }
                    Err(_elapsed) => {
                        let cost_ms = start_time.elapsed().as_millis();
                        error!(
                            "[{}] 同步域名 {} ({}) 超时 (超过 {:?}) (耗时 {}ms)",
                            task_name, full_domain, type_str, DNS_SYNC_TIMEOUT, cost_ms
                        );
                        SyncRecordResult::failed(
                            full_domain,
                            rec_type,
                            ip.to_string(),
                            format!("DNS 同步请求超时 (超过 {:?})", DNS_SYNC_TIMEOUT),
                        )
                    }
                }
            });
        }
    } else {
        for domain in params.domains {
            let full_domain = domain.full_domain();
            let fail_msg = match params.record_type {
                DnsRecordType::A => "获取本地公网 IPv4 地址失败",
                DnsRecordType::AAAA => "获取本地公网 IPv6 地址失败",
            };
            let rec_type = params.record_type;
            sync_join_set.spawn(async move {
                SyncRecordResult::failed(full_domain, rec_type, "未知/获取失败", fail_msg)
            });
        }
    }
}

/// 同步完成后更新任务的运行时状态快照
///
/// # 设计原理
/// - **实现初衷**: 集中原子维护各域名最新同步记录、连续失败计数、连续轮询计数以及错误摘要。
/// - **核心优势**: 成功则自动清除历史错误并重置计数器；失败时提取详尽的错误摘要供 Web 控制台展示与自愈判定。
pub(crate) fn update_runtime_state_after_sync(params: SyncStateUpdateParams<'_>) {
    for r in params.sync_results {
        let key = format!("{}:{:?}", r.domain, r.record_type);
        if r.status != SyncStatus::Failed {
            params
                .current_state
                .synced_domains
                .insert(key, r.target_ip.clone());
        } else {
            params.current_state.synced_domains.remove(&key);
        }
    }

    // 裁剪已从当前任务配置中移除的废弃域名记录，防止内存持续膨胀 (F-6)
    let mut valid_keys = std::collections::HashSet::new();
    if params.task.ipv4.enabled {
        for d in &params.task.ipv4.domains {
            if let Some(parsed) = crate::core::domain::parse_domain(d) {
                valid_keys.insert(format!("{}:A", parsed.full_domain()));
            }
        }
    }
    if params.task.ipv6.enabled {
        for d in &params.task.ipv6.domains {
            if let Some(parsed) = crate::core::domain::parse_domain(d) {
                valid_keys.insert(format!("{}:AAAA", parsed.full_domain()));
            }
        }
    }
    params
        .current_state
        .synced_domains
        .retain(|k, _| valid_keys.contains(k));

    let ipv4_all_ok = is_protocol_all_ok(
        params.task.ipv4.enabled,
        params.ipv4_opt.is_some(),
        params.v4_count,
        DnsRecordType::A,
        params.sync_results,
    );
    let ipv6_all_ok = is_protocol_all_ok(
        params.task.ipv6.enabled,
        params.ipv6_opt.is_some(),
        params.v6_count,
        DnsRecordType::AAAA,
        params.sync_results,
    );

    if ipv4_all_ok && params.ipv4_opt.is_some() {
        params.current_state.last_ipv4 = params.ipv4_opt;
    }
    if ipv6_all_ok && params.ipv6_opt.is_some() {
        params.current_state.last_ipv6 = params.ipv6_opt;
    }

    params.current_state.last_sync_time =
        Some(Local::now().format("%Y-%m-%d %H:%M:%S").to_string());
    if params.reach_cache_limit || (ipv4_all_ok && ipv6_all_ok) {
        params.current_state.check_counter = 0;
    }

    if ipv4_all_ok && ipv6_all_ok {
        params.current_state.consecutive_failures = 0;
        params.current_state.last_error = None;
    } else {
        params.current_state.consecutive_failures =
            params.current_state.consecutive_failures.saturating_add(1);
        let failed_msgs: Vec<String> = params
            .sync_results
            .iter()
            .filter(|r| r.status == SyncStatus::Failed)
            .map(|r| format!("{}: {}", r.domain, r.message))
            .collect();
        if !failed_msgs.is_empty() {
            params.current_state.last_error = Some(failed_msgs.join("; "));
        }
    }
}

/// 评估同步结果并向已启用的渠道派发通知事件
///
/// # 设计原理
/// - **实现初衷**: 解耦 DNS 记录修改与外部告警通知，根据全量、部分或全部失败计算总体状态并异步通知。
pub(crate) fn dispatch_sync_notification(
    task_name: &str,
    dispatcher: &NotificationDispatcher,
    ipv4_opt: Option<Ipv4Addr>,
    ipv6_opt: Option<Ipv6Addr>,
    sync_results: Vec<SyncRecordResult>,
) {
    if sync_results.is_empty() {
        return;
    }
    let has_success = sync_results.iter().any(|r| r.status != SyncStatus::Failed);
    let has_failed = sync_results.iter().any(|r| r.status == SyncStatus::Failed);
    let has_actual_updates = sync_results
        .iter()
        .any(|r| matches!(r.status, SyncStatus::Created | SyncStatus::Updated));

    let overall_status = if has_success && !has_failed {
        NotificationOverallStatus::Success
    } else if !has_success && has_failed {
        NotificationOverallStatus::Failed
    } else {
        NotificationOverallStatus::PartialSuccess
    };

    dispatcher.dispatch(NotificationEvent {
        overall_status,
        task_name: task_name.to_string(),
        ipv4: ipv4_opt,
        ipv6: ipv6_opt,
        ip_changed: has_actual_updates,
        results: sync_results,
        timestamp: Local::now(),
    });
}

/// 执行带有瞬时抖动自动重试的 DNS 记录同步操作 (P1-11)
///
/// 当遇到底层网络连接断开或对端服务端瞬时限流 (502/503/504/RateLimit) 时，
/// 等待梯级退避时间进行至多 2 次自动重试（总共至多尝试 3 次），充分吸收开机阶段的网络与 DNS 就绪抖动。
async fn sync_record_with_retry(
    provider: &Arc<dyn DnsProvider>,
    task_name: &str,
    domain: &ParsedDomain,
    rec_type: DnsRecordType,
    ip: &IpAddr,
    ttl: Option<u32>,
) -> Result<SyncRecordResult, DnsProviderError> {
    let mut retry_count = 0usize;
    loop {
        match provider.sync_record(domain, rec_type, ip, ttl).await {
            Ok(res) => return Ok(res),
            Err(e) if e.is_retryable() && retry_count < MAX_RETRIES => {
                let delay = RETRY_DELAYS[retry_count];
                retry_count = retry_count.saturating_add(1);
                warn!(
                    "[{}] 同步域名 {} ({}) 遇到临时网络抖动: {}，正在进行第 {}/{} 次重试 (等待 {:?})...",
                    task_name,
                    domain.full_domain(),
                    rec_type,
                    e,
                    retry_count,
                    MAX_RETRIES,
                    delay
                );
                tokio::time::sleep(delay).await;
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::NotificationConfig;
    use crate::core::domain::{ParsedDomain, parse_domain};
    use crate::dns::trait_def::DnsProvider;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    struct DummyProvider;
    #[async_trait::async_trait]
    impl DnsProvider for DummyProvider {
        fn provider_name(&self) -> &'static str {
            "Dummy"
        }
        async fn sync_record(
            &self,
            domain: &ParsedDomain,
            record_type: DnsRecordType,
            ip: &IpAddr,
            _ttl: Option<u32>,
        ) -> Result<SyncRecordResult, crate::dns::trait_def::DnsProviderError> {
            Ok(SyncRecordResult::updated(
                domain.full_domain(),
                record_type,
                ip.to_string(),
            ))
        }
    }

    #[tokio::test]
    async fn test_spawn_protocol_sync_tasks_no_ip() {
        let mut join_set = JoinSet::new();
        let domain = parse_domain("test.example.com").unwrap();
        let sem = Arc::new(Semaphore::new(1));
        let synced = HashMap::new();

        spawn_protocol_sync_tasks(
            &mut join_set,
            ProtocolSyncParams {
                enabled: true,
                task_name: "test_task".to_string(),
                record_type: DnsRecordType::A,
                ip_opt: None,
                domains: &[domain],
                provider: Arc::new(DummyProvider),
                ttl: None,
                synced_domains: &synced,
                force_sync_all: false,
                semaphore: sem,
            },
        );

        let res = join_set.join_next().await.unwrap().unwrap();
        assert_eq!(res.status, SyncStatus::Failed);
    }

    #[tokio::test]
    async fn test_spawn_protocol_sync_tasks_short_circuit_and_force() {
        let mut join_set = JoinSet::new();
        let domain = parse_domain("test.example.com").unwrap();
        let sem = Arc::new(Semaphore::new(1));
        let mut synced = HashMap::new();
        synced.insert("test.example.com:A".to_string(), "1.2.3.4".to_string());

        // 1. 本地 IP 未变且已同步短路
        spawn_protocol_sync_tasks(
            &mut join_set,
            ProtocolSyncParams {
                enabled: true,
                task_name: "test_task".to_string(),
                record_type: DnsRecordType::A,
                ip_opt: Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
                domains: std::slice::from_ref(&domain),
                provider: Arc::new(DummyProvider),
                ttl: None,
                synced_domains: &synced,
                force_sync_all: false,
                semaphore: sem.clone(),
            },
        );
        let res = join_set.join_next().await.unwrap().unwrap();
        assert_eq!(res.status, SyncStatus::Unchanged);

        // 2. force_sync_all 强制同步
        spawn_protocol_sync_tasks(
            &mut join_set,
            ProtocolSyncParams {
                enabled: true,
                task_name: "test_task".to_string(),
                record_type: DnsRecordType::A,
                ip_opt: Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
                domains: std::slice::from_ref(&domain),
                provider: Arc::new(DummyProvider),
                ttl: None,
                synced_domains: &synced,
                force_sync_all: true,
                semaphore: sem,
            },
        );
        let res2 = join_set.join_next().await.unwrap().unwrap();
        assert_eq!(res2.status, SyncStatus::Updated);
    }

    #[test]
    fn test_dispatch_sync_notification_statuses() {
        let dispatcher = NotificationDispatcher::new(NotificationConfig::default());

        // 验证空列表安全跳过
        dispatch_sync_notification("task", &dispatcher, None, None, Vec::new());

        // 构造三态结果验证
        let s1 = SyncRecordResult::unchanged("a.com", DnsRecordType::A, "1.1.1.1");
        let s2 = SyncRecordResult::failed("b.com", DnsRecordType::A, "1.1.1.1", "err");
        dispatch_sync_notification("task", &dispatcher, None, None, vec![s1.clone()]);
        dispatch_sync_notification("task", &dispatcher, None, None, vec![s2.clone()]);
        dispatch_sync_notification("task", &dispatcher, None, None, vec![s1, s2]);
    }

    struct HangProvider;

    #[async_trait::async_trait]
    impl DnsProvider for HangProvider {
        fn provider_name(&self) -> &'static str {
            "hang"
        }

        async fn sync_record(
            &self,
            _domain: &crate::core::domain::ParsedDomain,
            _record_type: DnsRecordType,
            _ip: &std::net::IpAddr,
            _ttl: Option<u32>,
        ) -> Result<SyncRecordResult, crate::dns::trait_def::DnsProviderError> {
            tokio::time::sleep(Duration::from_secs(5)).await;
            unreachable!()
        }
    }

    #[tokio::test]
    async fn test_spawn_protocol_sync_tasks_timeout() {
        let mut join_set = JoinSet::new();
        let domain = parse_domain("timeout.example.com").unwrap();
        let sem = Arc::new(Semaphore::new(1));
        let synced = HashMap::new();

        spawn_protocol_sync_tasks(
            &mut join_set,
            ProtocolSyncParams {
                enabled: true,
                task_name: "timeout_task".to_string(),
                record_type: DnsRecordType::A,
                ip_opt: Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
                domains: std::slice::from_ref(&domain),
                provider: Arc::new(HangProvider),
                ttl: None,
                synced_domains: &synced,
                force_sync_all: true,
                semaphore: sem,
            },
        );

        let res = join_set.join_next().await.unwrap().unwrap();
        assert_eq!(res.status, SyncStatus::Failed);
        assert!(res.message.contains("超时"));
    }

    struct FlakyProvider {
        attempt: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl DnsProvider for FlakyProvider {
        fn provider_name(&self) -> &'static str {
            "flaky"
        }

        async fn sync_record(
            &self,
            domain: &ParsedDomain,
            record_type: DnsRecordType,
            ip: &IpAddr,
            _ttl: Option<u32>,
        ) -> Result<SyncRecordResult, DnsProviderError> {
            let n = self
                .attempt
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n == 0 {
                Err(DnsProviderError::Http(
                    "Connection reset by peer".to_string(),
                ))
            } else {
                Ok(SyncRecordResult::created(
                    domain.full_domain(),
                    record_type,
                    ip.to_string(),
                ))
            }
        }
    }

    #[tokio::test]
    async fn test_sync_record_with_retry_succeeds_on_second_try() {
        let domain = parse_domain("retry.example.com").unwrap();
        let provider: Arc<dyn DnsProvider> = Arc::new(FlakyProvider {
            attempt: std::sync::atomic::AtomicUsize::new(0),
        });
        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let res =
            sync_record_with_retry(&provider, "test_task", &domain, DnsRecordType::A, &ip, None)
                .await
                .unwrap();

        assert_eq!(res.status, SyncStatus::Created);
    }

    struct TwiceFlakyProvider {
        attempt: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl DnsProvider for TwiceFlakyProvider {
        fn provider_name(&self) -> &'static str {
            "twice_flaky"
        }

        async fn sync_record(
            &self,
            domain: &ParsedDomain,
            record_type: DnsRecordType,
            ip: &IpAddr,
            _ttl: Option<u32>,
        ) -> Result<SyncRecordResult, DnsProviderError> {
            let n = self
                .attempt
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n < 2 {
                Err(DnsProviderError::Http(
                    "Connection reset by peer".to_string(),
                ))
            } else {
                Ok(SyncRecordResult::created(
                    domain.full_domain(),
                    record_type,
                    ip.to_string(),
                ))
            }
        }
    }

    #[tokio::test]
    async fn test_sync_record_with_retry_succeeds_on_third_try() {
        let domain = parse_domain("retry3.example.com").unwrap();
        let provider: Arc<dyn DnsProvider> = Arc::new(TwiceFlakyProvider {
            attempt: std::sync::atomic::AtomicUsize::new(0),
        });
        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let res =
            sync_record_with_retry(&provider, "test_task", &domain, DnsRecordType::A, &ip, None)
                .await
                .unwrap();

        assert_eq!(res.status, SyncStatus::Created);
    }
}
