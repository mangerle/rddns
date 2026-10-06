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
    let res = sync_record_with_retry(&provider, "test_task", &domain, DnsRecordType::A, &ip, None)
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
    let res = sync_record_with_retry(&provider, "test_task", &domain, DnsRecordType::A, &ip, None)
        .await
        .unwrap();

    assert_eq!(res.status, SyncStatus::Created);
}
