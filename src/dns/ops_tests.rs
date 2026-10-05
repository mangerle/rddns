use super::*;
use std::net::Ipv4Addr;

#[test]
fn test_remote_record_matches_target_ipv4() {
    let rec = RemoteRecord::new("id-1", "1.2.3.4");
    assert!(rec.matches_target(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
    assert!(!rec.matches_target(&IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8))));
}

#[test]
fn test_remote_record_handles_ipv6_equivalent_forms() {
    // 同一 IPv6 的不同文本写法应判定为一致，避免无谓更新
    let rec = RemoteRecord::new("id-1", "2001:0db8:0000:0000:0000:0000:0000:0001");
    assert!(rec.matches_target(&"2001:db8::1".parse().unwrap()));
}

#[test]
fn test_remote_record_falls_back_to_text_compare() {
    // 非 IP 文本（如厂商占位符）时退化为去空白比较，不应 panic
    let rec = RemoteRecord::new("id-1", "  1.2.3.4  ");
    assert!(rec.matches_target(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
}

/// 记录操作过程的调用轨迹，用于断言模板的分支走向
#[derive(Debug, Default, PartialEq, Clone)]
struct CallLog {
    resolved_zone: bool,
    last_zone: Option<String>,
    listed: bool,
    before_sync: usize,
    created: usize,
    updated: usize,
    deleted: usize,
}

/// 可配置的测试用 RecordOps 实现
struct MockOps {
    existing: Vec<RemoteRecord>,
    log: parking_lot::Mutex<CallLog>,
    zone: String,
}

impl MockOps {
    fn with_records(existing: Vec<RemoteRecord>) -> Self {
        Self {
            existing,
            log: parking_lot::Mutex::new(CallLog::default()),
            zone: "zone-1".to_string(),
        }
    }

    fn log(&self) -> CallLog {
        (*self.log.lock()).clone()
    }
}

#[async_trait]
impl RecordOps for MockOps {
    fn provider_name(&self) -> &'static str {
        "MockProvider"
    }

    async fn resolve_zone(&self, _root_domain: &str) -> Result<String, DnsProviderError> {
        self.log.lock().resolved_zone = true;
        Ok(self.zone.clone())
    }

    async fn list_records(
        &self,
        zone: &str,
        _domain: &ParsedDomain,
        _record_type: DnsRecordType,
    ) -> Result<Vec<RemoteRecord>, DnsProviderError> {
        let mut log = self.log.lock();
        log.listed = true;
        log.last_zone = Some(zone.to_string());
        Ok(self.existing.clone())
    }

    async fn create_record(
        &self,
        zone: &str,
        _domain: &ParsedDomain,
        _record_type: DnsRecordType,
        _ip: &IpAddr,
        _ttl: Option<u32>,
    ) -> Result<(), DnsProviderError> {
        let mut log = self.log.lock();
        log.created += 1;
        log.last_zone = Some(zone.to_string());
        Ok(())
    }

    async fn update_record(
        &self,
        zone: &str,
        _record_id: &str,
        _domain: &ParsedDomain,
        _record_type: DnsRecordType,
        _ip: &IpAddr,
        _ttl: Option<u32>,
    ) -> Result<(), DnsProviderError> {
        let mut log = self.log.lock();
        log.updated += 1;
        log.last_zone = Some(zone.to_string());
        Ok(())
    }

    async fn delete_record(&self, zone: &str, _record_id: &str) -> Result<(), DnsProviderError> {
        let mut log = self.log.lock();
        log.deleted += 1;
        log.last_zone = Some(zone.to_string());
        Ok(())
    }

    async fn before_sync(&self, _zone: &str, _records: &[RemoteRecord]) {
        self.log.lock().before_sync += 1;
    }
}

/// 构造测试用域名
fn test_domain() -> ParsedDomain {
    ParsedDomain {
        raw: "nas.example.com".to_string(),
        root_domain: "example.com".to_string(),
        sub_domain: "nas".to_string(),
        custom_params: std::collections::HashMap::new(),
    }
}

#[tokio::test]
async fn test_template_skips_update_when_value_matches() {
    let ops = MockOps::with_records(vec![RemoteRecord::new("rec-1", "1.2.3.4")]);
    let result = sync_record_via(
        &ops,
        &test_domain(),
        DnsRecordType::A,
        &IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        None,
    )
    .await
    .expect("应成功返回");

    assert_eq!(result.status, crate::dns::trait_def::SyncStatus::Unchanged);
    let log = ops.log();
    assert!(log.listed, "应先查询现存记录");
    assert_eq!(log.updated, 0, "值未变时不得触发更新");
    assert_eq!(log.created, 0, "值未变时不得触发创建");
}

#[tokio::test]
async fn test_template_handles_multi_records_and_cleans_redundancy() {
    // 场景 1: 多条记录中第 2 条匹配目标 IP，第 1 条为旧残留记录
    let ops = MockOps::with_records(vec![
        RemoteRecord::new("old-rec", "9.9.9.9"),
        RemoteRecord::new("valid-rec", "1.2.3.4"),
    ]);
    let result = sync_record_via(
        &ops,
        &test_domain(),
        DnsRecordType::A,
        &IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        None,
    )
    .await
    .expect("应成功返回");

    assert_eq!(result.status, crate::dns::trait_def::SyncStatus::Unchanged);
    let log = ops.log();
    assert_eq!(log.updated, 0);
    assert_eq!(log.deleted, 1, "应主动触发清理未匹配的旧冗余记录");

    // 场景 2: 多条记录均不匹配目标 IP
    let ops2 = MockOps::with_records(vec![
        RemoteRecord::new("old-rec-1", "8.8.8.8"),
        RemoteRecord::new("old-rec-2", "9.9.9.9"),
    ]);
    let result2 = sync_record_via(
        &ops2,
        &test_domain(),
        DnsRecordType::A,
        &IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        None,
    )
    .await
    .expect("应成功返回");

    assert_eq!(result2.status, crate::dns::trait_def::SyncStatus::Updated);
    let log2 = ops2.log();
    assert_eq!(log2.updated, 1, "应更新首条记录");
    assert_eq!(log2.deleted, 1, "应清理多余的其他旧记录");
}

#[tokio::test]
async fn test_template_updates_when_value_differs() {
    let ops = MockOps::with_records(vec![RemoteRecord::new("rec-1", "9.9.9.9")]);
    let result = sync_record_via(
        &ops,
        &test_domain(),
        DnsRecordType::A,
        &IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        None,
    )
    .await
    .expect("应成功返回");

    assert_eq!(result.status, crate::dns::trait_def::SyncStatus::Updated);
    let log = ops.log();
    assert_eq!(log.updated, 1, "值变更时应触发一次更新");
    assert_eq!(log.created, 0, "已有记录时不应创建");
}

#[tokio::test]
async fn test_template_creates_when_no_record_exists() {
    let ops = MockOps::with_records(Vec::new());
    let result = sync_record_via(
        &ops,
        &test_domain(),
        DnsRecordType::A,
        &IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        None,
    )
    .await
    .expect("应成功返回");

    assert_eq!(result.status, crate::dns::trait_def::SyncStatus::Created);
    let log = ops.log();
    assert_eq!(log.created, 1, "无记录时应触发一次创建");
    assert_eq!(log.updated, 0);
}

#[tokio::test]
async fn test_template_invokes_before_sync_hook() {
    let ops = MockOps::with_records(vec![RemoteRecord::new("rec-1", "1.2.3.4")]);
    sync_record_via(
        &ops,
        &test_domain(),
        DnsRecordType::A,
        &IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        None,
    )
    .await
    .expect("应成功返回");

    assert_eq!(ops.log().before_sync, 1, "清理钩子应在比对前被调用一次");
}

#[tokio::test]
async fn test_template_uses_default_zone_resolution() {
    // 无额外 Zone ID 层级的服务商走 trait 默认实现，应直接返回 root_domain 作为 zone
    struct PureDefaultOps {
        captured_zone: parking_lot::Mutex<Option<String>>,
    }

    #[async_trait]
    impl RecordOps for PureDefaultOps {
        fn provider_name(&self) -> &'static str {
            "PureDefaultProvider"
        }

        async fn list_records(
            &self,
            zone: &str,
            _domain: &ParsedDomain,
            _record_type: DnsRecordType,
        ) -> Result<Vec<RemoteRecord>, DnsProviderError> {
            *self.captured_zone.lock() = Some(zone.to_string());
            Ok(Vec::new())
        }

        async fn create_record(
            &self,
            zone: &str,
            _domain: &ParsedDomain,
            _record_type: DnsRecordType,
            _ip: &IpAddr,
            _ttl: Option<u32>,
        ) -> Result<(), DnsProviderError> {
            *self.captured_zone.lock() = Some(zone.to_string());
            Ok(())
        }

        async fn update_record(
            &self,
            zone: &str,
            _record_id: &str,
            _domain: &ParsedDomain,
            _record_type: DnsRecordType,
            _ip: &IpAddr,
            _ttl: Option<u32>,
        ) -> Result<(), DnsProviderError> {
            *self.captured_zone.lock() = Some(zone.to_string());
            Ok(())
        }
    }

    let ops = PureDefaultOps {
        captured_zone: parking_lot::Mutex::new(None),
    };
    let domain = test_domain();
    let result = sync_record_via(
        &ops,
        &domain,
        DnsRecordType::A,
        &IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        None,
    )
    .await
    .expect("应成功返回");

    assert_eq!(result.status, crate::dns::trait_def::SyncStatus::Created);
    assert_eq!(
        ops.captured_zone.lock().as_deref(),
        Some("example.com"),
        "默认 resolve_zone 必须返回 root_domain"
    );
}

#[tokio::test]
async fn test_template_propagates_list_failure() {
    /// 始终在查询环节失败的 Mock，用于验证错误传播
    struct FailingOps;

    #[async_trait]
    impl RecordOps for FailingOps {
        fn provider_name(&self) -> &'static str {
            "FailingProvider"
        }

        async fn list_records(
            &self,
            _zone: &str,
            _domain: &ParsedDomain,
            _record_type: DnsRecordType,
        ) -> Result<Vec<RemoteRecord>, DnsProviderError> {
            Err(DnsProviderError::api("500", "查询记录失败"))
        }

        async fn create_record(
            &self,
            _zone: &str,
            _domain: &ParsedDomain,
            _record_type: DnsRecordType,
            _ip: &IpAddr,
            _ttl: Option<u32>,
        ) -> Result<(), DnsProviderError> {
            panic!("查询失败时不应进入创建分支");
        }

        async fn update_record(
            &self,
            _zone: &str,
            _record_id: &str,
            _domain: &ParsedDomain,
            _record_type: DnsRecordType,
            _ip: &IpAddr,
            _ttl: Option<u32>,
        ) -> Result<(), DnsProviderError> {
            panic!("查询失败时不应进入更新分支");
        }
    }

    let result = sync_record_via(
        &FailingOps,
        &test_domain(),
        DnsRecordType::A,
        &IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        None,
    )
    .await;

    assert!(result.is_err(), "查询失败时应向上传播错误");
}
