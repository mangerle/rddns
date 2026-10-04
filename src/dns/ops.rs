//! DNS 记录同步的模板化编排
//!
//! # 设计原理
//! - **实现初衷**: 27 个 provider 的 `sync_record` 中，约八成是同一套
//!   「查询现存记录 → 逐条比对 IP → 未变则跳过 / 有则更新 / 无则创建」的
//!   编排骨架，真正因provider 而异的仅有四类操作：
//!   1. 解析 Zone（多数 provider 直接用根域名，少数需先查 Zone ID）；
//!   2. 列出指定名称与类型的现存记录；
//!   3. 创建一条记录；
//!   4. 更新一条既有记录。
//!
//!   本模块把上述骨架收敛为 [`sync_record_via`] 模板方法，provider 只需
//!   实现 [`RecordOps`] 的四个方法即可接入，从「抄 130 行再改」降为
//!   「实现若干小方法」。
//!
//! - **核心优势**: 比对逻辑（含 `Unchanged` 判定与 `SyncRecordResult`
//!   构造）仅存在一份，修复一次即全局生效；新增 provider 的实现成本
//!   与其 API 复杂度成正比，而不再与其样板代码量成正比。
//!
//! - **代价与局限**: 各服务商 API 差异较大，本抽象并非万能。存在
//!   特殊形态的 provider（如不比对记录、直接覆盖写入的 Callback）应
//!   **继续自行实现** [`DnsProvider`]，不必迁入本模板。
//!
//! # 不变式保证
//! - 模板假定「同一名称 + 同一类型」最多对应一条有效记录；若服务商可能
//!   返回多条同名记录，实现方应在 [`RecordOps::list_records`] 中自行
//!   归并或标注，交由 [`RecordOps::before_sync`] 钩子做额外清理。

use crate::core::domain::ParsedDomain;
use crate::dns::trait_def::{DnsProviderError, DnsRecordType, SyncRecordResult};
use async_trait::async_trait;
use log::debug;
use std::net::IpAddr;

/// 服务商侧的远端记录视图
///
/// # 设计原理
/// 各服务商的响应结构千差万别，但在「是否同一条解析记录」这一判断上
/// 语义是一致的。故抽象出最小信息集：标识、当前值、以及可选的
/// 冗余清理句柄。
#[derive(Debug, Clone)]
pub struct RemoteRecord {
    /// 服务商侧记录标识（用于更新/ 删除），如 Cloudflare 的 record id
    pub id: String,
    /// 当前指向的 IP 文本
    pub value: String,
}

impl RemoteRecord {
    /// 构造远端记录视图
    pub fn new(id: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            value: value.into(),
        }
    }

    /// 判断当前值是否与目标 IP 一致
    ///
    /// # 设计原理
    /// IPv6 文本存在多种等价写法（如 `2001:db8::1` 与 `2001:0db8::1`），
    /// 故先做规范化解析再比较，避免因表示差异误判为「已变更」而触发
    /// 无谓的更新请求。
    pub fn matches_target(&self, target: &IpAddr) -> bool {
        match (self.value.trim().parse::<IpAddr>(), target) {
            (Ok(parsed), _) => &parsed == target,
            // 解析失败时退化为去除首尾空白的文本比较，保持与既有行为一致
            _ => self.value.trim() == target.to_string(),
        }
    }
}

/// 记录操作的服务商差异契约
///
/// # 设计原理
/// 只暴露编排所需的四个最小操作，provider 实现方无需关心比对与
/// 结果构造，从而专注于自身 API 的请求与响应细节。
#[async_trait]
pub trait RecordOps: Send + Sync {
    /// 服务商名称，用于日志与结果消息
    fn provider_name(&self) -> &'static str;

    /// 解析记录所属的 Zone
    ///
    /// 默认实现直接返回根域名，适用于不引入额外 Zone ID 层级的服务商（如 AliDNS、DNSPod、GoDaddy、NameSilo 等）。
    /// Cloudflare 等需要先查询 Zone ID 的实现应覆写此方法。
    async fn resolve_zone(&self, root_domain: &str) -> Result<String, DnsProviderError> {
        Ok(root_domain.to_string())
    }

    /// 列出指定名称与类型的现存记录
    ///
    /// # 参数设计
    /// 接收完整的 [`ParsedDomain`] 而非仅域名字符串：部分服务商支持线路选择
    /// （如 AliDNS 的 `Line=default`、DNSPod 的 `line`），需根据域名的自定义参数
    /// 精确匹配现有记录。
    ///
    /// # Errors
    ///
    /// 当网络通信失败或响应无法解析时返回 [`DnsProviderError`]。
    async fn list_records(
        &self,
        zone: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
    ) -> Result<Vec<RemoteRecord>, DnsProviderError>;

    /// 创建一条解析记录
    ///
    /// # 参数设计
    /// 接收完整的 [`ParsedDomain`] 而非仅域名文本：部分服务商需读取
    /// 域名的自定义参数才能确定记录属性（如 Cloudflare 的 `?proxied=true`
    /// 决定是否开启 CDN 代理、DNSPod 的 `line=telecom` 指定线路）。
    /// 传字符串会丢失这些信息，导致行为退化。
    ///
    /// # Errors
    ///
    /// 当服务商返回错误或鉴权失败时返回 [`DnsProviderError`]。
    async fn create_record(
        &self,
        zone: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
        ip: &IpAddr,
        ttl: Option<u32>,
    ) -> Result<(), DnsProviderError>;

    /// 更新一条既有解析记录
    ///
    /// # 参数设计
    /// 接收完整的 [`ParsedDomain`] 与 [`DnsRecordType`]：多数主流服务商（如 AliDNS、DNSPod 等）
    /// 在更新记录时仍强制要求提交主机记录（RR）、记录类型及线路等属性。
    ///
    /// # Errors
    ///
    /// 当服务商返回错误或鉴权失败时返回 [`DnsProviderError`]。
    async fn update_record(
        &self,
        zone: &str,
        record_id: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
        ip: &IpAddr,
        ttl: Option<u32>,
    ) -> Result<(), DnsProviderError>;

    /// 同步前的可选清理钩子
    ///
    /// # 设计原理
    /// 部分服务商允许同名同类型的多条记录共存（如 Cloudflare），需在
    /// 同步前清理冗余项。默认无需处理。
    async fn before_sync(&self, _zone: &str, _records: &[RemoteRecord]) {}
}

/// 按「查 → 比 → 改/建」编排完成单条记录同步
///
/// # 设计原理
/// - 查到记录且值一致时返回 `Unchanged`，这是 DDNS 降低云端 API 调用
///   频次的关键路径，判定逻辑必须唯一且集中。
/// - 未查到记录时创建，查到但值不一致时更新。
/// - 任何一步失败都以 [`DnsProviderError`] 向上传播，由上层统一计入
///   失败次数并触发通知。
///
/// # Errors
///
/// 当 Zone 解析、记录查询、创建或更新任一环节失败时返回 [`DnsProviderError`]。
pub async fn sync_record_via<O: RecordOps + ?Sized>(
    ops: &O,
    domain: &ParsedDomain,
    record_type: DnsRecordType,
    ip: &IpAddr,
    ttl: Option<u32>,
) -> Result<SyncRecordResult, DnsProviderError> {
    let full_domain = domain.full_domain();
    let target_ip = ip.to_string();
    let zone = ops.resolve_zone(&domain.root_domain).await?;

    let records = ops.list_records(&zone, domain, record_type).await?;
    ops.before_sync(&zone, &records).await;

    match records.first() {
        Some(existing) if existing.matches_target(ip) => {
            debug!(
                "[{}] 域名 {} 记录未变化 ({}), 跳过更新",
                ops.provider_name(),
                full_domain,
                target_ip
            );
            Ok(SyncRecordResult::unchanged(
                full_domain,
                record_type,
                target_ip,
            ))
        }
        Some(existing) => {
            ops.update_record(&zone, &existing.id, domain, record_type, ip, ttl)
                .await?;
            Ok(SyncRecordResult::updated(
                full_domain,
                record_type,
                target_ip,
            ))
        }
        None => {
            ops.create_record(&zone, domain, record_type, ip, ttl)
                .await?;
            Ok(SyncRecordResult::created(
                full_domain,
                record_type,
                target_ip,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
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
}
