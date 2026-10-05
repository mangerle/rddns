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
use crate::dns::trait_def::{DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult};
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
    /// 委托给 [`crate::dns::trait_def::ip_value_matches`]，统一支持 IPv6 标准化缩写等价比对，
    /// 避免格式差异误判为变更。
    pub fn matches_target(&self, target: &IpAddr) -> bool {
        crate::dns::trait_def::ip_value_matches(&self.value, target)
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

    /// 删除一条解析记录（可选，用于在多条同名同类型冲突记录时清理冗余项）
    ///
    /// 默认实现为空操作 (Ok)，支持记录删除的服务商可覆写此方法以自动清理历史冲突记录。
    async fn delete_record(&self, _zone: &str, _record_id: &str) -> Result<(), DnsProviderError> {
        Ok(())
    }

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
/// - 若存在多条同名同类型记录（如容灾历史残留），遍历检测匹配项，避免仅取首条导致误判，并清理多余记录 (P1-14)。
/// - 更新或创建成功时输出清晰日志，保障可观测性 (P2-13)。
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

    if records.is_empty() {
        ops.create_record(&zone, domain, record_type, ip, ttl)
            .await?;
        return Ok(SyncRecordResult::created_log(
            ops.provider_name(),
            full_domain,
            record_type,
            target_ip,
        ));
    }

    // 检查是否存在同名同类型的多条解析记录 (P1-14)
    if records.len() > 1 {
        log::warn!(
            "[{}] 域名 {} 存在 {} 条同名同类型的解析记录，建议清理历史残留记录以防 DNS 解析异常",
            ops.provider_name(),
            full_domain,
            records.len()
        );
    }

    // 优先检查是否有记录已经与目标 IP 一致
    if let Some((idx, matched)) = records
        .iter()
        .enumerate()
        .find(|(_, r)| r.matches_target(ip))
    {
        debug!(
            "[{}] 域名 {} 记录未变化 (ID: {}, IP: {}), 跳过更新",
            ops.provider_name(),
            full_domain,
            matched.id,
            target_ip
        );
        // 若存在多条记录且仅当前条匹配目标 IP，对其余旧记录尝试调用 delete_record 清理
        if records.len() > 1 {
            for (i, rec) in records.iter().enumerate() {
                if i != idx
                    && let Err(e) = ops.delete_record(&zone, &rec.id).await
                {
                    log::warn!(
                        "[{}] 清理域名 {} 冗余旧解析记录 (ID: {}) 失败: {}",
                        ops.provider_name(),
                        full_domain,
                        rec.id,
                        e
                    );
                }
            }
        }
        return Ok(SyncRecordResult::unchanged_log(
            ops.provider_name(),
            full_domain,
            record_type,
            target_ip,
        ));
    }

    // 所有现有记录均未匹配目标 IP：更新首条记录，并对其余多余旧记录尝试清理
    let primary = &records[0];
    ops.update_record(&zone, &primary.id, domain, record_type, ip, ttl)
        .await?;

    if records.len() > 1 {
        for rec in &records[1..] {
            if let Err(e) = ops.delete_record(&zone, &rec.id).await {
                log::warn!(
                    "[{}] 清理域名 {} 冗余旧解析记录 (ID: {}) 失败: {}",
                    ops.provider_name(),
                    full_domain,
                    rec.id,
                    e
                );
            }
        }
    }

    Ok(SyncRecordResult::updated_log(
        ops.provider_name(),
        full_domain,
        record_type,
        target_ip,
    ))
}

#[async_trait]
impl<T: RecordOps> DnsProvider for T {
    fn provider_name(&self) -> &'static str {
        RecordOps::provider_name(self)
    }

    async fn sync_record(
        &self,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
        ip: &IpAddr,
        ttl: Option<u32>,
    ) -> Result<SyncRecordResult, DnsProviderError> {
        sync_record_via(self, domain, record_type, ip, ttl).await
    }
}

#[cfg(test)]
#[path = "ops_tests.rs"]
mod ops_tests;
