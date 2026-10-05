use crate::config::model::DnsTaskConfig;
use crate::core::domain::ParsedDomain;
use crate::core::state::{StateManager, TaskRuntimeState};
use crate::dns::trait_def::{DnsProvider, DnsRecordType, SyncRecordResult};
use crate::notifier::dispatcher::NotificationDispatcher;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tokio::sync::Semaphore;

/// 全局向 DNS 服务商并发同步域名的最大协程数，防止跨任务并发请求打满平台 QPS 限流
pub const MAX_CONCURRENT_DNS_SYNCS: usize = 10;

/// 单个 DNS 任务的处理上下文参数对象（参数对象模式，避免平铺多参）
///
/// # 设计原理
/// - **实现初衷**: 收敛任务执行时所需的配置、状态管理器、通知分发器及全局并发信号量。
/// - **核心优势**: 符合入参不超 4 个规范，并在任务生命周期中复用全局 DNS 并发控制器。
pub(crate) struct TaskProcessParams<'a> {
    pub task: &'a DnsTaskConfig,
    pub cache_times: u32,
    pub dispatcher: &'a NotificationDispatcher,
    pub state_manager: &'a StateManager,
    pub semaphore: Arc<Semaphore>,
    pub force_sync: bool,
}

/// 单协议域名并发同步入参对象（参数对象模式，避免平铺多参）
///
/// # 设计原理
/// - **实现初衷**: 符合工程规范中入参超过 4 个强制收敛为参数对象的准则。
/// - **核心优势**: 消除长参数列表调用处的混淆与维护成本，提升并发派发逻辑的可读性。
pub(crate) struct ProtocolSyncParams<'a> {
    pub enabled: bool,
    pub domains: &'a [ParsedDomain],
    pub ip_opt: Option<IpAddr>,
    pub record_type: DnsRecordType,
    pub provider: Arc<dyn DnsProvider>,
    pub task_name: String,
    pub ttl: Option<u32>,
    pub semaphore: Arc<Semaphore>,
    pub force_sync_all: bool,
    pub synced_domains: &'a HashMap<String, String>,
}

/// 评估是否需要向云端发起 DNS 同步的输入参数对象
///
/// # 设计原理
/// - **实现初衷**: 聚合评估决策所需全部只读上下文（任务配置、状态快照、探测到的 IP），避免传参膨胀。
/// - **核心优势**: 以标量 `cache_times` 替代全量配置深拷贝，保障高频评估计算的零额外分配。
pub(crate) struct SyncEvaluationParams<'a> {
    pub task: &'a DnsTaskConfig,
    /// 服务商强制校对周期，以标量替代整份配置以避免深拷贝
    pub cache_times: u32,
    pub current_state: &'a TaskRuntimeState,
    pub v4_domains: &'a [ParsedDomain],
    pub v6_domains: &'a [ParsedDomain],
    pub ipv4_opt: Option<Ipv4Addr>,
    pub ipv6_opt: Option<Ipv6Addr>,
    pub force_sync: bool,
}

/// 同步完成后更新任务运行时状态的输入参数对象
///
/// # 设计原理
/// - **实现初衷**: 封装同步结果与状态快照的可变引用，保证状态更新逻辑的入参整洁。
/// - **核心优势**: 集中管理域名计数与更新结果切片，便于批量原子计算最新运行时指标。
pub(crate) struct SyncStateUpdateParams<'a> {
    pub task: &'a DnsTaskConfig,
    pub current_state: &'a mut TaskRuntimeState,
    pub v4_count: usize,
    pub v6_count: usize,
    pub ipv4_opt: Option<Ipv4Addr>,
    pub ipv6_opt: Option<Ipv6Addr>,
    pub sync_results: &'a [SyncRecordResult],
    pub reach_cache_limit: bool,
}
