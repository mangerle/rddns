use crate::config::model::DnsTaskConfig;
use crate::core::domain::{ParsedDomain, parse_domain_list_split_invalid};
use crate::core::engine::decision;
use crate::core::engine::params::{
    ProtocolSyncParams, SyncEvaluationParams, SyncStateUpdateParams, TaskProcessParams,
};
use crate::core::engine::sync;
use crate::core::state::TaskRuntimeState;
use crate::dns::create_dns_provider;
use crate::dns::trait_def::{DnsRecordType, SyncRecordResult};
use chrono::Local;
use log::{debug, error, info, warn};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use tokio::task::JoinSet;
use tokio::time::timeout;

/// 单个任务 IP 探测的总聚合超时上限（秒）
///
/// # 设计原理
/// - **实现初衷**: 防止多端点 URL 或 STUN 节点连续网络超时导致整个探测流程挂起达数十秒 (P1-16)。
/// - **核心优势**: 强制在 20 秒内闭环返回结果，释放 Tokio 协程调度，防止调度循环与手动触发被持续阻塞。
const IP_PROBE_AGGREGATE_TIMEOUT: Duration = Duration::from_secs(20);

/// 任务双栈域名解析结果聚合结构
struct ParsedTaskDomains {
    parsed_v4: Vec<ParsedDomain>,
    invalid_v4: Vec<SyncRecordResult>,
    parsed_v6: Vec<ParsedDomain>,
    invalid_v6: Vec<SyncRecordResult>,
}

impl ParsedTaskDomains {
    fn has_invalid_domains(&self) -> bool {
        !self.invalid_v4.is_empty() || !self.invalid_v6.is_empty()
    }
}

/// 任务公网 IP 探测结果聚合结构
#[derive(Clone, Copy)]
struct ProbedTaskIps {
    ipv4_opt: Option<Ipv4Addr>,
    ipv6_opt: Option<Ipv6Addr>,
    ip_fetch_failed: bool,
}

/// 将格式非法的域名条目转换为同步失败记录 (P1-17)
pub(crate) fn build_invalid_domain_results(
    invalid_domains: Vec<String>,
    record_type: DnsRecordType,
) -> Vec<SyncRecordResult> {
    invalid_domains
        .into_iter()
        .map(|domain| {
            SyncRecordResult::failed(
                domain,
                record_type,
                "未知/解析失败",
                "域名格式非法或无法识别有效根域名",
            )
        })
        .collect()
}

/// 解析任务配置的 IPv4 与 IPv6 域名列表并分离非法条目
fn parse_task_domains(task: &DnsTaskConfig) -> ParsedTaskDomains {
    let (parsed_v4, invalid_v4) = if task.ipv4.has_configured_domains() {
        let (ok, bad) = parse_domain_list_split_invalid(&task.ipv4.domains);
        (ok, build_invalid_domain_results(bad, DnsRecordType::A))
    } else {
        (Vec::new(), Vec::new())
    };
    let (parsed_v6, invalid_v6) = if task.ipv6.has_configured_domains() {
        let (ok, bad) = parse_domain_list_split_invalid(&task.ipv6.domains);
        (ok, build_invalid_domain_results(bad, DnsRecordType::AAAA))
    } else {
        (Vec::new(), Vec::new())
    };
    ParsedTaskDomains {
        parsed_v4,
        invalid_v4,
        parsed_v6,
        invalid_v6,
    }
}

/// 执行任务 IP 探测并更新运行时连续失败计数与错误摘要
async fn probe_and_record_ips(
    task: &DnsTaskConfig,
    current_state: &mut TaskRuntimeState,
) -> ProbedTaskIps {
    let (ipv4_opt, ipv6_opt) =
        match timeout(IP_PROBE_AGGREGATE_TIMEOUT, sync::probe_task_ips(task)).await {
            Ok(ips) => ips,
            Err(_) => {
                warn!(
                    "[{}] IP 探测聚合耗时超过 {} 秒上限，触发熔断并跳过本轮",
                    task.name,
                    IP_PROBE_AGGREGATE_TIMEOUT.as_secs()
                );
                (None, None)
            }
        };

    let mut ip_fetch_failed = false;
    let mut fetch_errors = Vec::with_capacity(2);
    if task.ipv4.has_configured_domains() {
        if ipv4_opt.is_some() {
            current_state.ipv4_fail_count = 0;
        } else {
            current_state.ipv4_fail_count = current_state.ipv4_fail_count.saturating_add(1);
            ip_fetch_failed = true;
            fetch_errors.push(format!(
                "[{}] 公网 IPv4 获取失败（连续 {} 次），本轮跳过云端同步",
                task.name, current_state.ipv4_fail_count
            ));
        }
    }
    if task.ipv6.has_configured_domains() {
        if ipv6_opt.is_some() {
            current_state.ipv6_fail_count = 0;
        } else {
            current_state.ipv6_fail_count = current_state.ipv6_fail_count.saturating_add(1);
            ip_fetch_failed = true;
            fetch_errors.push(format!(
                "[{}] 公网 IPv6 获取失败（连续 {} 次），本轮跳过云端同步",
                task.name, current_state.ipv6_fail_count
            ));
        }
    }
    if !fetch_errors.is_empty() {
        current_state.last_error = Some(fetch_errors.join("；"));
    }

    ProbedTaskIps {
        ipv4_opt,
        ipv6_opt,
        ip_fetch_failed,
    }
}

/// 处理无需发起云端同步的分支（IP 探测失败告警或 IP 未变动静默跳过）
fn handle_skipped_sync(
    params: &TaskProcessParams<'_>,
    mut current_state: TaskRuntimeState,
    domains: ParsedTaskDomains,
    probed: ProbedTaskIps,
) {
    let task = params.task;
    if !probed.ip_fetch_failed {
        debug!(
            "[{}] 本地 IP 未发生变动 (IPv4: {:?}, IPv6: {:?})，未达服务商校对周期 ({}/{})，跳过云端请求",
            task.name,
            probed.ipv4_opt,
            probed.ipv6_opt,
            current_state.check_counter,
            params.cache_times
        );
        current_state.last_sync_time = Some(Local::now().format("%Y-%m-%d %H:%M:%S").to_string());
        params
            .state_manager
            .update_task_state(&task.name, |s| *s = current_state);
        return;
    }

    warn!(
        "[{}] 公网 IP 获取失败，跳过云端同步并派发告警通知",
        task.name
    );
    current_state.check_counter = 0;
    current_state.consecutive_failures = current_state.consecutive_failures.saturating_add(1);
    current_state.last_sync_time = Some(Local::now().format("%Y-%m-%d %H:%M:%S").to_string());
    params
        .state_manager
        .update_task_state(&task.name, |s| *s = current_state.clone());

    let mut fail_results =
        Vec::with_capacity(domains.parsed_v4.len() + domains.parsed_v6.len() + 2);
    if task.ipv4.has_configured_domains() && probed.ipv4_opt.is_none() {
        for d in &domains.parsed_v4 {
            fail_results.push(SyncRecordResult::failed(
                d.full_domain(),
                DnsRecordType::A,
                "未知/获取失败",
                "获取本地公网 IPv4 地址失败",
            ));
        }
    }
    if task.ipv6.has_configured_domains() && probed.ipv6_opt.is_none() {
        for d in &domains.parsed_v6 {
            fail_results.push(SyncRecordResult::failed(
                d.full_domain(),
                DnsRecordType::AAAA,
                "未知/获取失败",
                "获取本地公网 IPv6 地址失败",
            ));
        }
    }
    fail_results.extend(domains.invalid_v4);
    fail_results.extend(domains.invalid_v6);

    sync::dispatch_sync_notification(
        &task.name,
        params.dispatcher,
        probed.ipv4_opt,
        probed.ipv6_opt,
        fail_results,
        params.in_startup_grace,
    );
}

/// 并发收集所有域名同步子任务的执行结果并统计异常崩溃数
async fn collect_sync_results(
    task_name: &str,
    mut sync_join_set: JoinSet<SyncRecordResult>,
    capacity: usize,
) -> (Vec<SyncRecordResult>, usize) {
    let mut sync_results = Vec::with_capacity(capacity);
    let mut panicked_domains = 0usize;
    while let Some(res) = sync_join_set.join_next().await {
        match res {
            Ok(r) => sync_results.push(r),
            Err(join_err) => {
                panicked_domains = panicked_domains.saturating_add(1);
                error!(
                    "[{}] 域名同步子任务异常终止 (panic={}): {}",
                    task_name,
                    join_err.is_panic(),
                    join_err
                );
            }
        }
    }
    (sync_results, panicked_domains)
}

/// 派生双栈协议的并发 DNS 同步子任务集合
fn spawn_dual_stack_sync_tasks(
    params: &TaskProcessParams<'_>,
    domains: &ParsedTaskDomains,
    probed: ProbedTaskIps,
    context: (
        &TaskRuntimeState,
        &std::sync::Arc<dyn crate::dns::trait_def::DnsProvider>,
        bool,
    ),
) -> JoinSet<SyncRecordResult> {
    let (current_state, dns_provider, force_sync_all) = context;
    let task = params.task;
    let mut sync_join_set = JoinSet::new();

    sync::spawn_protocol_sync_tasks(
        &mut sync_join_set,
        ProtocolSyncParams {
            enabled: task.ipv4.has_configured_domains(),
            domains: &domains.parsed_v4,
            ip_opt: probed.ipv4_opt.map(IpAddr::V4),
            record_type: DnsRecordType::A,
            provider: dns_provider.clone(),
            task_name: task.name.clone(),
            ttl: task.ttl,
            semaphore: params.semaphore.clone(),
            force_sync_all,
            synced_domains: &current_state.synced_domains,
        },
    );

    sync::spawn_protocol_sync_tasks(
        &mut sync_join_set,
        ProtocolSyncParams {
            enabled: task.ipv6.has_configured_domains(),
            domains: &domains.parsed_v6,
            ip_opt: probed.ipv6_opt.map(IpAddr::V6),
            record_type: DnsRecordType::AAAA,
            provider: dns_provider.clone(),
            task_name: task.name.clone(),
            ttl: task.ttl,
            semaphore: params.semaphore.clone(),
            force_sync_all,
            synced_domains: &current_state.synced_domains,
        },
    );

    sync_join_set
}

/// 汇总云端同步结果、更新任务运行时状态并触发通知分发
fn finalize_cloud_sync(
    params: &TaskProcessParams<'_>,
    mut current_state: TaskRuntimeState,
    domains: ParsedTaskDomains,
    outcome: (
        ProbedTaskIps,
        (bool, bool),
        bool,
        (Vec<SyncRecordResult>, usize),
    ),
) {
    let (probed, (supports_v4, supports_v6), reach_cache_limit, (mut sync_results, panicked)) =
        outcome;
    let task = params.task;

    let v4_invalid_count = domains.invalid_v4.len();
    let v6_invalid_count = domains.invalid_v6.len();
    sync_results.extend(domains.invalid_v4);
    sync_results.extend(domains.invalid_v6);

    let effective_v4_count = if supports_v4 {
        domains.parsed_v4.len() + v4_invalid_count
    } else {
        v4_invalid_count
    };
    let effective_v6_count = if supports_v6 {
        domains.parsed_v6.len() + v6_invalid_count
    } else {
        v6_invalid_count
    };

    sync::update_runtime_state_after_sync(SyncStateUpdateParams {
        task,
        current_state: &mut current_state,
        v4_count: effective_v4_count,
        v6_count: effective_v6_count,
        ipv4_opt: probed.ipv4_opt,
        ipv6_opt: probed.ipv6_opt,
        sync_results: &sync_results,
        reach_cache_limit,
    });

    if panicked > 0 {
        current_state.consecutive_failures = current_state
            .consecutive_failures
            .saturating_add(panicked as u32);
        let panic_note = format!("{} 个域名同步子任务异常终止", panicked);
        current_state.last_error = Some(match current_state.last_error.take() {
            Some(prev) => format!("{}; {}", prev, panic_note),
            None => panic_note,
        });
    }

    params
        .state_manager
        .update_task_state(&task.name, |s| *s = current_state);
    sync::dispatch_sync_notification(
        &task.name,
        params.dispatcher,
        probed.ipv4_opt,
        probed.ipv6_opt,
        sync_results,
        params.in_startup_grace,
    );
    info!("======== 任务 [{}] 同步执行完毕 ========\n", task.name);
}

/// 处理单个 DNS 任务的完整生命周期（探测 -> 评估 -> 云端同步 -> 状态更新与通知）
pub(crate) async fn process_task(params: TaskProcessParams<'_>) {
    let task = params.task;
    if !decision::validate_task_preconditions(task) {
        return;
    }

    info!("======== 开始执行任务: [{}] ========", task.name);
    let mut current_state = params.state_manager.get_task_state(&task.name);
    let probed = probe_and_record_ips(task, &mut current_state).await;
    let domains = parse_task_domains(task);

    current_state.check_counter = current_state.check_counter.saturating_add(1);
    if !params.force_sync
        && decision::should_backoff(&current_state, params.cache_times, probed.ip_fetch_failed)
    {
        debug!(
            "[{}] IP 探测连续失败且处于指数退避期 (计数: {})，跳过云端请求",
            task.name, current_state.check_counter
        );
        current_state.last_sync_time = Some(Local::now().format("%Y-%m-%d %H:%M:%S").to_string());
        params
            .state_manager
            .update_task_state(&task.name, |s| *s = current_state);
        return;
    }

    let reach_cache_limit =
        decision::is_reach_cache_limit(current_state.check_counter, params.cache_times);
    let should_sync = domains.has_invalid_domains()
        || decision::evaluate_sync_necessity(&SyncEvaluationParams {
            task,
            cache_times: params.cache_times,
            current_state: &current_state,
            v4_domains: &domains.parsed_v4,
            v6_domains: &domains.parsed_v6,
            ipv4_opt: probed.ipv4_opt,
            ipv6_opt: probed.ipv6_opt,
            force_sync: params.force_sync,
        });

    if !should_sync {
        handle_skipped_sync(&params, current_state, domains, probed);
        return;
    }

    if reach_cache_limit {
        info!(
            "[{}] 达到服务商校对周期 ({}/{})，强制发起云端真实记录对比",
            task.name, current_state.check_counter, params.cache_times
        );
    }

    let dns_provider = match create_dns_provider(&task.provider, task.http_interface.as_deref()) {
        Ok(p) => p,
        Err(e) => {
            error!("[{}] 创建 DNS 服务商驱动失败: {}", task.name, e);
            current_state.consecutive_failures =
                current_state.consecutive_failures.saturating_add(1);
            current_state.last_error = Some(format!("创建 DNS 服务商驱动失败: {}", e));
            current_state.last_sync_time =
                Some(Local::now().format("%Y-%m-%d %H:%M:%S").to_string());
            params
                .state_manager
                .update_task_state(&task.name, |s| *s = current_state);
            return;
        }
    };

    let supports_v4 = dns_provider.supports_record_type(DnsRecordType::A);
    let supports_v6 = dns_provider.supports_record_type(DnsRecordType::AAAA);
    let force_sync_all = params.force_sync || reach_cache_limit;
    let sync_join_set = spawn_dual_stack_sync_tasks(
        &params,
        &domains,
        probed,
        (&current_state, &dns_provider, force_sync_all),
    );
    let total_domains = domains.parsed_v4.len() + domains.parsed_v6.len();
    let collected = collect_sync_results(&task.name, sync_join_set, total_domains).await;

    finalize_cloud_sync(
        &params,
        current_state,
        domains,
        (
            probed,
            (supports_v4, supports_v6),
            reach_cache_limit,
            collected,
        ),
    );
}
