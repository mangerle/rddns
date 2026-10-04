use crate::config::model::DnsTaskConfig;
use crate::core::engine::params::SyncEvaluationParams;
use crate::dns::trait_def::{DnsRecordType, SyncRecordResult, SyncStatus};
use log::{debug, info};

/// 验证任务前置条件是否满足
///
/// # 设计原理
/// - **实现初衷**: 确保只有合法配置（启用状态、服务商认证就绪、配置了域名）的任务才会进入 IP 探测与同步流水线。
/// - **核心优势**: 提早短路非法或空配置任务，防止发起无效系统网络调用并输出清晰引导日志。
pub(crate) fn validate_task_preconditions(task: &DnsTaskConfig) -> bool {
    if !task.enabled {
        debug!("[{}] 任务已处于禁用状态，跳过后台同步", task.name);
        return false;
    }
    if !task.provider.is_configured() {
        info!(
            "[{}] 未配置有效的 DNS 服务商认证凭据，跳过同步（请访问 Web 界面 http://localhost:9876 完成配置）",
            task.name
        );
        return false;
    }
    if !task.has_domains() {
        info!(
            "[{}] 未配置需要解析的域名，跳过同步（请访问 Web 界面添加解析域名）",
            task.name
        );
        return false;
    }
    true
}

/// 评估是否需要向云端发起 DNS 记录同步与比对
///
/// # 设计原理
/// - **实现初衷**: 最小化云端 API 调用次数，避免触发各大 DNS 厂商（Cloudflare/AliDNS 等）的严格 QPS 限流。
/// - **核心优势**: 采用“IP 变更检测 + 缓存周期检测 + 未同步域名增量比对 + 强制同步标志”四维决策算法，纯内存比对耗时微秒级。
/// - **代价与局限**: 若用户通过外部面板直接篡改了云端解析，只能等待周期计数达标（`cache_times`）后才能发现并矫正。
pub(crate) fn evaluate_sync_necessity(params: &SyncEvaluationParams<'_>) -> bool {
    let ipv4_changed =
        params.ipv4_opt.is_some() && params.ipv4_opt != params.current_state.last_ipv4;
    let ipv6_changed =
        params.ipv6_opt.is_some() && params.ipv6_opt != params.current_state.last_ipv6;
    let ip_changed = ipv4_changed || ipv6_changed;

    let reach_cache_limit = params.current_state.check_counter >= params.cache_times;

    let has_unsynced_v4 = params.task.ipv4.enabled
        && params.ipv4_opt.is_some()
        && params.v4_domains.iter().any(|d| {
            let key = format!("{}:{:?}", d.full_domain(), DnsRecordType::A);
            params.current_state.synced_domains.get(&key)
                != params.ipv4_opt.map(|ip| ip.to_string()).as_ref()
        });
    let has_unsynced_v6 = params.task.ipv6.enabled
        && params.ipv6_opt.is_some()
        && params.v6_domains.iter().any(|d| {
            let key = format!("{}:{:?}", d.full_domain(), DnsRecordType::AAAA);
            params.current_state.synced_domains.get(&key)
                != params.ipv6_opt.map(|ip| ip.to_string()).as_ref()
        });

    params.force_sync || ip_changed || reach_cache_limit || has_unsynced_v4 || has_unsynced_v6
}

/// 校验指定协议的所有域名是否均成功同步
///
/// # 设计原理
/// - **实现初衷**: 精确评估单个协议（IPv4 或 IPv6）的整体同步完整性，决定是否可更新对应的全局 `last_ipv4` / `last_ipv6` 指针。
/// - **核心优势**: 严格校验成功条目数与任务域名总数相等，杜绝部分子任务失败被误判为全量成功。
pub(crate) fn is_protocol_all_ok(
    enabled: bool,
    has_ip: bool,
    domain_count: usize,
    record_type: DnsRecordType,
    results: &[SyncRecordResult],
) -> bool {
    if !enabled {
        return true;
    }
    if !has_ip {
        return false;
    }
    if domain_count == 0 {
        return true;
    }
    let success_count = results
        .iter()
        .filter(|r| r.record_type == record_type && r.status != SyncStatus::Failed)
        .count();
    success_count == domain_count
}
