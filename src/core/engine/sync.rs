use crate::config::model::DnsTaskConfig;
use crate::core::engine::decision::is_protocol_all_ok;
use crate::core::engine::params::{ProtocolSyncParams, SyncStateUpdateParams};
use crate::dns::trait_def::{DnsRecordType, SyncRecordResult, SyncStatus};
use crate::ip_fetcher::create_ip_fetcher;
use crate::notifier::dispatcher::NotificationDispatcher;
use crate::notifier::trait_def::{NotificationEvent, NotificationOverallStatus};
use chrono::Local;
use log::{debug, error, info};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Instant;
use tokio::task::JoinSet;

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
                match provider.sync_record(&domain, rec_type, &ip, ttl).await {
                    Ok(res) => {
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
                    Err(e) => {
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
