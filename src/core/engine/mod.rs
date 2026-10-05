pub(crate) mod decision;
pub(crate) mod params;
pub(crate) mod sync;

#[cfg(test)]
mod tests;

use crate::config::model::DnsTaskConfig;
use crate::config::storage::ConfigManager;
use crate::core::domain::parse_domain_list;
use crate::core::state::StateManager;
use crate::dns::create_dns_provider;
use crate::dns::trait_def::DnsRecordType;
use crate::notifier::dispatcher::{ErrorTrackerMap, NotificationDispatcher};
use crate::util::wait_internet::wait_for_internet;
use chrono::Local;
use log::{debug, error, info, warn};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::select;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;
use tokio::time::{MissedTickBehavior, interval};
use tokio_util::sync::CancellationToken;

pub(crate) use params::*;

/// DDNS 核心调度引擎
///
/// # 设计原理
/// - **实现初衷**: 统一协调与驱动定时轮询、配置热加载订阅、手动触发、故障重试、网络连通性探测以及多任务并发同步。
/// - **核心优势**: 任务间全异步独立并发，单任务内通过信号量限制 DNS 同步并发度（最大 5 并发），兼顾同步吞吐量与平台 QPS 防限流；智能增量比对与缓存周期检测，极大降低公网 API 调用频次。
/// - **代价与局限**: 跨任务错误追踪与状态快照驻留内存，需依赖生命周期回收函数 `retain_active_tasks` 定期清理已删除任务。
pub struct DdnsEngine {
    config_manager: Arc<ConfigManager>,
    state_manager: StateManager,
    trigger_receiver: mpsc::Receiver<()>,
    error_trackers: ErrorTrackerMap,
}

impl DdnsEngine {
    /// 创建 DDNS 引擎实例与外部手动触发通道
    ///
    /// # 设计原理
    /// - **实现初衷**: 允许调用方（Web 层）注入与引擎共享的 `StateManager` 实例，使运行状态可被外部读取，避免引擎状态成为自闭环数据。
    /// - **核心优势**: `StateManager` 内部为 `Arc<DashMap<..>>`，克隆即共享同一份数据，无需额外的跨模块通信通道。
    ///
    /// # Parameters
    /// - `config_manager`: 配置管理器句柄
    /// - `state_manager`: 任务运行时状态管理器
    pub fn new(
        config_manager: Arc<ConfigManager>,
        state_manager: StateManager,
    ) -> (Self, mpsc::Sender<()>) {
        let (tx, rx) = mpsc::channel(10);
        let engine = Self {
            config_manager,
            state_manager,
            trigger_receiver: rx,
            error_trackers: Arc::new(RwLock::new(HashMap::new())),
        };
        (engine, tx)
    }

    /// 获取任务运行时状态管理器句柄
    ///
    /// # 设计原理
    /// 供上层（如集成测试、状态查询端点）读取引擎所持有的状态实例。
    pub fn state_manager(&self) -> StateManager {
        self.state_manager.clone()
    }

    /// 执行单次全量任务检查与同步 (多任务并发执行)
    pub async fn run_once(&self, force_cloud_sync: bool) {
        let config = self.config_manager.get_config();

        // 1. 同步清理已被用户删除的任务历史状态快照，防止内存泄漏
        let active_task_names: Vec<String> =
            config.dns_tasks.iter().map(|t| t.name.clone()).collect();
        self.state_manager.retain_active_tasks(&active_task_names);

        let dispatcher = NotificationDispatcher::new_with_trackers(
            config.notifications.clone(),
            self.error_trackers.clone(),
        );

        let cache_times = config.cache_times;

        let mut join_set = JoinSet::new();
        for task in config.dns_tasks.iter() {
            if !task.enabled {
                debug!("[{}] 任务已处于禁用状态，跳过后台同步", task.name);
                continue;
            }
            let task = task.clone();
            let dispatcher_clone = dispatcher.clone();
            let state_manager = self.state_manager.clone();
            join_set.spawn(async move {
                Self::process_task(
                    &task,
                    cache_times,
                    &dispatcher_clone,
                    &state_manager,
                    force_cloud_sync,
                )
                .await;
            });
        }

        let mut panicked_tasks = 0usize;
        while let Some(res) = join_set.join_next().await {
            if let Err(join_err) = res {
                panicked_tasks += 1;
                error!(
                    "任务子协程异常终止 (panic={}): {}",
                    join_err.is_panic(),
                    join_err
                );
            }
        }
        if panicked_tasks > 0 {
            error!(
                "本轮共有 {} 个任务子协程异常终止，其状态未正常更新",
                panicked_tasks
            );
        }
    }

    /// 处理单个 DNS 任务
    async fn process_task(
        task: &DnsTaskConfig,
        cache_times: u32,
        dispatcher: &NotificationDispatcher,
        state_manager: &StateManager,
        force_sync: bool,
    ) {
        if !decision::validate_task_preconditions(task) {
            return;
        }

        info!("======== 开始执行任务: [{}] ========", task.name);
        let mut current_state = state_manager.get_task_state(&task.name);

        let (ipv4_opt, ipv6_opt) = sync::probe_task_ips(task).await;
        let mut ip_fetch_failed = false;
        if task.ipv4.enabled {
            if ipv4_opt.is_some() {
                current_state.ipv4_fail_count = 0;
            } else {
                current_state.ipv4_fail_count = current_state.ipv4_fail_count.saturating_add(1);
                ip_fetch_failed = true;
                current_state.last_error = Some(format!(
                    "[{}] 公网 IPv4 获取失败（连续 {} 次），本轮跳过云端同步",
                    task.name, current_state.ipv4_fail_count
                ));
            }
        }
        if task.ipv6.enabled {
            if ipv6_opt.is_some() {
                current_state.ipv6_fail_count = 0;
            } else {
                current_state.ipv6_fail_count = current_state.ipv6_fail_count.saturating_add(1);
                ip_fetch_failed = true;
                current_state.last_error = Some(format!(
                    "[{}] 公网 IPv6 获取失败（连续 {} 次），本轮跳过云端同步",
                    task.name, current_state.ipv6_fail_count
                ));
            }
        }

        let parsed_v4 = if task.ipv4.enabled {
            parse_domain_list(&task.ipv4.domains)
        } else {
            Vec::new()
        };
        let parsed_v6 = if task.ipv6.enabled {
            parse_domain_list(&task.ipv6.domains)
        } else {
            Vec::new()
        };

        current_state.check_counter = current_state.check_counter.saturating_add(1);
        if !force_sync && decision::should_backoff(&current_state, cache_times, ip_fetch_failed) {
            debug!(
                "[{}] IP 探测连续失败且处于指数退避期 (计数: {})，跳过云端请求",
                task.name, current_state.check_counter
            );
            current_state.last_sync_time =
                Some(Local::now().format("%Y-%m-%d %H:%M:%S").to_string());
            state_manager.update_task_state(&task.name, |s| *s = current_state);
            return;
        }
        let reach_cache_limit = current_state.check_counter >= cache_times;
        let should_sync = decision::evaluate_sync_necessity(&SyncEvaluationParams {
            task,
            cache_times,
            current_state: &current_state,
            v4_domains: &parsed_v4,
            v6_domains: &parsed_v6,
            ipv4_opt,
            ipv6_opt,
            force_sync,
        });

        if !should_sync {
            debug!(
                "[{}] 本地 IP 未发生变动 (IPv4: {:?}, IPv6: {:?})，未达服务商校对周期 ({}/{})，跳过云端请求",
                task.name, ipv4_opt, ipv6_opt, current_state.check_counter, cache_times
            );
            current_state.last_sync_time =
                Some(Local::now().format("%Y-%m-%d %H:%M:%S").to_string());
            state_manager.update_task_state(&task.name, |s| *s = current_state);
            return;
        }

        if reach_cache_limit {
            info!(
                "[{}] 达到服务商校对周期 ({}/{})，强制发起云端真实记录对比",
                task.name, current_state.check_counter, cache_times
            );
        }

        let dns_provider = match create_dns_provider(&task.provider, task.http_interface.as_deref())
        {
            Ok(p) => p,
            Err(e) => {
                error!("[{}] 创建 DNS 服务商驱动失败: {}", task.name, e);
                current_state.consecutive_failures =
                    current_state.consecutive_failures.saturating_add(1);
                current_state.last_error = Some(format!("创建 DNS 服务商驱动失败: {}", e));
                current_state.last_sync_time =
                    Some(Local::now().format("%Y-%m-%d %H:%M:%S").to_string());
                state_manager.update_task_state(&task.name, |s| *s = current_state);
                return;
            }
        };

        let mut sync_join_set = JoinSet::new();
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_DNS_SYNCS));
        let force_sync_all = force_sync || reach_cache_limit;

        sync::spawn_protocol_sync_tasks(
            &mut sync_join_set,
            ProtocolSyncParams {
                enabled: task.ipv4.enabled,
                domains: &parsed_v4,
                ip_opt: ipv4_opt.map(IpAddr::V4),
                record_type: DnsRecordType::A,
                provider: dns_provider.clone(),
                task_name: task.name.clone(),
                ttl: task.ttl,
                semaphore: semaphore.clone(),
                force_sync_all,
                synced_domains: &current_state.synced_domains,
            },
        );

        sync::spawn_protocol_sync_tasks(
            &mut sync_join_set,
            ProtocolSyncParams {
                enabled: task.ipv6.enabled,
                domains: &parsed_v6,
                ip_opt: ipv6_opt.map(IpAddr::V6),
                record_type: DnsRecordType::AAAA,
                provider: dns_provider,
                task_name: task.name.clone(),
                ttl: task.ttl,
                semaphore,
                force_sync_all,
                synced_domains: &current_state.synced_domains,
            },
        );

        let mut sync_results = Vec::new();
        let mut panicked_domains = 0usize;
        while let Some(res) = sync_join_set.join_next().await {
            match res {
                Ok(r) => sync_results.push(r),
                Err(join_err) => {
                    panicked_domains += 1;
                    error!(
                        "[{}] 域名同步子任务异常终止 (panic={}): {}",
                        task.name,
                        join_err.is_panic(),
                        join_err
                    );
                }
            }
        }

        sync::update_runtime_state_after_sync(SyncStateUpdateParams {
            task,
            current_state: &mut current_state,
            v4_count: parsed_v4.len(),
            v6_count: parsed_v6.len(),
            ipv4_opt,
            ipv6_opt,
            sync_results: &sync_results,
            reach_cache_limit,
        });

        if panicked_domains > 0 {
            current_state.consecutive_failures += panicked_domains as u32;
            let panic_note = format!("{} 个域名同步子任务异常终止", panicked_domains);
            current_state.last_error = Some(match current_state.last_error.take() {
                Some(prev) => format!("{}; {}", prev, panic_note),
                None => panic_note,
            });
        }

        state_manager.update_task_state(&task.name, |s| *s = current_state);
        sync::dispatch_sync_notification(&task.name, dispatcher, ipv4_opt, ipv6_opt, sync_results);
        info!("======== 任务 [{}] 同步执行完毕 ========\n", task.name);
    }

    /// 伴随取消令牌执行单次全量检查，若在执行期间收到停止信号，返回 false 提示调用方平滑退出
    async fn run_once_cancellable(
        &self,
        force_cloud_sync: bool,
        cancel_token: &CancellationToken,
    ) -> bool {
        select! {
            _ = cancel_token.cancelled() => false,
            _ = self.run_once(force_cloud_sync) => true,
        }
    }

    /// 启动引擎后台主循环
    ///
    /// # 设计原理
    /// - **实现初衷**: 作为常驻后台主调度任务，周期性触发 DDNS 检查，并支持热重载配置和外部手动触发同步。
    /// - **核心优势**: 监听配置变更通道实现零重启动态生效；监听取消令牌 `CancellationToken` 实现平滑优雅退出。
    pub async fn run_loop(mut self, cancel_token: CancellationToken) {
        select! {
            _ = cancel_token.cancelled() => {
                info!("收到停止信号，DDNS 调度引擎平滑退出");
                return;
            }
            _ = wait_for_internet(120, 3) => {}
        }

        let mut config_rx = self.config_manager.subscribe();
        let initial_conf = self.config_manager.get_config();
        let mut current_interval = Duration::from_secs(initial_conf.interval_secs.max(5));
        let mut timer = interval(current_interval);
        timer.set_missed_tick_behavior(MissedTickBehavior::Delay);

        let mut trigger_rx_closed = false;
        let mut config_rx_closed = false;

        'engine_loop: loop {
            select! {
                _ = cancel_token.cancelled() => {
                    info!("收到停止信号，DDNS 调度引擎平滑退出");
                    break 'engine_loop;
                }
                _ = timer.tick() => {
                    if !self.run_once_cancellable(false, &cancel_token).await {
                        info!("定时同步执行期间收到停止信号，DDNS 调度引擎平滑退出");
                        break 'engine_loop;
                    }
                }
                manual_req = self.trigger_receiver.recv(), if !trigger_rx_closed => {
                    match manual_req {
                        Some(_) => {
                            info!("收到手动强制同步触发指令");
                            if !self.run_once_cancellable(true, &cancel_token).await {
                                info!("手动同步执行期间收到停止信号，DDNS 调度引擎平滑退出");
                                break 'engine_loop;
                            }
                        }
                        None => {
                            warn!("手动同步触发通道已关闭，已停用手动指令监听分支，防止 CPU 空转");
                            trigger_rx_closed = true;
                        }
                    }
                }
                res = config_rx.changed(), if !config_rx_closed => {
                    match res {
                        Ok(()) => {
                            let new_conf = config_rx.borrow_and_update().clone();
                            let new_secs = new_conf.interval_secs.max(5);
                            if Duration::from_secs(new_secs) != current_interval {
                                current_interval = Duration::from_secs(new_secs);
                                let mut new_timer = interval(current_interval);
                                new_timer.set_missed_tick_behavior(MissedTickBehavior::Delay);
                                new_timer.reset();
                                timer = new_timer;
                                info!("DDNS 轮询周期热更新为: {} 秒", new_secs);
                            }
                        }
                        Err(_) => {
                            warn!("配置变更广播通道已关闭，已停用配置监听分支，防止 CPU 空转");
                            config_rx_closed = true;
                        }
                    }
                }
            }
        }
    }

    // ===== 关联委托方法，便于单元测试与外部调用兼容 =====

    #[cfg(test)]
    pub(crate) fn evaluate_sync_necessity(params: &SyncEvaluationParams<'_>) -> bool {
        decision::evaluate_sync_necessity(params)
    }

    #[cfg(test)]
    pub(crate) fn is_protocol_all_ok(
        enabled: bool,
        has_ip: bool,
        domain_count: usize,
        record_type: DnsRecordType,
        results: &[crate::dns::trait_def::SyncRecordResult],
    ) -> bool {
        decision::is_protocol_all_ok(enabled, has_ip, domain_count, record_type, results)
    }

    #[cfg(test)]
    pub(crate) fn update_runtime_state_after_sync(params: SyncStateUpdateParams<'_>) {
        sync::update_runtime_state_after_sync(params);
    }
}
