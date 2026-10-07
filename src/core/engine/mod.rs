pub(crate) mod decision;
pub(crate) mod params;
pub(crate) mod sync;
pub(crate) mod task_runner;

#[cfg(test)]
mod tests;

use crate::config::storage::ConfigManager;
use crate::core::state::StateManager;
#[cfg(test)]
use crate::dns::trait_def::DnsRecordType;
use crate::notifier::dispatcher::{ErrorTrackerMap, NotificationDispatcher};
use crate::util::wait_internet::wait_for_internet;
use log::{debug, error, info, warn};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::select;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;
use tokio::time::{Interval, MissedTickBehavior, interval};
use tokio_util::sync::CancellationToken;

pub(crate) use params::*;

/// 启动宽限期内不派发失败告警的时长 (P1-21)
///
/// # 设计原理
/// - **实现初衷**: 开机自启动时，即便网络就绪探测已通过，系统 DNS Client 与 TLS
///   链路仍可能存在数秒瞬态波动，使首轮同步整体失败。此类失败并非真实配置问题，
///   照常告警只会产生噪声。
/// - **核心优势**: 以时间窗限定抑制范围而非永久放宽——若宽限期后问题依旧存在，
///   后续轮次将正常派发告警，绝不会掩盖真实故障。
const STARTUP_GRACE_PERIOD: Duration = Duration::from_secs(90);

/// DDNS 核心调度引擎
///
/// # 设计原理
/// - **实现初衷**: 统一协调与驱动定时轮询、配置热加载订阅、手动触发、故障重试、网络连通性探测以及多任务并发同步。
/// - **核心优势**: 任务间全异步独立并发，全局通过信号量限制跨任务 DNS 同步并发度（由 `MAX_CONCURRENT_DNS_SYNCS` 约束，最大 10 并发），兼顾同步吞吐量与平台 QPS 防限流；智能增量比对与缓存周期检测，极大降低公网 API 调用频次。
/// - **代价与局限**: 跨任务错误追踪与状态快照驻留内存，需依赖生命周期回收函数 `retain_active_tasks` 定期清理已删除任务。
pub struct DdnsEngine {
    config_manager: Arc<ConfigManager>,
    state_manager: StateManager,
    trigger_receiver: mpsc::Receiver<()>,
    error_trackers: ErrorTrackerMap,
    dns_sync_semaphore: Arc<Semaphore>,
}

impl DdnsEngine {
    /// 创建 DDNS 引擎实例与外部手动触发通道
    ///
    /// # 设计原理
    /// - **实现初衷**: 允许调用方（Web 层）注入与引擎共享的 `StateManager` 实例，使运行状态可被外部读取，避免引擎状态成为自闭环数据。
    /// - **核心优势**: `StateManager` 内部为 `Arc<DashMap<..>>`，克隆即共享同一份数据，无需额外的跨模块通信通道。
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
            dns_sync_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_DNS_SYNCS)),
        };
        (engine, tx)
    }

    /// 获取任务运行时状态管理器句柄
    pub fn state_manager(&self) -> StateManager {
        self.state_manager.clone()
    }

    /// 执行单次全量任务检查与同步 (多任务并发执行)
    ///
    /// * `in_startup_grace`: 本次调用是否处于启动宽限期内，用于抑制开机瞬态误告警
    pub async fn run_once(&self, force_cloud_sync: bool, in_startup_grace: bool) {
        let config = self.config_manager.get_config();

        // 1. 同步清理已被用户删除的任务历史状态快照与错误冷却追踪，防止内存泄漏与旧状态残留
        let active_task_names: Vec<String> =
            config.dns_tasks.iter().map(|t| t.name.clone()).collect();
        self.state_manager.retain_active_tasks(&active_task_names);
        self.error_trackers
            .write()
            .retain(|k, _| active_task_names.iter().any(|name| name == k));

        let dispatcher = NotificationDispatcher::new_with_trackers_and_statuses(
            config.notifications.clone(),
            self.error_trackers.clone(),
            self.state_manager.delivery_statuses(),
        );

        let cache_times = config.cache_times;
        let mut join_set = JoinSet::new();
        let semaphore = self.dns_sync_semaphore.clone();
        for task in config.dns_tasks.iter() {
            if !task.enabled {
                debug!("[{}] 任务已处于禁用状态，跳过后台同步", task.name);
                continue;
            }
            let task = task.clone();
            let dispatcher_clone = dispatcher.clone();
            let state_manager = self.state_manager.clone();
            let sem = semaphore.clone();
            join_set.spawn(async move {
                task_runner::process_task(TaskProcessParams {
                    task: &task,
                    cache_times,
                    dispatcher: &dispatcher_clone,
                    state_manager: &state_manager,
                    semaphore: sem,
                    force_sync: force_cloud_sync,
                    in_startup_grace,
                })
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

    /// 伴随取消令牌执行单次全量检查，若在执行期间收到停止信号，返回 false 提示调用方平滑退出
    async fn run_once_cancellable(
        &self,
        force_cloud_sync: bool,
        in_startup_grace: bool,
        cancel_token: &CancellationToken,
    ) -> bool {
        select! {
            _ = cancel_token.cancelled() => false,
            _ = self.run_once(force_cloud_sync, in_startup_grace) => true,
        }
    }

    /// 评估并切换自愈快速重试定时器与常规周期定时器
    fn update_fast_retry_timer(
        &self,
        timer: &mut Interval,
        in_fast_retry: &mut bool,
        current_interval: Duration,
    ) {
        let fast_retry_interval = Duration::from_secs(30);
        let has_recent_failures = self.state_manager.has_recent_failures(5);
        if has_recent_failures && !*in_fast_retry && current_interval > fast_retry_interval {
            *in_fast_retry = true;
            info!(
                "检测到任务同步存在偶发故障，临时启用自愈快速重试调度 (每 {} 秒检测一次)...",
                fast_retry_interval.as_secs()
            );
            let mut fast_timer = interval(fast_retry_interval);
            fast_timer.set_missed_tick_behavior(MissedTickBehavior::Delay);
            fast_timer.reset();
            *timer = fast_timer;
        } else if !has_recent_failures && *in_fast_retry {
            *in_fast_retry = false;
            info!(
                "任务同步已恢复正常或超出快速自愈阈值，定时同步恢复为正常周期: {} 秒",
                current_interval.as_secs()
            );
            let mut normal_timer = interval(current_interval);
            normal_timer.set_missed_tick_behavior(MissedTickBehavior::Delay);
            normal_timer.reset();
            *timer = normal_timer;
        }
    }

    /// 应用配置变更广播中的新轮询间隔
    fn apply_interval_change(
        new_secs: u64,
        current_interval: &mut Duration,
        in_fast_retry: bool,
        timer: &mut Interval,
    ) {
        let clamped_secs = new_secs.max(5);
        if Duration::from_secs(clamped_secs) != *current_interval {
            *current_interval = Duration::from_secs(clamped_secs);
            if !in_fast_retry {
                let mut new_timer = interval(*current_interval);
                new_timer.set_missed_tick_behavior(MissedTickBehavior::Delay);
                new_timer.reset();
                *timer = new_timer;
            }
            info!("DDNS 轮询周期热更新为: {} 秒", clamped_secs);
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

        let startup_grace_deadline = Instant::now() + STARTUP_GRACE_PERIOD;
        let mut trigger_rx_closed = false;
        let mut config_rx_closed = false;
        let mut in_fast_retry = false;

        'engine_loop: loop {
            select! {
                _ = cancel_token.cancelled() => {
                    info!("收到停止信号，DDNS 调度引擎平滑退出");
                    break 'engine_loop;
                }
                _ = timer.tick() => {
                    let in_startup_grace = Instant::now() < startup_grace_deadline;
                    if !self.run_once_cancellable(false, in_startup_grace, &cancel_token).await {
                        info!("定时同步执行期间收到停止信号，DDNS 调度引擎平滑退出");
                        break 'engine_loop;
                    }
                    self.update_fast_retry_timer(&mut timer, &mut in_fast_retry, current_interval);
                }
                manual_req = self.trigger_receiver.recv(), if !trigger_rx_closed => {
                    if manual_req.is_some() {
                        info!("收到手动强制同步触发指令");
                        if !self.run_once_cancellable(true, false, &cancel_token).await {
                            info!("手动同步执行期间收到停止信号，DDNS 调度引擎平滑退出");
                            break 'engine_loop;
                        }
                    } else {
                        warn!("手动同步触发通道已关闭，已停用手动指令监听分支，防止 CPU 空转");
                        trigger_rx_closed = true;
                    }
                }
                res = config_rx.changed(), if !config_rx_closed => {
                    if res.is_ok() {
                        let new_secs = config_rx.borrow_and_update().interval_secs;
                        Self::apply_interval_change(new_secs, &mut current_interval, in_fast_retry, &mut timer);
                    } else {
                        warn!("配置变更广播通道已关闭，已停用配置监听分支，防止 CPU 空转");
                        config_rx_closed = true;
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

    #[cfg(test)]
    pub(crate) fn build_invalid_domain_results(
        invalid_domains: Vec<String>,
        record_type: DnsRecordType,
    ) -> Vec<crate::dns::trait_def::SyncRecordResult> {
        task_runner::build_invalid_domain_results(invalid_domains, record_type)
    }
}
