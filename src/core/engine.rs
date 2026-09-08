use crate::config::model::{AppConfig, DnsTaskConfig};
use crate::config::storage::ConfigManager;
use crate::core::domain::{ParsedDomain, parse_domain_list};
use crate::core::state::{StateManager, TaskRuntimeState};
use crate::dns::create_dns_provider;
use crate::dns::trait_def::{DnsProvider, DnsRecordType, SyncRecordResult, SyncStatus};
use crate::ip_fetcher::create_ip_fetcher;
use crate::notifier::dispatcher::{ErrorTrackerMap, NotificationDispatcher};
use crate::notifier::trait_def::{NotificationEvent, NotificationOverallStatus};
use crate::util::wait_internet::wait_for_internet;
use chrono::Local;
use log::{debug, error, info};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::select;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;
use tokio::time::{MissedTickBehavior, interval};
use tokio_util::sync::CancellationToken;

/// 单任务内向 DNS 服务商并发同步域名的最大协程数，防止瞬时打满平台 QPS 限流
const MAX_CONCURRENT_DNS_SYNCS: usize = 5;

/// 单协议域名并发同步入参对象（参数对象模式，避免平铺多参）
struct ProtocolSyncParams<'a> {
    enabled: bool,
    domains: &'a [ParsedDomain],
    ip_opt: Option<IpAddr>,
    record_type: DnsRecordType,
    provider: Arc<dyn DnsProvider>,
    task_name: String,
    ttl: Option<u32>,
    semaphore: Arc<Semaphore>,
    force_sync_all: bool,
    synced_domains: &'a HashMap<String, String>,
}

/// 评估是否需要向云端发起 DNS 同步的输入参数对象
struct SyncEvaluationParams<'a> {
    task: &'a DnsTaskConfig,
    app_config: &'a AppConfig,
    current_state: &'a TaskRuntimeState,
    v4_domains: &'a [ParsedDomain],
    v6_domains: &'a [ParsedDomain],
    ipv4_opt: Option<Ipv4Addr>,
    ipv6_opt: Option<Ipv6Addr>,
    force_sync: bool,
}

/// 同步完成后更新任务运行时状态的输入参数对象
struct SyncStateUpdateParams<'a> {
    task: &'a DnsTaskConfig,
    current_state: &'a mut TaskRuntimeState,
    v4_count: usize,
    v6_count: usize,
    ipv4_opt: Option<Ipv4Addr>,
    ipv6_opt: Option<Ipv6Addr>,
    sync_results: &'a [SyncRecordResult],
    reach_cache_limit: bool,
}

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
    pub fn new(config_manager: Arc<ConfigManager>) -> (Self, mpsc::Sender<()>) {
        let (tx, rx) = mpsc::channel(10);
        let engine = Self {
            config_manager,
            state_manager: StateManager::new(),
            trigger_receiver: rx,
            error_trackers: Arc::new(RwLock::new(HashMap::new())),
        };
        (engine, tx)
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

        let mut join_set = JoinSet::new();
        for task in config.dns_tasks.clone() {
            if !task.enabled {
                debug!("[{}] 任务已处于禁用状态，跳过后台同步", task.name);
                continue;
            }
            let config_clone = config.clone();
            let dispatcher_clone = dispatcher.clone();
            let state_manager = self.state_manager.clone();
            join_set.spawn(async move {
                Self::process_task(
                    &task,
                    &config_clone,
                    &dispatcher_clone,
                    &state_manager,
                    force_cloud_sync,
                )
                .await;
            });
        }

        while join_set.join_next().await.is_some() {}
    }

    /// 并发探测任务所需的公网 IPv4 与 IPv6 地址
    async fn probe_task_ips(task: &DnsTaskConfig) -> (Option<Ipv4Addr>, Option<Ipv6Addr>) {
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

    /// 评估是否需要向云端发起 DNS 记录同步与比对
    fn evaluate_sync_necessity(params: &SyncEvaluationParams<'_>) -> bool {
        let ipv4_changed = params.ipv4_opt.is_some() && params.ipv4_opt != params.current_state.last_ipv4;
        let ipv6_changed = params.ipv6_opt.is_some() && params.ipv6_opt != params.current_state.last_ipv6;
        let ip_changed = ipv4_changed || ipv6_changed;

        let reach_cache_limit = params.current_state.check_counter >= params.app_config.cache_times;

        let has_unsynced_v4 = params.task.ipv4.enabled
            && params.ipv4_opt.is_some()
            && params.v4_domains.iter().any(|d| {
                let key = format!("{}:{:?}", d.full_domain(), DnsRecordType::A);
                params.current_state.synced_domains.get(&key) != params.ipv4_opt.map(|ip| ip.to_string()).as_ref()
            });
        let has_unsynced_v6 = params.task.ipv6.enabled
            && params.ipv6_opt.is_some()
            && params.v6_domains.iter().any(|d| {
                let key = format!("{}:{:?}", d.full_domain(), DnsRecordType::AAAA);
                params.current_state.synced_domains.get(&key) != params.ipv6_opt.map(|ip| ip.to_string()).as_ref()
            });

        params.force_sync || ip_changed || reach_cache_limit || has_unsynced_v4 || has_unsynced_v6
    }

    /// 同步完成后更新任务的运行时状态快照
    fn update_runtime_state_after_sync(params: SyncStateUpdateParams<'_>) {
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

        let ipv4_all_ok = Self::is_protocol_all_ok(
            params.task.ipv4.enabled,
            params.ipv4_opt.is_some(),
            params.v4_count,
            DnsRecordType::A,
            params.sync_results,
        );
        let ipv6_all_ok = Self::is_protocol_all_ok(
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
            params.current_state.consecutive_failures += 1;
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
    fn dispatch_sync_notification(
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

    /// 验证任务前置条件是否满足
    fn validate_task_preconditions(task: &DnsTaskConfig) -> bool {
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

    /// 处理单个 DNS 任务
    async fn process_task(
        task: &DnsTaskConfig,
        app_config: &AppConfig,
        dispatcher: &NotificationDispatcher,
        state_manager: &StateManager,
        force_sync: bool,
    ) {
        if !Self::validate_task_preconditions(task) {
            return;
        }

        info!("======== 开始执行任务: [{}] ========", task.name);
        let mut current_state = state_manager.get_task_state(&task.name);

        let (ipv4_opt, ipv6_opt) = Self::probe_task_ips(task).await;
        if task.ipv4.enabled {
            current_state.ipv4_fail_count = if ipv4_opt.is_some() {
                0
            } else {
                current_state.ipv4_fail_count + 1
            };
        }
        if task.ipv6.enabled {
            current_state.ipv6_fail_count = if ipv6_opt.is_some() {
                0
            } else {
                current_state.ipv6_fail_count + 1
            };
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

        current_state.check_counter += 1;
        let reach_cache_limit = current_state.check_counter >= app_config.cache_times;
        let should_sync = Self::evaluate_sync_necessity(&SyncEvaluationParams {
            task,
            app_config,
            current_state: &current_state,
            v4_domains: &parsed_v4,
            v6_domains: &parsed_v6,
            ipv4_opt,
            ipv6_opt,
            force_sync,
        });

        if !should_sync {
            info!(
                "[{}] 本地 IP 未发生变动 (IPv4: {:?}, IPv6: {:?})，未达服务商校对周期 ({}/{})，跳过云端请求",
                task.name, ipv4_opt, ipv6_opt, current_state.check_counter, app_config.cache_times
            );
            current_state.last_sync_time =
                Some(Local::now().format("%Y-%m-%d %H:%M:%S").to_string());
            state_manager.update_task_state(&task.name, |s| *s = current_state);
            return;
        }

        if reach_cache_limit {
            info!(
                "[{}] 达到服务商校对周期 ({}/{})，强制发起云端真实记录对比",
                task.name, current_state.check_counter, app_config.cache_times
            );
        }

        let dns_provider = match create_dns_provider(&task.provider, task.http_interface.as_deref())
        {
            Ok(p) => p,
            Err(e) => {
                error!("[{}] 创建 DNS 服务商驱动失败: {}", task.name, e);
                current_state.consecutive_failures += 1;
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

        Self::spawn_protocol_sync_tasks(
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

        Self::spawn_protocol_sync_tasks(
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
        while let Some(res) = sync_join_set.join_next().await {
            if let Ok(r) = res {
                sync_results.push(r);
            }
        }

        Self::update_runtime_state_after_sync(SyncStateUpdateParams {
            task,
            current_state: &mut current_state,
            v4_count: parsed_v4.len(),
            v6_count: parsed_v6.len(),
            ipv4_opt,
            ipv6_opt,
            sync_results: &sync_results,
            reach_cache_limit,
        });
        state_manager.update_task_state(&task.name, |s| *s = current_state);
        Self::dispatch_sync_notification(&task.name, dispatcher, ipv4_opt, ipv6_opt, sync_results);
        info!("======== 任务 [{}] 同步执行完毕 ========\n", task.name);
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

        loop {
            select! {
                _ = cancel_token.cancelled() => {
                    info!("收到停止信号，DDNS 调度引擎平滑退出");
                    break;
                }
                _ = timer.tick() => {
                    self.run_once(false).await;
                }
                manual_req = self.trigger_receiver.recv() => {
                    if manual_req.is_some() {
                        info!("收到手动强制同步触发指令");
                        self.run_once(true).await;
                    }
                }
                res = config_rx.changed() => {
                    if res.is_ok() {
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
                }
            }
        }
    }

    /// 调度单个网络协议 (IPv4/IPv6) 下所有域名的并发同步任务
    fn spawn_protocol_sync_tasks(
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

                if !params.force_sync_all && params.synced_domains.get(&domain_key) == Some(&ip_str)
                {
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

    /// 校验指定协议的所有域名是否均成功同步
    fn is_protocol_all_ok(
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::{IpFetchConfig, IpSourceType, ProviderConfig};

    #[tokio::test]
    async fn test_disabled_task_skipped_in_run_once() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let config_manager = Arc::new(ConfigManager::load_or_create(config_path).unwrap());

        config_manager
            .update_config(AppConfig {
                dns_tasks: vec![DnsTaskConfig {
                    name: "已关闭的任务".to_string(),
                    enabled: false,
                    provider: ProviderConfig::Cloudflare {
                        api_token: Some("dummy_token".to_string()),
                        api_key: None,
                        email: None,
                    },
                    ipv4: IpFetchConfig {
                        enabled: true,
                        source_type: IpSourceType::Url,
                        url_endpoints: vec!["https://api.ipify.org".to_string()],
                        domains: vec!["test.example.com".to_string()],
                        ..Default::default()
                    },
                    ..Default::default()
                }],
                ..Default::default()
            })
            .unwrap();

        let (engine, _tx) = DdnsEngine::new(config_manager.clone());
        engine.run_once(false).await;

        // 验证由于任务被禁用，state_manager 中不应存在该任务的状态记录（从未执行 process_task）
        let state = engine.state_manager.get_task_state("已关闭的任务");
        assert_eq!(state.last_sync_time, None);
        assert_eq!(state.check_counter, 0);
    }
}
