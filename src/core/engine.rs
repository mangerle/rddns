use crate::config::model::{AppConfig, DnsTaskConfig};
use crate::config::storage::ConfigManager;
use crate::core::domain::parse_domain_list;
use crate::core::state::StateManager;
use crate::dns::create_dns_provider;
use crate::dns::trait_def::{DnsRecordType, SyncRecordResult, SyncStatus};
use crate::ip_fetcher::create_ip_fetcher;
use crate::notifier::dispatcher::{ErrorTrackerMap, NotificationDispatcher};
use crate::notifier::trait_def::{NotificationEvent, NotificationOverallStatus};
use chrono::Local;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// DDNS 核心调度引擎
pub struct DdnsEngine {
    config_manager: Arc<ConfigManager>,
    state_manager: StateManager,
    trigger_receiver: mpsc::Receiver<()>,
    error_trackers: ErrorTrackerMap,
}

impl DdnsEngine {
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
        let dispatcher = NotificationDispatcher::new_with_trackers(
            config.notifications.clone(),
            self.error_trackers.clone(),
        );

        let mut join_set = tokio::task::JoinSet::new();
        for task in config.dns_tasks.clone() {
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

    /// 处理单个 DNS 任务
    async fn process_task(
        task: &DnsTaskConfig,
        app_config: &AppConfig,
        dispatcher: &NotificationDispatcher,
        state_manager: &StateManager,
        force_sync: bool,
    ) {
        if !task.provider.is_configured() {
            tracing::info!(
                "[{}] 未配置有效的 DNS 服务商认证凭据，跳过同步（请访问 Web 界面 http://localhost:9876 完成配置）",
                task.name
            );
            return;
        }

        if !task.has_domains() {
            tracing::info!(
                "[{}] 未配置需要解析的域名，跳过同步（请访问 Web 界面添加解析域名）",
                task.name
            );
            return;
        }

        tracing::info!("======== 开始执行任务: [{}] ========", task.name);

        let mut current_state = state_manager.get_task_state(&task.name);

        // 1. 并发探测 IPv4 与 IPv6
        let v4_fetcher = create_ip_fetcher(&task.ipv4, task.http_interface.as_deref());
        let v6_fetcher = create_ip_fetcher(&task.ipv6, task.http_interface.as_deref());

        let (ipv4_opt, ipv6_opt) = tokio::join!(
            async {
                if let Some(fetcher) = v4_fetcher {
                    match fetcher.fetch_ipv4().await {
                        Ok(ip) => {
                            if let Some(ref v4) = ip {
                                tracing::info!("[{}] 探测到当前公网 IPv4: {}", task.name, v4);
                            }
                            ip
                        }
                        Err(e) => {
                            tracing::error!("[{}] 获取 IPv4 失败: {}", task.name, e);
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
                                tracing::info!("[{}] 探测到当前公网 IPv6: {}", task.name, v6);
                            }
                            ip
                        }
                        Err(e) => {
                            tracing::error!("[{}] 获取 IPv6 失败: {}", task.name, e);
                            None
                        }
                    }
                } else {
                    None
                }
            }
        );

        // 维护 IP 获取状态计数
        if task.ipv4.enabled {
            if ipv4_opt.is_some() {
                current_state.ipv4_fail_count = 0;
            } else {
                current_state.ipv4_fail_count += 1;
            }
        }
        if task.ipv6.enabled {
            if ipv6_opt.is_some() {
                current_state.ipv6_fail_count = 0;
            } else {
                current_state.ipv6_fail_count += 1;
            }
        }

        // 判断 IP 是否发生变动
        let ipv4_changed = ipv4_opt.is_some() && ipv4_opt != current_state.last_ipv4;
        let ipv6_changed = ipv6_opt.is_some() && ipv6_opt != current_state.last_ipv6;
        let ip_changed = ipv4_changed || ipv6_changed;

        current_state.check_counter += 1;
        let reach_cache_limit = current_state.check_counter >= app_config.cache_times;

        let should_sync_cloud = force_sync || ip_changed || reach_cache_limit;

        if !should_sync_cloud {
            tracing::info!(
                "[{}] 本地 IP 未发生变动 (IPv4: {:?}, IPv6: {:?})，未达服务商校对周期 ({}/{})，跳过云端请求",
                task.name,
                ipv4_opt,
                ipv6_opt,
                current_state.check_counter,
                app_config.cache_times
            );
            current_state.last_sync_time =
                Some(Local::now().format("%Y-%m-%d %H:%M:%S").to_string());
            state_manager.update_task_state(&task.name, |s| *s = current_state);
            return;
        }

        if reach_cache_limit {
            tracing::info!(
                "[{}] 达到服务商校对周期 ({}/{})，强制发起云端真实记录对比",
                task.name,
                current_state.check_counter,
                app_config.cache_times
            );
        }

        // 3. 构建 DNS 提供商驱动
        let dns_provider: Arc<dyn crate::dns::trait_def::DnsProvider> =
            match create_dns_provider(&task.provider, task.http_interface.as_deref()) {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!("[{}] 创建 DNS 服务商驱动失败: {}", task.name, e);
                    current_state.consecutive_failures += 1;
                    current_state.last_error = Some(format!("创建 DNS 服务商驱动失败: {}", e));
                    current_state.last_sync_time =
                        Some(Local::now().format("%Y-%m-%d %H:%M:%S").to_string());
                    state_manager.update_task_state(&task.name, |s| *s = current_state);
                    return;
                }
            };

        let mut sync_join_set = tokio::task::JoinSet::new();

        let parsed_v4_domains = if task.ipv4.enabled {
            parse_domain_list(&task.ipv4.domains)
        } else {
            Vec::new()
        };
        let parsed_v6_domains = if task.ipv6.enabled {
            parse_domain_list(&task.ipv6.domains)
        } else {
            Vec::new()
        };

        // 4. 并发调度 IPv4 域名同步任务
        if task.ipv4.enabled {
            if let Some(ipv4) = ipv4_opt {
                for domain in &parsed_v4_domains {
                    let domain = domain.clone();
                    let provider = dns_provider.clone();
                    let task_name = task.name.clone();
                    let ttl = task.ttl;
                    sync_join_set.spawn(async move {
                        let start_time = std::time::Instant::now();
                        let full_domain = domain.full_domain();
                        match provider
                            .sync_record(&domain, DnsRecordType::A, &IpAddr::V4(ipv4), ttl)
                            .await
                        {
                            Ok(res) => {
                                let cost_ms = start_time.elapsed().as_millis();
                                tracing::info!(
                                    "[{}] 同步域名 {} (A 记录) 完成: {} (耗时 {}ms)",
                                    task_name,
                                    full_domain,
                                    res.status.as_str(),
                                    cost_ms
                                );
                                res
                            }
                            Err(e) => {
                                let cost_ms = start_time.elapsed().as_millis();
                                tracing::error!(
                                    "[{}] 同步域名 {} (A 记录) 失败: {} (耗时 {}ms)",
                                    task_name,
                                    full_domain,
                                    e,
                                    cost_ms
                                );
                                SyncRecordResult {
                                    domain: full_domain,
                                    record_type: DnsRecordType::A,
                                    target_ip: ipv4.to_string(),
                                    status: SyncStatus::Failed,
                                    message: e.to_string(),
                                }
                            }
                        }
                    });
                }
            } else {
                for domain in &parsed_v4_domains {
                    let full_domain = domain.full_domain();
                    sync_join_set.spawn(async move {
                        SyncRecordResult {
                            domain: full_domain,
                            record_type: DnsRecordType::A,
                            target_ip: "未知/获取失败".to_string(),
                            status: SyncStatus::Failed,
                            message: "获取本地公网 IPv4 地址失败".to_string(),
                        }
                    });
                }
            }
        }

        // 5. 并发调度 IPv6 域名同步任务
        if task.ipv6.enabled {
            if let Some(ipv6) = ipv6_opt {
                for domain in &parsed_v6_domains {
                    let domain = domain.clone();
                    let provider = dns_provider.clone();
                    let task_name = task.name.clone();
                    let ttl = task.ttl;
                    sync_join_set.spawn(async move {
                        let start_time = std::time::Instant::now();
                        let full_domain = domain.full_domain();
                        match provider
                            .sync_record(&domain, DnsRecordType::AAAA, &IpAddr::V6(ipv6), ttl)
                            .await
                        {
                            Ok(res) => {
                                let cost_ms = start_time.elapsed().as_millis();
                                tracing::info!(
                                    "[{}] 同步域名 {} (AAAA 记录) 完成: {} (耗时 {}ms)",
                                    task_name,
                                    full_domain,
                                    res.status.as_str(),
                                    cost_ms
                                );
                                res
                            }
                            Err(e) => {
                                let cost_ms = start_time.elapsed().as_millis();
                                tracing::error!(
                                    "[{}] 同步域名 {} (AAAA 记录) 失败: {} (耗时 {}ms)",
                                    task_name,
                                    full_domain,
                                    e,
                                    cost_ms
                                );
                                SyncRecordResult {
                                    domain: full_domain,
                                    record_type: DnsRecordType::AAAA,
                                    target_ip: ipv6.to_string(),
                                    status: SyncStatus::Failed,
                                    message: e.to_string(),
                                }
                            }
                        }
                    });
                }
            } else {
                for domain in &parsed_v6_domains {
                    let full_domain = domain.full_domain();
                    sync_join_set.spawn(async move {
                        SyncRecordResult {
                            domain: full_domain,
                            record_type: DnsRecordType::AAAA,
                            target_ip: "未知/获取失败".to_string(),
                            status: SyncStatus::Failed,
                            message: "获取本地公网 IPv6 地址失败".to_string(),
                        }
                    });
                }
            }
        }

        let mut sync_results: Vec<SyncRecordResult> = Vec::new();
        while let Some(res) = sync_join_set.join_next().await {
            if let Ok(r) = res {
                sync_results.push(r);
            }
        }

        // 6. 更新状态快照 (仅当对应协议的所有域名均成功同步时才更新 last_ip，避免失败后被误判为未变动而长期不重试)
        let ipv4_all_ok = if task.ipv4.enabled {
            if ipv4_opt.is_some() {
                let parsed_v4_count = parsed_v4_domains.len();
                let v4_success_count = sync_results
                    .iter()
                    .filter(|r| r.record_type == DnsRecordType::A && r.status != SyncStatus::Failed)
                    .count();
                parsed_v4_count == 0 || v4_success_count == parsed_v4_count
            } else {
                false
            }
        } else {
            true
        };

        let ipv6_all_ok = if task.ipv6.enabled {
            if ipv6_opt.is_some() {
                let parsed_v6_count = parsed_v6_domains.len();
                let v6_success_count = sync_results
                    .iter()
                    .filter(|r| {
                        r.record_type == DnsRecordType::AAAA && r.status != SyncStatus::Failed
                    })
                    .count();
                parsed_v6_count == 0 || v6_success_count == parsed_v6_count
            } else {
                false
            }
        } else {
            true
        };

        if ipv4_all_ok && ipv4_opt.is_some() {
            current_state.last_ipv4 = ipv4_opt;
        }
        if ipv6_all_ok && ipv6_opt.is_some() {
            current_state.last_ipv6 = ipv6_opt;
        }

        current_state.last_sync_time = Some(Local::now().format("%Y-%m-%d %H:%M:%S").to_string());

        if ipv4_all_ok && ipv6_all_ok {
            current_state.check_counter = 0;
            current_state.consecutive_failures = 0;
            current_state.last_error = None;
        } else {
            current_state.consecutive_failures += 1;
            let failed_msgs: Vec<String> = sync_results
                .iter()
                .filter(|r| r.status == SyncStatus::Failed)
                .map(|r| format!("{}: {}", r.domain, r.message))
                .collect();
            if !failed_msgs.is_empty() {
                current_state.last_error = Some(failed_msgs.join("; "));
            }
        }

        state_manager.update_task_state(&task.name, |s| *s = current_state);

        // 7. 发送通知事件
        if !sync_results.is_empty() {
            let has_success = sync_results.iter().any(|r| r.status != SyncStatus::Failed);
            let has_failed = sync_results.iter().any(|r| r.status == SyncStatus::Failed);
            // 精准判断云端 DNS 记录是否发生了真实的创建或修改变动
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

            let event = NotificationEvent {
                overall_status,
                title: format!("rddns 同步通知 - [{}]", task.name),
                task_name: task.name.clone(),
                ipv4: ipv4_opt,
                ipv6: ipv6_opt,
                ip_changed: has_actual_updates,
                results: sync_results,
                timestamp: Local::now(),
            };

            dispatcher.dispatch(event);
        }

        tracing::info!("======== 任务 [{}] 同步执行完毕 ========\n", task.name);
    }

    /// 启动引擎后台主循环
    pub async fn run_loop(mut self, cancel_token: CancellationToken) {
        // 开机网络探测：在后台异步探测网络就绪（最大等待 120 秒），若收到退出信号可提前退出
        tokio::select! {
            _ = cancel_token.cancelled() => {
                tracing::info!("收到停止信号，DDNS 调度引擎平滑退出");
                return;
            }
            _ = crate::util::wait_internet::wait_for_internet(120, 3) => {}
        }

        let mut config_rx = self.config_manager.subscribe();
        let initial_conf = self.config_manager.get_config();
        let mut current_interval = Duration::from_secs(initial_conf.interval_secs.max(5));
        let mut timer = tokio::time::interval(current_interval);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = cancel_token.cancelled() => {
                    tracing::info!("收到停止信号，DDNS 调度引擎平滑退出");
                    break;
                }
                _ = timer.tick() => {
                    self.run_once(false).await;
                }
                manual_req = self.trigger_receiver.recv() => {
                    if manual_req.is_some() {
                        tracing::info!("收到手动强制同步触发指令");
                        self.run_once(true).await;
                    }
                }
                res = config_rx.changed() => {
                    if res.is_ok() {
                        let new_conf = config_rx.borrow_and_update().clone();
                        let new_secs = new_conf.interval_secs.max(5);
                        if Duration::from_secs(new_secs) != current_interval {
                            current_interval = Duration::from_secs(new_secs);
                            let mut new_timer = tokio::time::interval(current_interval);
                            new_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                            new_timer.reset();
                            timer = new_timer;
                            tracing::info!("DDNS 轮询周期热更新为: {} 秒", new_secs);
                        }
                    }
                }
            }
        }
    }
}
