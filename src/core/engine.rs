use crate::config::model::{AppConfig, DnsTaskConfig};
use crate::config::storage::ConfigManager;
use crate::core::domain::{ParsedDomain, parse_domain_list};
use crate::core::state::StateManager;
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
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Semaphore, mpsc};
use tokio_util::sync::CancellationToken;

/// 单任务内向 DNS 服务商并发同步域名的最大协程数，防止瞬时打满平台 QPS 限流
const MAX_CONCURRENT_DNS_SYNCS: usize = 5;

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

    /// 处理单个 DNS 任务
    async fn process_task(
        task: &DnsTaskConfig,
        app_config: &AppConfig,
        dispatcher: &NotificationDispatcher,
        state_manager: &StateManager,
        force_sync: bool,
    ) {
        if !task.enabled {
            debug!("[{}] 任务已处于禁用状态，跳过后台同步", task.name);
            return;
        }

        if !task.provider.is_configured() {
            info!(
                "[{}] 未配置有效的 DNS 服务商认证凭据，跳过同步（请访问 Web 界面 http://localhost:9876 完成配置）",
                task.name
            );
            return;
        }

        if !task.has_domains() {
            info!(
                "[{}] 未配置需要解析的域名，跳过同步（请访问 Web 界面添加解析域名）",
                task.name
            );
            return;
        }

        info!("======== 开始执行任务: [{}] ========", task.name);

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

        // 3. 构建 DNS 提供商驱动
        let dns_provider: Arc<dyn DnsProvider> =
            match create_dns_provider(&task.provider, task.http_interface.as_deref()) {
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

        // 4. 并发调度 IPv4 / IPv6 域名同步任务（通过信号量限制单任务最大并发数为 5）
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_DNS_SYNCS));

        Self::spawn_protocol_sync_tasks(
            &mut sync_join_set,
            task.ipv4.enabled,
            &parsed_v4_domains,
            ipv4_opt.map(IpAddr::V4),
            DnsRecordType::A,
            dns_provider.clone(),
            task.name.clone(),
            task.ttl,
            semaphore.clone(),
        );

        Self::spawn_protocol_sync_tasks(
            &mut sync_join_set,
            task.ipv6.enabled,
            &parsed_v6_domains,
            ipv6_opt.map(IpAddr::V6),
            DnsRecordType::AAAA,
            dns_provider.clone(),
            task.name.clone(),
            task.ttl,
            semaphore.clone(),
        );

        let mut sync_results: Vec<SyncRecordResult> = Vec::new();
        while let Some(res) = sync_join_set.join_next().await {
            if let Ok(r) = res {
                sync_results.push(r);
            }
        }

        // 5. 更新状态快照 (仅当对应协议的所有域名均成功同步时才更新 last_ip，避免失败后被误判为未变动而长期不重试)
        let ipv4_all_ok = Self::is_protocol_all_ok(
            task.ipv4.enabled,
            ipv4_opt.is_some(),
            parsed_v4_domains.len(),
            DnsRecordType::A,
            &sync_results,
        );

        let ipv6_all_ok = Self::is_protocol_all_ok(
            task.ipv6.enabled,
            ipv6_opt.is_some(),
            parsed_v6_domains.len(),
            DnsRecordType::AAAA,
            &sync_results,
        );

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
                task_name: task.name.clone(),
                ipv4: ipv4_opt,
                ipv6: ipv6_opt,
                ip_changed: has_actual_updates,
                results: sync_results,
                timestamp: Local::now(),
            };

            dispatcher.dispatch(event);
        }

        info!("======== 任务 [{}] 同步执行完毕 ========\n", task.name);
    }

    /// 启动引擎后台主循环
    pub async fn run_loop(mut self, cancel_token: CancellationToken) {
        // 开机网络探测：在后台异步探测网络就绪（最大等待 120 秒），若收到退出信号可提前退出
        tokio::select! {
            _ = cancel_token.cancelled() => {
                info!("收到停止信号，DDNS 调度引擎平滑退出");
                return;
            }
            _ = wait_for_internet(120, 3) => {}
        }

        let mut config_rx = self.config_manager.subscribe();
        let initial_conf = self.config_manager.get_config();
        let mut current_interval = Duration::from_secs(initial_conf.interval_secs.max(5));
        let mut timer = tokio::time::interval(current_interval);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
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
                            let mut new_timer = tokio::time::interval(current_interval);
                            new_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
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
    #[allow(clippy::too_many_arguments)]
    fn spawn_protocol_sync_tasks(
        sync_join_set: &mut tokio::task::JoinSet<SyncRecordResult>,
        enabled: bool,
        domains: &[ParsedDomain],
        ip_opt: Option<IpAddr>,
        record_type: DnsRecordType,
        provider: Arc<dyn DnsProvider>,
        task_name: String,
        ttl: Option<u32>,
        semaphore: Arc<Semaphore>,
    ) {
        if !enabled {
            return;
        }

        let type_str = match record_type {
            DnsRecordType::A => "A 记录",
            DnsRecordType::AAAA => "AAAA 记录",
        };

        if let Some(ip) = ip_opt {
            for domain in domains {
                let domain = domain.clone();
                let provider = provider.clone();
                let task_name = task_name.clone();
                let sem = semaphore.clone();
                sync_join_set.spawn(async move {
                    let _permit = sem.acquire().await.ok();
                    let start_time = std::time::Instant::now();
                    let full_domain = domain.full_domain();
                    match provider.sync_record(&domain, record_type, &ip, ttl).await {
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
                                record_type,
                                ip.to_string(),
                                e.to_string(),
                            )
                        }
                    }
                });
            }
        } else {
            for domain in domains {
                let full_domain = domain.full_domain();
                let fail_msg = match record_type {
                    DnsRecordType::A => "获取本地公网 IPv4 地址失败",
                    DnsRecordType::AAAA => "获取本地公网 IPv6 地址失败",
                };
                sync_join_set.spawn(async move {
                    SyncRecordResult::failed(full_domain, record_type, "未知/获取失败", fail_msg)
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
