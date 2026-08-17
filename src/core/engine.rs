use crate::config::model::{AppConfig, DnsTaskConfig};
use crate::config::storage::ConfigManager;
use crate::core::domain::parse_domain_list;
use crate::core::state::StateManager;
use crate::dns::create_dns_provider;
use crate::dns::trait_def::{DnsRecordType, SyncRecordResult, SyncStatus};
use crate::ip_fetcher::create_ip_fetcher;
use crate::notifier::dispatcher::NotificationDispatcher;
use crate::notifier::trait_def::{NotificationEvent, NotificationOverallStatus};
use chrono::Local;
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
}

impl DdnsEngine {
    pub fn new(config_manager: Arc<ConfigManager>) -> (Self, mpsc::Sender<()>) {
        let (tx, rx) = mpsc::channel(10);
        let engine = Self {
            config_manager,
            state_manager: StateManager::new(),
            trigger_receiver: rx,
        };
        (engine, tx)
    }

    /// 执行单次全量任务检查与同步
    pub async fn run_once(&self, force_cloud_sync: bool) {
        let config = self.config_manager.get_config();
        let dispatcher = NotificationDispatcher::new(config.notifications.clone());

        for task in &config.dns_tasks {
            self.process_task(task, &config, &dispatcher, force_cloud_sync)
                .await;
        }
    }

    /// 处理单个 DNS 任务
    async fn process_task(
        &self,
        task: &DnsTaskConfig,
        app_config: &AppConfig,
        dispatcher: &NotificationDispatcher,
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

        let mut current_state = self.state_manager.get_task_state(&task.name);

        // 1. 获取 IPv4
        let ipv4_opt = if let Some(fetcher) = create_ip_fetcher(&task.ipv4) {
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
        };

        // 2. 获取 IPv6
        let ipv6_opt = if let Some(fetcher) = create_ip_fetcher(&task.ipv6) {
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
        };

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
        let dns_provider = match create_dns_provider(&task.provider) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("[{}] 创建 DNS 服务商驱动失败: {}", task.name, e);
                return;
            }
        };

        let mut sync_results: Vec<SyncRecordResult> = Vec::new();

        // 4. 同步 IPv4 域名
        if task.ipv4.enabled
            && let Some(ipv4) = ipv4_opt
        {
            let parsed_domains = parse_domain_list(&task.ipv4.domains);
            for domain in parsed_domains {
                match dns_provider
                    .sync_record(&domain, DnsRecordType::A, &IpAddr::V4(ipv4), task.ttl)
                    .await
                {
                    Ok(res) => sync_results.push(res),
                    Err(e) => {
                        tracing::error!(
                            "[{}] 同步域名 {} (A 记录) 失败: {}",
                            task.name,
                            domain.full_domain(),
                            e
                        );
                        sync_results.push(SyncRecordResult {
                            domain: domain.full_domain(),
                            record_type: DnsRecordType::A,
                            target_ip: ipv4.to_string(),
                            status: SyncStatus::Failed,
                            message: e.to_string(),
                        });
                    }
                }
            }
        }

        // 5. 同步 IPv6 域名
        if task.ipv6.enabled
            && let Some(ipv6) = ipv6_opt
        {
            let parsed_domains = parse_domain_list(&task.ipv6.domains);
            for domain in parsed_domains {
                match dns_provider
                    .sync_record(&domain, DnsRecordType::AAAA, &IpAddr::V6(ipv6), task.ttl)
                    .await
                {
                    Ok(res) => sync_results.push(res),
                    Err(e) => {
                        tracing::error!(
                            "[{}] 同步域名 {} (AAAA 记录) 失败: {}",
                            task.name,
                            domain.full_domain(),
                            e
                        );
                        sync_results.push(SyncRecordResult {
                            domain: domain.full_domain(),
                            record_type: DnsRecordType::AAAA,
                            target_ip: ipv6.to_string(),
                            status: SyncStatus::Failed,
                            message: e.to_string(),
                        });
                    }
                }
            }
        }

        // 6. 更新状态快照
        if ipv4_opt.is_some() {
            current_state.last_ipv4 = ipv4_opt;
        }
        if ipv6_opt.is_some() {
            current_state.last_ipv6 = ipv6_opt;
        }
        current_state.check_counter = 0;

        self.state_manager
            .update_task_state(&task.name, |s| *s = current_state);

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
        let mut config_rx = self.config_manager.subscribe();
        let initial_conf = self.config_manager.get_config();
        let mut current_interval = Duration::from_secs(initial_conf.interval_secs.max(5));
        let mut timer = tokio::time::interval(current_interval);

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
                            timer = tokio::time::interval(current_interval);
                            tracing::info!("DDNS 轮询周期热更新为: {} 秒", new_secs);
                        }
                    }
                }
            }
        }
    }
}
