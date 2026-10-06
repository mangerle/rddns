use crate::config::model::NotificationConfig;
use crate::notifier::bark::BarkNotifier;
use crate::notifier::dingtalk::DingTalkNotifier;
use crate::notifier::feishu::FeishuNotifier;
use crate::notifier::mail::EmailNotifier;
use crate::notifier::telegram::TelegramNotifier;
use crate::notifier::trait_def::{NotificationEvent, NotificationOverallStatus, Notifier};
use crate::notifier::webhook::CustomWebhookNotifier;
use crate::notifier::wechat_official::WechatOfficialNotifier;
use crate::notifier::wecom::WeComNotifier;
use log::{debug, error, warn};
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

/// 错误追踪表触发过期清理的软阈值条数
const TRACKER_SOFT_LIMIT: usize = 256;
/// 错误追踪表绝对硬上限，防止内存无限膨胀
const TRACKER_HARD_LIMIT: usize = 512;
/// 错误记录最长留存时间（1 小时），超时条目自动清理
const ERROR_TRACKER_TTL: Duration = Duration::from_secs(3600);
/// 相同错误防风暴告警冷却窗口（30 分钟）
const ERROR_SUPPRESSION_TTL: Duration = Duration::from_secs(1800);

/// 全局在途通知任务并发上限 (P1-13)
///
/// # 设计原理
/// - **实现初衷**: `dispatch_internal` 为保持「即发即忘」语义而不阻塞 DDNS
///   主同步循环，每轮会派生「渠道数 + 1」个任务且**无任何数量约束**。
///   最短同步间隔为 5 秒，而单渠道最长耗时可达约 36 秒（10 秒超时 × 3 次
///   尝试 + 梯级退避），稳态下在途任务可无界累积上百个，最终演变为
///   协程与内存的双重膨胀。
/// - **核心优势**: 以全局 `Semaphore` 为在途任务数设上限，超限时立即拒绝
///   并记录告警。通知属于「尽力而为」的旁路能力，为保障 DDNS 主流程可用性
///   而拒绝过量通知，是明确的取舍而非缺陷。
const MAX_INFLIGHT_NOTIFY_TASKS: usize = 32;

/// 全局在途通知任务并发闸门
static NOTIFY_INFLIGHT_GATE: LazyLock<Semaphore> =
    LazyLock::new(|| Semaphore::new(MAX_INFLIGHT_NOTIFY_TASKS));

/// 全局通知监管任务追踪表 (P1-13)
///
/// # 设计原理
/// 监管任务若以 `let _ = spawn(...)` 形式派生，其 `JoinHandle` 会随
/// 作用域结束被丢弃——生命周期完全脱离追踪，与项目「严禁脱缰孤儿任务」
/// 的约定相悖，且 panic 无人收割。
///
/// `JoinSet` 本身不满足 `Sync`（需 `&mut` 才能收割），无法直接作为
/// `static`。故以 `parking_lot::Mutex` 包裹：`dispatch` 为同步函数，
/// 锁内仅执行一次 `spawn`（微秒级），收割发生在 `JoinSet::join_next`
/// 的异步轮询中，二者不共享临界区。
static HARVESTER_TRACKER: LazyLock<Mutex<JoinSet<()>>> =
    LazyLock::new(|| Mutex::new(JoinSet::new()));

/// 错误告警状态跟踪（用于防风暴抑制）
#[derive(Debug, Clone)]
pub struct ErrorTracker {
    pub last_error_summary: String,
    pub last_notified_at: Instant,
    pub suppressed_count: u32,
}

pub type ErrorTrackerMap = Arc<RwLock<HashMap<String, ErrorTracker>>>;

// 投递状态类型已下沉至 `core::state`（P1-17）：状态类型应与「谁拥有状态」
// 同层，而非与「谁写入状态」同层。此处反向消费以保持
// `core → notifier` 的单向依赖方向。
pub use crate::core::state::{ChannelDeliveryStatus, DeliveryStatusMap};

/// 全局多渠道通知分发器
///
/// # 设计原理
/// - **实现初衷**: 集中管理系统向多渠道（企业微信、钉钉、飞书、Telegram、Bark、邮件、自定义 Webhook、微信公众号）的异步告警分发，屏蔽底层推送细节差异。
/// - **核心优势**: 内置防告警风暴（30分钟冷却窗口与同错误折叠计数）、按 IP 变动过滤静默机制，并采用无锁化与后台并发异步推送，杜绝因通知网络阻塞影响 DDNS 主同步循环。
/// - **代价与局限**: 跨任务持久化的错误追踪表常驻内存（内置最多 256 条并按 1 小时自动淘汰），占用极少内存。
#[derive(Clone)]
pub struct NotificationDispatcher {
    notifiers: Vec<Arc<dyn Notifier>>,
    config: NotificationConfig,
    error_trackers: ErrorTrackerMap,
    delivery_statuses: DeliveryStatusMap,
}

impl NotificationDispatcher {
    /// 创建通知分发器实例
    pub fn new(config: NotificationConfig) -> Self {
        Self::new_with_trackers_and_statuses(
            config,
            Arc::new(RwLock::new(HashMap::new())),
            Arc::new(RwLock::new(HashMap::new())),
        )
    }

    /// 支持传入外部持久化的错误跟踪器（供 Engine 跨周期保留冷却状态）
    pub fn new_with_trackers(config: NotificationConfig, trackers: ErrorTrackerMap) -> Self {
        Self::new_with_trackers_and_statuses(
            config,
            trackers,
            Arc::new(RwLock::new(HashMap::new())),
        )
    }

    /// 支持传入外部持久化的错误跟踪器与渠道投递状态表（供 Engine 与 Web 状态管理器共享）
    pub fn new_with_trackers_and_statuses(
        config: NotificationConfig,
        trackers: ErrorTrackerMap,
        delivery_statuses: DeliveryStatusMap,
    ) -> Self {
        let notifiers = Self::build_enabled_notifiers(&config);
        Self {
            notifiers,
            config,
            error_trackers: trackers,
            delivery_statuses,
        }
    }

    /// 获取全部通知渠道的最新投递状态快照
    pub fn snapshot_delivery_statuses(&self) -> HashMap<String, ChannelDeliveryStatus> {
        self.delivery_statuses.read().clone()
    }

    /// 根据配置初始化所有启用的通知渠道实例
    fn build_enabled_notifiers(config: &NotificationConfig) -> Vec<Arc<dyn Notifier>> {
        let mut notifiers: Vec<Arc<dyn Notifier>> = Vec::new();

        if let Some(ref wx) = config.wechat_official
            && wx.enabled
        {
            notifiers.push(Arc::new(WechatOfficialNotifier::new(wx.clone())));
        }
        if let Some(ref wecom) = config.wecom
            && wecom.enabled
        {
            notifiers.push(Arc::new(WeComNotifier::new(wecom.clone())));
        }
        if let Some(ref tg) = config.telegram
            && tg.enabled
        {
            notifiers.push(Arc::new(TelegramNotifier::new(tg.clone())));
        }
        if let Some(ref dt) = config.dingtalk
            && dt.enabled
        {
            notifiers.push(Arc::new(DingTalkNotifier::new(dt.clone())));
        }
        if let Some(ref fs) = config.feishu
            && fs.enabled
        {
            notifiers.push(Arc::new(FeishuNotifier::new(fs.clone())));
        }
        if let Some(ref bark) = config.bark
            && bark.enabled
        {
            notifiers.push(Arc::new(BarkNotifier::new(bark.clone())));
        }
        if let Some(ref email) = config.email
            && email.enabled
        {
            notifiers.push(Arc::new(EmailNotifier::new(email.clone())));
        }
        if let Some(ref wh) = config.webhook
            && wh.enabled
        {
            notifiers.push(Arc::new(CustomWebhookNotifier::new(wh.clone())));
        }

        notifiers
    }

    /// 触发通知事件派发（受策略与防风暴抑制规则控制）
    pub fn dispatch(&self, event: NotificationEvent) {
        self.dispatch_internal(event, false);
    }

    /// 强制派发通知（供 Web 界面手动“测试通知”使用，绕过过滤策略与防风暴抑制）
    pub fn dispatch_force(&self, event: NotificationEvent) {
        self.dispatch_internal(event, true);
    }

    /// 策略过滤检查：判断当前事件是否应被策略过滤忽略
    fn should_filter_event(&self, event: &NotificationEvent) -> bool {
        // 策略过滤: 仅当记录发生实际增改时才发送成功通知
        if self.config.on_ip_change_only
            && !event.ip_changed
            && event.overall_status == NotificationOverallStatus::Success
        {
            debug!(
                "[{}] 域名解析记录未发生实际变动，静默跳过成功通知",
                event.task_name
            );
            return true;
        }

        match event.overall_status {
            NotificationOverallStatus::Success => {
                if !self.config.on_success {
                    debug!("同步成功，但配置关闭了成功通知，跳过发送");
                    return true;
                }
                self.error_trackers.write().remove(&event.task_name);
                false
            }
            NotificationOverallStatus::Failed | NotificationOverallStatus::PartialSuccess => {
                if !self.config.on_failure {
                    debug!("同步存在失败，但配置关闭了失败报警，跳过发送");
                    return true;
                }
                self.check_and_update_error_throttle(&event.task_name, event.error_fingerprint())
            }
        }
    }

    /// 检查并更新错误冷却状态，返回 true 表示需被抑制
    ///
    /// # 设计原理
    /// - **实现初衷**: 避免任务持续失败时高频推送告警造成通知风暴，并在短时间内大量新错误涌入时防止内存无限膨胀。
    /// - **核心优势**: 软限制 (256 条) 触发过期数据清理，硬限制 (512 条) 淘汰最长未告警（即最早通知记录）条目，确保内存恒定有界。
    fn check_and_update_error_throttle(&self, task_name: &str, error_summary: String) -> bool {
        let mut trackers = self.error_trackers.write();

        // 1. 达到软阈值时淘汰过期项
        if trackers.len() >= TRACKER_SOFT_LIMIT {
            trackers.retain(|_, t| t.last_notified_at.elapsed() < ERROR_TRACKER_TTL);
        }

        // 2. 若依然达到硬上限且当前任务不在表中，淘汰最早通知（最长未告警）的条目
        if !trackers.contains_key(task_name)
            && trackers.len() >= TRACKER_HARD_LIMIT
            && let Some(oldest_key) = trackers
                .iter()
                .min_by_key(|(_, t)| t.last_notified_at)
                .map(|(k, _)| k.clone())
        {
            trackers.remove(&oldest_key);
        }

        if let Some(tracker) = trackers.get_mut(task_name) {
            if tracker.last_error_summary == error_summary
                && tracker.last_notified_at.elapsed() < ERROR_SUPPRESSION_TTL
            {
                tracker.suppressed_count = tracker.suppressed_count.saturating_add(1);
                warn!(
                    "任务 [{}] 出现相同错误，处于冷却抑制中 (已抑制 {} 次)，暂不重复报警",
                    task_name, tracker.suppressed_count
                );
                return true;
            }
            tracker.last_error_summary = error_summary;
            tracker.last_notified_at = Instant::now();
            tracker.suppressed_count = 0;
        } else {
            trackers.insert(
                task_name.to_string(),
                ErrorTracker {
                    last_error_summary: error_summary,
                    last_notified_at: Instant::now(),
                    suppressed_count: 0,
                },
            );
        }
        false
    }

    /// 内部通知分发执行
    ///
    /// # 设计原理
    /// 各渠道推送相互独立，单个渠道失败不应影响其他渠道。为避免通知网络
    /// 延迟阻塞 DDNS 主同步循环，本函数保持「即发即忘」语义。
    ///
    /// # 在途任务限流 (P1-13)
    /// 每轮派生「渠道数 + 1」个任务且无数量约束时，最短同步间隔（5 秒）
    /// 小于单渠道最长耗时（约 36 秒），稳态下在途任务会无界累积。故在派生
    /// 前先申请全局闸门许可，无许可时立即拒绝并告警——通知属旁路能力，
    /// 为保障 DDNS 主流程可用性而拒绝过量通知是明确取舍。
    ///
    /// # 任务生命周期
    /// 监管任务的 `JoinHandle` 交由全局收割表纳管（见 [`Self::spawn_harvester`]），
    /// 确保其生命周期可追踪、可等待，避免脱缰孤儿任务。
    fn dispatch_internal(&self, event: NotificationEvent, force: bool) {
        if self.notifiers.is_empty() {
            return;
        }

        if !force && self.should_filter_event(&event) {
            return;
        }

        // 一次性申请本轮全部渠道所需许可，避免部分渠道被派发、部分被拒
        let permits = match NOTIFY_INFLIGHT_GATE.try_acquire_many(self.notifiers.len() as u32) {
            Ok(p) => p,
            Err(_) => {
                warn!(
                    "在途通知任务已达上限 ({})，本次通知分发被拒绝以避免任务无界堆积",
                    MAX_INFLIGHT_NOTIFY_TASKS
                );
                return;
            }
        };

        let ev_arc = std::sync::Arc::new(event);
        let mut join_set = JoinSet::new();
        for notifier in &self.notifiers {
            let n = notifier.clone();
            let ev = ev_arc.clone();
            join_set.spawn(async move {
                let name = n.channel_name().to_string();
                let res = Self::send_with_retry(n, ev).await;
                (name, res)
            });
        }

        let statuses = self.delivery_statuses.clone();
        // 监管任务：收割各渠道句柄与投递结果，确保 panic 可被识别并聚合投递状态 (P2-7, P3-15)
        //
        let mut tracker = HARVESTER_TRACKER.lock();
        // 惰性收割已完成的历史监管任务，防止追踪表无界膨胀并感知 panic (P1-13)
        while let Some(res) = tracker.try_join_next() {
            if let Err(join_err) = res
                && join_err.is_panic()
            {
                error!("通知监管任务发生 panic: {}", join_err);
            }
        }

        tracker.spawn(async move {
            // 许可令牌随本任务存活，任务结束时自动释放闸门配额
            let _permits = permits;
            while let Some(res) = join_set.join_next().await {
                match res {
                    Ok((channel_name, delivery_res)) => {
                        let now = chrono::Local::now().to_rfc3339();
                        let mut guard = statuses.write();
                        let entry = guard.entry(channel_name.clone()).or_insert_with(|| {
                            ChannelDeliveryStatus {
                                channel_name,
                                ..Default::default()
                            }
                        });
                        match delivery_res {
                            Ok(()) => {
                                entry.last_success_time = Some(now);
                                entry.success_count = entry.success_count.saturating_add(1);
                            }
                            Err(e) => {
                                entry.last_failure_time = Some(now);
                                let truncated: String = e.chars().take(500).collect();
                                entry.last_error = Some(truncated);
                                entry.failure_count = entry.failure_count.saturating_add(1);
                            }
                        }
                    }
                    Err(join_err) => {
                        if join_err.is_panic() {
                            error!("通知渠道任务发生 panic，该渠道推送已中断: {}", join_err);
                        }
                    }
                }
            }
        });
    }

    /// 尝试发送通知并在网络异常时进行有限重试 (最多重试 2 次，共 3 次尝试)
    ///
    /// 区分瞬时网络抖动与 4xx/认证配置错误等永久性错误，永久错误立即中止重试并输出日志；
    /// 重试退避引入轻量 Jitter，防范并发渠道重试风暴 (P2-8)。
    async fn send_with_retry(
        notifier: Arc<dyn Notifier>,
        ev: Arc<NotificationEvent>,
    ) -> Result<(), String> {
        const MAX_RETRIES: usize = 2;
        let mut attempt = 0;
        loop {
            match notifier.send(&ev).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    // 若属于 4xx 客户端认证或语法配置等永久错误，直接中止，无需重试
                    if !e.is_retryable() {
                        error!(
                            "[{}] 渠道发送通知遇到永久性错误，放弃重试: {}",
                            notifier.channel_name(),
                            e
                        );
                        return Err(e.to_string());
                    }

                    if attempt >= MAX_RETRIES {
                        error!(
                            "[{}] 渠道发送通知最终失败（已重试 {} 次）: {}",
                            notifier.channel_name(),
                            attempt,
                            e
                        );
                        return Err(e.to_string());
                    }
                    attempt += 1;
                    // 指数退避叠加轻量 Jitter (0~200ms)
                    let jitter_ms = (std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .subsec_nanos()
                        % 200) as u64;
                    let base_ms = 500 * (1 << attempt);
                    let backoff = Duration::from_millis(base_ms + jitter_ms);
                    warn!(
                        "[{}] 渠道发送通知失败: {}，将在 {} 秒后进行第 {}/{} 次重试",
                        notifier.channel_name(),
                        e,
                        backoff.as_secs_f32(),
                        attempt,
                        MAX_RETRIES
                    );
                    tokio::time::sleep(backoff).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notifier::trait_def::{NotificationOverallStatus, NotifyError};
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct MockRetryNotifier {
        fail_times: usize,
        call_count: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Notifier for MockRetryNotifier {
        fn channel_name(&self) -> &'static str {
            "测试Mock渠道"
        }

        async fn send(&self, _event: &NotificationEvent) -> Result<(), NotifyError> {
            let current = self.call_count.fetch_add(1, Ordering::SeqCst);
            if current < self.fail_times {
                Err(NotifyError::Provider("网络临时抖动".to_string()))
            } else {
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn test_send_with_retry_succeeds_after_retries() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let mock_notifier = Arc::new(MockRetryNotifier {
            fail_times: 2,
            call_count: call_count.clone(),
        });
        let event = Arc::new(NotificationEvent {
            overall_status: NotificationOverallStatus::Success,
            task_name: "测试任务".to_string(),
            ipv4: None,
            ipv6: None,
            ip_changed: true,
            results: vec![],
            timestamp: chrono::Local::now(),
        });

        let res = NotificationDispatcher::send_with_retry(mock_notifier, event).await;
        assert!(res.is_ok());
        // 初始 1 次 + 重试 2 次 = 3 次调用后成功
        assert_eq!(call_count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_send_with_retry_aborts_on_permanent_error() {
        struct PermanentFailNotifier {
            call_count: Arc<AtomicUsize>,
        }

        #[async_trait]
        impl Notifier for PermanentFailNotifier {
            fn channel_name(&self) -> &'static str {
                "永久失败Mock"
            }

            async fn send(&self, _event: &NotificationEvent) -> Result<(), NotifyError> {
                self.call_count.fetch_add(1, Ordering::SeqCst);
                Err(NotifyError::Http("401 Unauthorized".to_string()))
            }
        }

        let call_count = Arc::new(AtomicUsize::new(0));
        let mock = Arc::new(PermanentFailNotifier {
            call_count: call_count.clone(),
        });
        let event = Arc::new(NotificationEvent {
            overall_status: NotificationOverallStatus::Failed,
            task_name: "测试任务".to_string(),
            ipv4: None,
            ipv6: None,
            ip_changed: false,
            results: vec![],
            timestamp: chrono::Local::now(),
        });

        let res = NotificationDispatcher::send_with_retry(mock, event).await;
        assert!(res.is_err());
        // 遇到 401 永久性错误，立刻返回不重试，调用次数仅为 1
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_error_throttle_capacity_hard_limit() {
        let dispatcher = NotificationDispatcher::new(NotificationConfig::default());
        // 瞬间写入 600 个不同名称的任务错误
        for i in 0..600 {
            dispatcher
                .check_and_update_error_throttle(&format!("task_{}", i), "连接超时".to_string());
        }
        let trackers = dispatcher.error_trackers.read();
        // 验证不会无限膨胀，数量严格不超过硬上限 512
        assert_eq!(trackers.len(), TRACKER_HARD_LIMIT);
    }

    #[tokio::test]
    async fn test_dispatch_aggregates_delivery_status() {
        let statuses: DeliveryStatusMap = Arc::new(RwLock::new(HashMap::new()));
        let mut dispatcher = NotificationDispatcher::new_with_trackers_and_statuses(
            NotificationConfig::default(),
            Arc::new(RwLock::new(HashMap::new())),
            statuses.clone(),
        );

        let call_count = Arc::new(AtomicUsize::new(0));
        let mock = Arc::new(MockRetryNotifier {
            fail_times: 0,
            call_count,
        });
        dispatcher.notifiers.push(mock);

        let event = NotificationEvent {
            overall_status: NotificationOverallStatus::Success,
            task_name: "测试聚合任务".to_string(),
            ipv4: None,
            ipv6: None,
            ip_changed: true,
            results: vec![],
            timestamp: chrono::Local::now(),
        };

        dispatcher.dispatch_internal(event, true);

        // 等待监管协程收割完成
        tokio::time::sleep(Duration::from_millis(100)).await;

        let snapshot = dispatcher.snapshot_delivery_statuses();
        assert!(snapshot.contains_key("测试Mock渠道"));
        let st = snapshot.get("测试Mock渠道").unwrap();
        assert_eq!(st.success_count, 1);
        assert_eq!(st.failure_count, 0);
        assert!(st.last_success_time.is_some());
        assert!(st.last_failure_time.is_none());
    }

    /// 全局闸门测试互斥锁
    ///
    /// # 设计原理
    /// `NOTIFY_INFLIGHT_GATE` 为进程级单例，多个测试并行改动其许可数会
    /// 相互干扰（一个测试的 `available_permits` 断言会被另一个测试的
    /// 占用打断）。此锁确保两个用例串行执行。
    static GATE_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_inflight_gate_blocks_unbounded_notification_tasks() {
        // 回归用例 (P1-13)：dispatch_internal 原先对在途任务数无任何约束。
        // 最短同步间隔（5 秒）小于单渠道最长耗时（约 36 秒），稳态下任务
        // 会无界累积。验证闸门在耗尽后会拒绝新的分发。
        //
        // 全程同步执行，锁的作用域不跨越任何 await（AGENTS.md 明令禁止
        // MutexGuard 跨 await）。
        let _serial = GATE_TEST_LOCK.lock();

        // 按当前实际可用量申请，不假定闸门初始为空闲——同进程内其它测试
        // 可能已占用部分许可，硬编码申请全量会间歇性失败（flaky）。
        let available = NOTIFY_INFLIGHT_GATE.available_permits();
        assert!(available > 0, "闸门可用许可应为正数，当前 {}", available);

        // 占满全部可用许可，模拟在途任务已达上限
        let held = NOTIFY_INFLIGHT_GATE
            .try_acquire_many(available as u32)
            .expect("按可用量申请许可理应成功");

        // 闸门耗尽后新的分发必须被拒绝
        assert!(
            NOTIFY_INFLIGHT_GATE.try_acquire_many(1).is_err(),
            "在途任务达上限后必须拒绝新的分发，否则任务将无界堆积"
        );

        // 许可释放后应可再次获取
        drop(held);
        assert!(
            NOTIFY_INFLIGHT_GATE.try_acquire_many(1).is_ok(),
            "许可释放后必须可继续分发"
        );
    }

    #[test]
    fn test_inflight_gate_permits_are_released_after_harvest() {
        // 验证许可令牌随持有者结束而释放，不会永久占用导致后续通知全被拒。
        // 全程使用 try_acquire_many 而非 async 版本，使本用例无需 await，
        // 从根本上避免 MutexGuard 跨挂起点的高危反模式。
        let _serial = GATE_TEST_LOCK.lock();
        let before = NOTIFY_INFLIGHT_GATE.available_permits();
        {
            let _p = NOTIFY_INFLIGHT_GATE
                .try_acquire_many(4)
                .expect("申请许可失败：闸门应有余量");
            assert_eq!(
                NOTIFY_INFLIGHT_GATE.available_permits(),
                before - 4,
                "许可应被实际占用"
            );
        }
        assert_eq!(
            NOTIFY_INFLIGHT_GATE.available_permits(),
            before,
            "作用域结束后许可必须被完整释放"
        );
    }

    #[test]
    fn test_harvester_tracker_is_process_wide_and_bounded() {
        // 监管任务必须纳管至全局追踪表而非被丢弃为孤儿任务
        let mut tracker = HARVESTER_TRACKER.lock();
        // 收割已完成的历史任务，防止表本身无界增长
        while tracker.try_join_next().is_some() {}
        let len = tracker.len();
        drop(tracker);
        assert!(
            len <= MAX_INFLIGHT_NOTIFY_TASKS * 2,
            "监管任务追踪表长度应受在途上限约束，实际 {}",
            len
        );
    }
}
