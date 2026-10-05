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
use log::{debug, error, info, warn};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::spawn;
use tokio::task::JoinSet;

/// 错误追踪表触发过期清理的软阈值条数
const TRACKER_SOFT_LIMIT: usize = 256;
/// 错误追踪表绝对硬上限，防止内存无限膨胀
const TRACKER_HARD_LIMIT: usize = 512;
/// 错误记录最长留存时间（1 小时），超时条目自动清理
const ERROR_TRACKER_TTL: Duration = Duration::from_secs(3600);
/// 相同错误防风暴告警冷却窗口（30 分钟）
const ERROR_SUPPRESSION_TTL: Duration = Duration::from_secs(1800);

/// 错误告警状态跟踪（用于防风暴抑制）
#[derive(Debug, Clone)]
pub struct ErrorTracker {
    pub last_error_summary: String,
    pub last_notified_at: Instant,
    pub suppressed_count: u32,
}

pub type ErrorTrackerMap = Arc<RwLock<HashMap<String, ErrorTracker>>>;

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
}

impl NotificationDispatcher {
    /// 创建通知分发器实例
    pub fn new(config: NotificationConfig) -> Self {
        Self::new_with_trackers(config, Arc::new(RwLock::new(HashMap::new())))
    }

    /// 支持传入外部持久化的错误跟踪器（供 Engine 跨周期保留冷却状态）
    pub fn new_with_trackers(config: NotificationConfig, trackers: ErrorTrackerMap) -> Self {
        let notifiers = Self::build_enabled_notifiers(&config);
        Self {
            notifiers,
            config,
            error_trackers: trackers,
        }
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
            info!(
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
                self.check_and_update_error_throttle(&event.task_name, event.format_details_text())
            }
        }
    }

    /// 检查并更新错误冷却状态，返回 true 表示需被抑制
    ///
    /// # 设计原理
    /// - **实现初衷**: 避免任务持续失败时高频推送告警造成通知风暴，并在短时间内大量新错误涌入时防止内存无限膨胀。
    /// - **核心优势**: 软限制 (256 条) 触发过期数据清理，硬限制 (512 条) 采用 LRU 淘汰最旧条目，确保内存恒定有界。
    fn check_and_update_error_throttle(&self, task_name: &str, error_summary: String) -> bool {
        let mut trackers = self.error_trackers.write();

        // 1. 达到软阈值时淘汰过期项
        if trackers.len() >= TRACKER_SOFT_LIMIT {
            trackers.retain(|_, t| t.last_notified_at.elapsed() < ERROR_TRACKER_TTL);
        }

        // 2. 若依然达到硬上限且当前任务不在表中，淘汰最早通知的条目 (LRU)
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
    /// 延迟阻塞 DDNS 主同步循环，本函数保持「即发即忘」语义；但裸 spawn
    /// 会丢弃 JoinHandle，使 panic 彻底静默。故派生一个**监管任务**持有
    /// JoinSet 并收割全部结果——既保持非阻塞，又不丢失 panic 感知能力。
    fn dispatch_internal(&self, event: NotificationEvent, force: bool) {
        if self.notifiers.is_empty() {
            return;
        }

        if !force && self.should_filter_event(&event) {
            return;
        }

        let ev_arc = std::sync::Arc::new(event);
        let mut join_set = JoinSet::new();
        for notifier in &self.notifiers {
            let n = notifier.clone();
            let ev = ev_arc.clone();
            join_set.spawn(async move {
                Self::send_with_retry(n, ev).await;
            });
        }

        // 监管任务：收割各渠道句柄，确保 panic 可被识别并记录
        spawn(async move {
            while let Some(res) = join_set.join_next().await {
                if let Err(join_err) = res
                    && join_err.is_panic()
                {
                    error!("通知渠道任务发生 panic，该渠道推送已中断: {}", join_err);
                }
            }
        });
    }

    /// 尝试发送通知并在网络异常时进行有限重试 (最多重试 2 次，共 3 次尝试)
    async fn send_with_retry(notifier: Arc<dyn Notifier>, ev: Arc<NotificationEvent>) {
        const MAX_RETRIES: usize = 2;
        let mut attempt = 0;
        loop {
            match notifier.send(&ev).await {
                Ok(()) => return,
                Err(e) => {
                    if attempt >= MAX_RETRIES {
                        error!(
                            "[{}] 渠道发送通知最终失败（已重试 {} 次）: {}",
                            notifier.channel_name(),
                            attempt,
                            e
                        );
                        return;
                    }
                    attempt += 1;
                    let backoff = Duration::from_millis(500 * (1 << attempt)); // 1s, 2s
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

        NotificationDispatcher::send_with_retry(mock_notifier, event).await;
        // 初始 1 次 + 重试 2 次 = 3 次调用后成功
        assert_eq!(call_count.load(Ordering::SeqCst), 3);
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
}
