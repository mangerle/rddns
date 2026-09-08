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
    fn check_and_update_error_throttle(&self, task_name: &str, error_summary: String) -> bool {
        let mut trackers = self.error_trackers.write();
        if trackers.len() >= 256 {
            trackers.retain(|_, t| t.last_notified_at.elapsed() < Duration::from_secs(3600));
        }

        if let Some(tracker) = trackers.get_mut(task_name) {
            if tracker.last_error_summary == error_summary
                && tracker.last_notified_at.elapsed() < Duration::from_secs(1800)
            {
                tracker.suppressed_count += 1;
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
    fn dispatch_internal(&self, event: NotificationEvent, force: bool) {
        if self.notifiers.is_empty() {
            return;
        }

        if !force && self.should_filter_event(&event) {
            return;
        }

        for notifier in &self.notifiers {
            let n = notifier.clone();
            let ev = event.clone();
            spawn(async move {
                if let Err(e) = n.send(&ev).await {
                    error!("[{}] 渠道发送通知失败: {}", n.channel_name(), e);
                }
            });
        }
    }
}
