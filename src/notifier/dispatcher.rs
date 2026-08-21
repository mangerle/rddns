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

/// 错误告警状态跟踪（用于防风暴抑制）
#[derive(Debug, Clone)]
pub struct ErrorTracker {
    pub last_error_summary: String,
    pub last_notified_at: Instant,
    pub suppressed_count: u32,
}

pub type ErrorTrackerMap = Arc<RwLock<HashMap<String, ErrorTracker>>>;

/// 通知分发器
#[derive(Clone)]
pub struct NotificationDispatcher {
    notifiers: Vec<Arc<dyn Notifier>>,
    config: NotificationConfig,
    error_trackers: ErrorTrackerMap,
}

impl NotificationDispatcher {
    pub fn new(config: NotificationConfig) -> Self {
        Self::new_with_trackers(config, Arc::new(RwLock::new(HashMap::new())))
    }

    /// 支持传入外部持久化的错误跟踪器（供 Engine 跨周期保留冷却状态）
    pub fn new_with_trackers(config: NotificationConfig, trackers: ErrorTrackerMap) -> Self {
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

        Self {
            notifiers,
            config,
            error_trackers: trackers,
        }
    }

    /// 触发通知事件派发（受策略与防风暴抑制规则控制）
    pub fn dispatch(&self, event: NotificationEvent) {
        self.dispatch_internal(event, false);
    }

    /// 强制派发通知（供 Web 界面手动“测试通知”使用，绕过过滤策略与防风暴抑制）
    pub fn dispatch_force(&self, event: NotificationEvent) {
        self.dispatch_internal(event, true);
    }

    fn dispatch_internal(&self, event: NotificationEvent, force: bool) {
        if self.notifiers.is_empty() {
            return;
        }

        if !force {
            // 策略过滤: 仅当记录发生实际增改时才发送成功通知（失败异常仍会触发告警）
            if self.config.on_ip_change_only
                && !event.ip_changed
                && event.overall_status == NotificationOverallStatus::Success
            {
                info!(
                    "[{}] 域名解析记录未发生实际变动，静默跳过成功通知",
                    event.task_name
                );
                return;
            }

            // 策略过滤: 成功/失败开关
            match event.overall_status {
                NotificationOverallStatus::Success => {
                    if !self.config.on_success {
                        debug!("同步成功，但配置关闭了成功通知，跳过发送");
                        return;
                    }
                    // 成功时清理历史错误记录（实现故障恢复）
                    self.error_trackers.write().remove(&event.task_name);
                }
                NotificationOverallStatus::Failed | NotificationOverallStatus::PartialSuccess => {
                    if !self.config.on_failure {
                        debug!("同步存在失败，但配置关闭了失败报警，跳过发送");
                        return;
                    }

                    // 错误防风暴冷却判断 (30 分钟冷却窗口)
                    let error_summary = event.format_details_text();
                    let mut trackers = self.error_trackers.write();

                    // 容量保护: 超过 256 条时清理过期条目
                    if trackers.len() >= 256 {
                        trackers.retain(|_, t| {
                            t.last_notified_at.elapsed() < Duration::from_secs(3600)
                        });
                    }

                    if let Some(tracker) = trackers.get_mut(&event.task_name) {
                        if tracker.last_error_summary == error_summary
                            && tracker.last_notified_at.elapsed() < Duration::from_secs(1800)
                        {
                            tracker.suppressed_count += 1;
                            warn!(
                                "任务 [{}] 出现相同错误，处于冷却抑制中 (已抑制 {} 次)，暂不重复报警",
                                event.task_name, tracker.suppressed_count
                            );
                            return;
                        }
                        tracker.last_error_summary = error_summary;
                        tracker.last_notified_at = Instant::now();
                        tracker.suppressed_count = 0;
                    } else {
                        trackers.insert(
                            event.task_name.clone(),
                            ErrorTracker {
                                last_error_summary: error_summary,
                                last_notified_at: Instant::now(),
                                suppressed_count: 0,
                            },
                        );
                    }
                }
            }
        }

        // 并行分发到所有已启用的通知渠道
        for notifier in &self.notifiers {
            let n = notifier.clone();
            let ev = event.clone();
            tokio::spawn(async move {
                if let Err(e) = n.send(&ev).await {
                    error!("[{}] 渠道发送通知失败: {}", n.channel_name(), e);
                }
            });
        }
    }
}
