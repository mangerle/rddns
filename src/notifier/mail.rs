use crate::config::model::EmailConfig;
use crate::notifier::trait_def::{NotificationEvent, Notifier, NotifyError};
use async_trait::async_trait;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

pub struct EmailNotifier {
    config: EmailConfig,
}

impl EmailNotifier {
    pub fn new(config: EmailConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Notifier for EmailNotifier {
    fn channel_name(&self) -> &'static str {
        "SMTP 邮件"
    }

    async fn send(&self, event: &NotificationEvent) -> Result<(), NotifyError> {
        let subject = format!("🔔 [rddns] 动态域名解析通知 - {}", event.overall_status.as_str());
        let body = format!(
            "<h3>🔔 rddns 动态域名解析通知</h3>\
            <p><strong>同步状态：</strong>{}</p>\
            <p><strong>任务名称：</strong>{}</p>\
            <p><strong>IPv4 地址：</strong>{}</p>\
            <p><strong>IPv6 地址：</strong>{}</p>\
            <p><strong>涉及域名：</strong>{}</p>\
            <p><strong>触发时间：</strong>{}</p>\
            <h4>同步详细结果：</h4>\
            <pre style=\"background:#f4f4f4;padding:10px;border-radius:4px;\">{}</pre>",
            event.overall_status.as_str(),
            event.task_name,
            event.ipv4.map(|ip| ip.to_string()).unwrap_or_else(|| "无".to_string()),
            event.ipv6.map(|ip| ip.to_string()).unwrap_or_else(|| "无".to_string()),
            event.domains_comma_separated(),
            event.timestamp.format("%Y-%m-%d %H:%M:%S"),
            event.format_details_text()
        );

        let from_mailbox = self
            .config
            .from_address
            .parse()
            .map_err(|e| NotifyError::Email(format!("发件人邮箱格式错误: {}", e)))?;

        let mut msg_builder = Message::builder()
            .from(from_mailbox)
            .subject(subject)
            .header(ContentType::TEXT_HTML);

        for to_addr in &self.config.to_addresses {
            if let Ok(to_mailbox) = to_addr.parse() {
                msg_builder = msg_builder.to(to_mailbox);
            }
        }

        let message = msg_builder
            .body(body)
            .map_err(|e| NotifyError::Email(format!("邮件构造失败: {}", e)))?;

        let creds = Credentials::new(
            self.config.username.clone(),
            self.config.password.clone(),
        );

        let transport = if self.config.use_ssl {
            AsyncSmtpTransport::<Tokio1Executor>::relay(&self.config.smtp_server)
                .map_err(|e| NotifyError::Email(format!("SMTP 连接配置失败: {}", e)))?
                .port(self.config.smtp_port)
                .credentials(creds)
                .build()
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&self.config.smtp_server)
                .map_err(|e| NotifyError::Email(format!("STARTTLS 连接配置失败: {}", e)))?
                .port(self.config.smtp_port)
                .credentials(creds)
                .build()
        };

        transport
            .send(message)
            .await
            .map_err(|e| NotifyError::Email(format!("邮件发送失败: {}", e)))?;

        tracing::info!("[{}] 邮件发送成功", self.channel_name());
        Ok(())
    }
}
