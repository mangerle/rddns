use crate::config::model::EmailConfig;
use crate::dns::trait_def::SyncStatus;
use crate::notifier::trait_def::{
    NotificationEvent, NotificationOverallStatus, Notifier, NotifyError,
};
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

    /// 渲染现代响应式 HTML 邮件模板
    fn render_html(event: &NotificationEvent) -> String {
        let (status_bg, status_color, status_border, status_title) = match event.overall_status {
            NotificationOverallStatus::Success => ("#ecfdf5", "#065f46", "#a7f3d0", "同步成功"),
            NotificationOverallStatus::Failed => ("#fef2f2", "#991b1b", "#fecaca", "同步失败"),
            NotificationOverallStatus::PartialSuccess => {
                ("#fffbeb", "#92400e", "#fde68a", "部分解析失败")
            }
        };

        let mut table_rows = String::new();
        for r in &event.results {
            let (status_badge_bg, status_badge_color, status_text) = match r.status {
                SyncStatus::Created => ("#ecfdf5", "#059669", "已新增"),
                SyncStatus::Updated => ("#ecfdf5", "#059669", "已更新"),
                SyncStatus::Unchanged => ("#f1f5f9", "#475569", "未变动"),
                SyncStatus::Failed => ("#fef2f2", "#dc2626", "同步失败"),
            };

            table_rows.push_str(&format!(
                r#"<tr>
                    <td style="padding:10px 10px;border-bottom:1px solid #e2e8f0;font-family:monospace;font-weight:600;color:#1e293b;font-size:12px;white-space:nowrap;">{domain}</td>
                    <td style="padding:10px 6px;border-bottom:1px solid #e2e8f0;text-align:center;white-space:nowrap;"><span style="background:#f1f5f9;padding:2px 6px;border-radius:4px;font-size:11px;font-weight:700;color:#475569;font-family:monospace;">{record_type}</span></td>
                    <td style="padding:10px 10px;border-bottom:1px solid #e2e8f0;font-family:monospace;color:#334155;font-size:11px;word-break:break-all;line-height:1.3;">{target_ip}</td>
                    <td style="padding:10px 8px;border-bottom:1px solid #e2e8f0;text-align:center;white-space:nowrap;"><span style="background:{status_badge_bg};color:{status_badge_color};padding:3px 8px;border-radius:12px;font-size:12px;font-weight:600;white-space:nowrap;display:inline-block;">{status_text}</span></td>
                    <td style="padding:10px 10px;border-bottom:1px solid #e2e8f0;font-size:12px;color:#64748b;line-height:1.4;">{message}</td>
                </tr>"#,
                domain = r.domain,
                record_type = r.record_type,
                target_ip = r.target_ip,
                status_badge_bg = status_badge_bg,
                status_badge_color = status_badge_color,
                status_text = status_text,
                message = r.message
            ));
        }

        let ipv4_str = event
            .ipv4
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "未获取 / 未启用".to_string());
        let ipv6_str = event
            .ipv6
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "未获取 / 未启用".to_string());
        let time_str = event.timestamp.format("%Y-%m-%d %H:%M:%S").to_string();

        format!(
            r#"<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>rddns 解析通知</title>
</head>
<body style="margin:0;padding:24px 12px;background-color:#f8fafc;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#0f172a;-webkit-font-smoothing:antialiased;">
  <table width="100%" border="0" cellspacing="0" cellpadding="0">
    <tr>
      <td align="center">
        <table width="100%" border="0" cellspacing="0" cellpadding="0" style="max-width:620px;background:#ffffff;border-radius:12px;border:1px solid #e2e8f0;overflow:hidden;box-shadow:0 4px 6px -1px rgba(0,0,0,0.05);">
          <!-- 顶部渐变装饰条 -->
          <tr>
            <td height="4" style="background:linear-gradient(90deg,#6366f1 0%,#06b6d4 100%);"></td>
          </tr>

          <!-- 品牌与标题区 -->
          <tr>
            <td style="padding:24px 28px 16px 28px;">
              <table width="100%" border="0" cellspacing="0" cellpadding="0">
                <tr>
                  <td>
                    <span style="font-size:20px;font-weight:800;letter-spacing:-0.5px;color:#4f46e5;">rddns</span>
                    <span style="font-size:14px;color:#64748b;margin-left:8px;font-weight:500;">动态域名解析系统</span>
                  </td>
                  <td align="right">
                    <span style="font-size:12px;color:#94a3b8;font-family:monospace;">{time_str}</span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- 状态通知卡片 -->
          <tr>
            <td style="padding:0 28px 20px 28px;">
              <div style="background:{status_bg};border:1px solid {status_border};border-radius:8px;padding:14px 16px;">
                <span style="font-size:14px;font-weight:700;color:{status_color};">● 状态: {status_title}</span>
                <span style="font-size:13px;color:{status_color};margin-left:12px;">任务名称: <strong>{task_name}</strong></span>
              </div>
            </td>
          </tr>

          <!-- IP 地址概览卡片 -->
          <tr>
            <td style="padding:0 28px 20px 28px;">
              <table width="100%" border="0" cellspacing="0" cellpadding="0">
                <tr>
                  <td width="48%" style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:12px 16px;" valign="top">
                    <div style="font-size:12px;color:#64748b;font-weight:600;margin-bottom:4px;">IPv4 地址</div>
                    <div style="font-size:15px;font-family:monospace;font-weight:700;color:#1e293b;word-break:break-all;">{ipv4_str}</div>
                  </td>
                  <td width="4%"></td>
                  <td width="48%" style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:12px 16px;" valign="top">
                    <div style="font-size:12px;color:#64748b;font-weight:600;margin-bottom:4px;">IPv6 地址</div>
                    <div style="font-size:13px;font-family:monospace;font-weight:700;color:#1e293b;word-break:break-all;">{ipv6_str}</div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- 域名解析明细表 -->
          <tr>
            <td style="padding:0 28px 24px 28px;">
              <div style="font-size:14px;font-weight:700;color:#1e293b;margin-bottom:10px;">解析明细结果</div>
              <table width="100%" border="0" cellspacing="0" cellpadding="0" style="border:1px solid #e2e8f0;border-radius:8px;border-collapse:collapse;font-size:13px;text-align:left;">
                <thead>
                  <tr style="background:#f8fafc;color:#64748b;font-size:12px;font-weight:600;">
                    <th style="padding:10px 10px;border-bottom:1px solid #e2e8f0;white-space:nowrap;">域名</th>
                    <th style="padding:10px 6px;border-bottom:1px solid #e2e8f0;text-align:center;white-space:nowrap;">类型</th>
                    <th style="padding:10px 10px;border-bottom:1px solid #e2e8f0;white-space:nowrap;">目标 IP</th>
                    <th style="padding:10px 8px;border-bottom:1px solid #e2e8f0;text-align:center;white-space:nowrap;">状态</th>
                    <th style="padding:10px 10px;border-bottom:1px solid #e2e8f0;white-space:nowrap;">详情</th>
                  </tr>
                </thead>
                <tbody>
                  {table_rows}
                </tbody>
              </table>
            </td>
          </tr>

          <!-- 底部版权与说明 -->
          <tr>
            <td style="background:#f8fafc;padding:16px 28px;border-top:1px solid #e2e8f0;font-size:12px;color:#94a3b8;text-align:center;">
              本邮件由 <strong>rddns</strong> (基于 Rust 的高性能 DDNS 引擎) 自动发出 · 请勿直接回复
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"#,
            status_bg = status_bg,
            status_border = status_border,
            status_color = status_color,
            status_title = status_title,
            task_name = event.task_name,
            time_str = time_str,
            ipv4_str = ipv4_str,
            ipv6_str = ipv6_str,
            table_rows = table_rows
        )
    }
}

#[async_trait]
impl Notifier for EmailNotifier {
    fn channel_name(&self) -> &'static str {
        "SMTP 邮件"
    }

    async fn send(&self, event: &NotificationEvent) -> Result<(), NotifyError> {
        let subject = format!(
            "[rddns] 动态域名解析通知 - {}",
            event.overall_status.as_str()
        );
        let body = Self::render_html(event);

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

        let creds = Credentials::new(self.config.username.clone(), self.config.password.clone());

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
