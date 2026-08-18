use chrono::Local;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

/// 单条日志记录条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub id: u64,
    pub timestamp: String,
    pub level: String,
    pub target: String,
    pub message: String,
}

/// 内存环形日志缓冲区
#[derive(Clone)]
pub struct LogBuffer {
    inner: Arc<RwLock<LogBufferInner>>,
    sender: broadcast::Sender<LogEntry>,
}

struct LogBufferInner {
    capacity: usize,
    counter: u64,
    entries: VecDeque<LogEntry>,
}

impl LogBuffer {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(100);
        Self {
            inner: Arc::new(RwLock::new(LogBufferInner {
                capacity,
                counter: 0,
                entries: VecDeque::with_capacity(capacity),
            })),
            sender,
        }
    }

    /// 插入一条新日志
    pub fn push(&self, level: Level, target: &str, message: String) {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let mut inner = self.inner.write();
        inner.counter += 1;
        let entry = LogEntry {
            id: inner.counter,
            timestamp,
            level: level.as_str().to_string(),
            target: target.to_string(),
            message,
        };

        if inner.entries.len() >= inner.capacity {
            inner.entries.pop_front();
        }
        inner.entries.push_back(entry.clone());

        // 广播给 SSE 订阅者 (忽略无接收者的情况)
        let _ = self.sender.send(entry);
    }

    /// 获取最近所有日志快照
    pub fn get_recent(&self) -> Vec<LogEntry> {
        let inner = self.inner.read();
        inner.entries.iter().cloned().collect()
    }

    /// 订阅实时日志广播通道
    pub fn subscribe(&self) -> broadcast::Receiver<LogEntry> {
        self.sender.subscribe()
    }
}

/// Tracing Subscriber Layer 适配器
pub struct BufferLogLayer {
    buffer: LogBuffer,
}

impl BufferLogLayer {
    pub fn new(buffer: LogBuffer) -> Self {
        Self { buffer }
    }
}

#[derive(Default)]
struct LogVisitor {
    message: Option<String>,
    extra_fields: Vec<String>,
}

impl LogVisitor {
    fn finish(self) -> String {
        let msg = self.message.unwrap_or_default();
        if self.extra_fields.is_empty() {
            msg
        } else if msg.is_empty() {
            self.extra_fields.join(", ")
        } else {
            format!("{} [{}]", msg, self.extra_fields.join(", "))
        }
    }
}

impl tracing::field::Visit for LogVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let s = format!("{:?}", value);
            let cleaned = if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
                &s[1..s.len() - 1]
            } else {
                &s
            };
            self.message = Some(cleaned.to_string());
        } else {
            self.extra_fields
                .push(format!("{}: {:?}", field.name(), value));
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        } else {
            self.extra_fields
                .push(format!("{}: {}", field.name(), value));
        }
    }
}

impl<S: Subscriber> Layer<S> for BufferLogLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let metadata = event.metadata();
        let mut visitor = LogVisitor::default();
        event.record(&mut visitor);

        let final_message = visitor.finish();
        if !final_message.is_empty() {
            self.buffer
                .push(*metadata.level(), metadata.target(), final_message);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_buffer_capacity() {
        let buffer = LogBuffer::new(3);
        buffer.push(Level::INFO, "test", "msg 1".to_string());
        buffer.push(Level::INFO, "test", "msg 2".to_string());
        buffer.push(Level::INFO, "test", "msg 3".to_string());
        buffer.push(Level::INFO, "test", "msg 4".to_string());

        let recent = buffer.get_recent();
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].message, "msg 2");
        assert_eq!(recent[2].message, "msg 4");
    }

    #[test]
    fn test_log_visitor_finish() {
        let visitor = LogVisitor {
            message: Some("操作成功".to_string()),
            extra_fields: vec!["task: demo".to_string(), "cost_ms: 12".to_string()],
        };

        assert_eq!(visitor.finish(), "操作成功 [task: demo, cost_ms: 12]");
    }
}
