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

struct LogVisitor {
    message: String,
}

impl tracing::field::Visit for LogVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{:?}", value).trim_matches('"').to_string();
        } else if self.message.is_empty() {
            self.message = format!("{}: {:?}", field.name(), value);
        } else {
            self.message
                .push_str(&format!(", {}: {:?}", field.name(), value));
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else if self.message.is_empty() {
            self.message = format!("{}: {}", field.name(), value);
        } else {
            self.message
                .push_str(&format!(", {}: {}", field.name(), value));
        }
    }
}

impl<S: Subscriber> Layer<S> for BufferLogLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let metadata = event.metadata();
        let mut visitor = LogVisitor {
            message: String::new(),
        };
        event.record(&mut visitor);

        if !visitor.message.is_empty() {
            self.buffer
                .push(*metadata.level(), metadata.target(), visitor.message);
        }
    }
}
