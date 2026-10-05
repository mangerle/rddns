use chrono::Local;
use log::Level;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::broadcast;

/// 单条日志记录条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// 唯一递增自增标识
    pub id: u64,
    /// 格式化时间戳字符串 (YYYY-MM-DD HH:MM:SS)
    pub timestamp: String,
    /// 日志级别文本 (INFO, WARN, ERROR, DEBUG 等)
    pub level: String,
    /// 触发日志的模块路径或目标
    pub target: String,
    /// 已经过脱敏过滤的最终日志正文
    pub message: String,
}

/// 内存环形日志缓冲区
///
/// # 设计原理
/// - **实现初衷**：为 Web 前端管理面板与实时 SSE 日志流提供低延迟、固定容量的最新记录快照。
/// - **核心优势**：通过 `RwLock` 保证轻量并发读取，配合 `tokio::sync::broadcast` 支持多客户端并发广播。
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
    /// 创建指定容量的内存环形日志缓冲区 (容量自动限制在 1..10000 之间)
    pub fn new(capacity: usize) -> Self {
        let real_capacity = capacity.clamp(1, 10000);
        let (sender, _) = broadcast::channel(100);
        Self {
            inner: Arc::new(RwLock::new(LogBufferInner {
                capacity: real_capacity,
                counter: 0,
                entries: VecDeque::with_capacity(real_capacity),
            })),
            sender,
        }
    }

    /// 插入一条新日志 (自动脱敏敏感凭据并广播给 SSE 订阅者)
    pub fn push(&self, level: Level, target: &str, message: String) {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let sanitized_msg = crate::dns::trait_def::sanitize_sensitive_url_params(&message);
        let mut inner = self.inner.write();
        inner.counter = inner.counter.wrapping_add(1);
        let entry = LogEntry {
            id: inner.counter,
            timestamp,
            level: level.as_str().to_string(),
            target: target.to_string(),
            message: sanitized_msg,
        };

        while inner.entries.len() >= inner.capacity {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_buffer_capacity() {
        let buffer = LogBuffer::new(3);
        buffer.push(Level::Info, "test", "msg 1".to_string());
        buffer.push(Level::Info, "test", "msg 2".to_string());
        buffer.push(Level::Info, "test", "msg 3".to_string());
        buffer.push(Level::Info, "test", "msg 4".to_string());

        let recent = buffer.get_recent();
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].message, "msg 2");
        assert_eq!(recent[2].message, "msg 4");
    }
}
