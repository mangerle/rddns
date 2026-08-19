use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

/// 单个 DNS 任务的运行时状态快照
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaskRuntimeState {
    /// 上一次成功同步的 IPv4
    pub last_ipv4: Option<Ipv4Addr>,
    /// 上一次成功同步的 IPv6
    pub last_ipv6: Option<Ipv6Addr>,
    /// 连续获取 IPv4 失败计数
    pub ipv4_fail_count: u32,
    /// 连续获取 IPv6 失败计数
    pub ipv6_fail_count: u32,
    /// 连续同步失败计数 (包括 DNS 解析与 API 调用失败)
    pub consecutive_failures: u32,
    /// 连续未与服务商强制比对的轮询计数 (用于 cache_times)
    pub check_counter: u32,
    /// 最后一次尝试同步的时间
    pub last_sync_time: Option<String>,
    /// 最后一次发生的错误摘要
    pub last_error: Option<String>,
}

/// 全局任务状态管理器
#[derive(Clone, Default)]
pub struct StateManager {
    tasks: Arc<RwLock<HashMap<String, TaskRuntimeState>>>,
}

impl StateManager {
    pub fn new() -> Self {
        Self {
            tasks: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// 获取任务状态拷贝，若不存在则初始化
    pub fn get_task_state(&self, task_name: &str) -> TaskRuntimeState {
        let mut tasks = self.tasks.write();
        tasks.entry(task_name.to_string()).or_default().clone()
    }

    /// 更新任务状态
    pub fn update_task_state<F>(&self, task_name: &str, f: F)
    where
        F: FnOnce(&mut TaskRuntimeState),
    {
        let mut tasks = self.tasks.write();
        let state = tasks.entry(task_name.to_string()).or_default();
        f(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_manager_lifecycle() {
        let mgr = StateManager::new();
        let state = mgr.get_task_state("task1");
        assert_eq!(state.consecutive_failures, 0);
        assert_eq!(state.check_counter, 0);
        assert!(state.last_error.is_none());

        mgr.update_task_state("task1", |s| {
            s.consecutive_failures = 2;
            s.last_error = Some("连接超时".to_string());
        });

        let updated = mgr.get_task_state("task1");
        assert_eq!(updated.consecutive_failures, 2);
        assert_eq!(updated.last_error.as_deref(), Some("连接超时"));
    }
}
