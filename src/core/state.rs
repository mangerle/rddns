use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

/// 单个 DNS 任务的运行时状态快照
#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
pub struct TaskRuntimeState {
    /// 上一次成功同步的 IPv4
    pub last_ipv4: Option<Ipv4Addr>,
    /// 上一次成功同步的 IPv6
    pub last_ipv6: Option<Ipv6Addr>,
    /// 连续获取 IPv4 失败计数
    pub ipv4_fail_count: u32,
    /// 连续获取 IPv6 失败计数
    pub ipv6_fail_count: u32,
    /// 连续未与服务商强制比对的轮询计数 (用于 cache_times)
    pub check_counter: u32,
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
