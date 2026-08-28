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
    /// 各域名最近一次成功同步的 IP 记录 (键格式: "full_domain:RecordType", 如 "example.com:A" -> "1.2.3.4")
    #[serde(default)]
    pub synced_domains: HashMap<String, String>,
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

    /// 清理已删除任务的历史运行时状态，防止内存长期驻留与泄漏
    pub fn retain_active_tasks(&self, active_task_names: &[String]) {
        let mut tasks = self.tasks.write();
        tasks.retain(|name, _| active_task_names.contains(name));
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
            s.synced_domains
                .insert("sub.example.com:A".to_string(), "1.2.3.4".to_string());
        });

        let updated = mgr.get_task_state("task1");
        assert_eq!(updated.consecutive_failures, 2);
        assert_eq!(updated.last_error.as_deref(), Some("连接超时"));
        assert_eq!(
            updated.synced_domains.get("sub.example.com:A"),
            Some(&"1.2.3.4".to_string())
        );

        // 测试清理已废弃任务状态
        mgr.get_task_state("obsolete_task");
        assert_eq!(mgr.tasks.read().len(), 2);
        mgr.retain_active_tasks(&["task1".to_string()]);
        assert_eq!(mgr.tasks.read().len(), 1);
        assert!(mgr.tasks.read().contains_key("task1"));
        assert!(!mgr.tasks.read().contains_key("obsolete_task"));
    }
}
