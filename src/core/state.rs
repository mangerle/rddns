use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

/// 单个 DNS 任务的运行时状态快照
///
/// # 设计原理
/// - **实现初衷**: 实时跟踪任务在内存中的动态同步状态，包括上次获取到的 IP、失败重试计数、连续轮询计数以及域名级别最后成功同步的 IP 记录。
/// - **核心优势**: 支持轻量化无锁读取与原子状态快照；支持与 Web 前端状态展示及错误自愈逻辑无缝联动。
/// - **代价与局限**: 默认纯内存驻留，进程重启后状态会被重置（但新一轮轮询会通过服务商比对迅速恢复最新状态）。
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

/// 错误摘要的最大保留字符数
///
/// # 设计原理
/// `last_error` 可能承载服务商返回的原始报文，其中夹杂账号、密钥等敏感内容。
/// 对外输出时统一截断，缩小暴露面并防止超长文本撑爆前端展示。
const MAX_ERROR_SUMMARY_CHARS: usize = 500;

impl TaskRuntimeState {
    /// 生成对外安全的副本，截断过长的错误摘要
    ///
    /// # 设计原理
    /// 引擎内部持有的原始状态需保留完整排障信息，但经 Web API 输出到浏览器前
    /// 必须收敛敏感内容与长度，避免服务商原始报文中的账号信息外泄。
    pub fn sanitized(&self) -> Self {
        let mut cloned = self.clone();
        if let Some(err) = cloned.last_error.as_mut()
            && err.chars().count() > MAX_ERROR_SUMMARY_CHARS
        {
            let truncated: String = err.chars().take(MAX_ERROR_SUMMARY_CHARS).collect();
            *err = format!("{}...(已截断)", truncated);
        }
        cloned
    }
}

/// 全局任务运行时状态管理器
///
/// # 设计原理
/// - **实现初衷**: 为整个 DDNS 异步调度引擎及 Web 控制台提供中心化、线程安全的任务生命周期与运行指标状态存储。
/// - **核心优势**: 采用分段并发映射容器 `Arc<DashMap>`，跨组件（调度引擎与 Web 服务）克隆时共享底层同一个并发表；各任务独立分片加锁，支持高并发独立读写，并可自动淘汰已删除任务状态，杜绝内存泄漏与读写锁竞争。
/// - **代价与局限**: 采用基于名称的字典映射，任务更名时需通过清理机制释放旧状态。
#[derive(Clone, Default)]
pub struct StateManager {
    tasks: Arc<DashMap<String, TaskRuntimeState>>,
}

impl StateManager {
    /// 创建状态管理器实例
    pub fn new() -> Self {
        Self {
            tasks: Arc::new(DashMap::new()),
        }
    }

    /// 获取指定任务的状态克隆快照，若不存在则初始化为默认值
    pub fn get_task_state(&self, task_name: &str) -> TaskRuntimeState {
        self.tasks.entry(task_name.to_string()).or_default().clone()
    }

    /// 通过闭包安全原子修改指定任务的状态
    pub fn update_task_state<F>(&self, task_name: &str, f: F)
    where
        F: FnOnce(&mut TaskRuntimeState),
    {
        let mut state = self.tasks.entry(task_name.to_string()).or_default();
        f(&mut state);
    }

    /// 清理已删除任务的历史运行时状态，防止内存长期驻留与泄漏
    pub fn retain_active_tasks(&self, active_task_names: &[String]) {
        self.tasks
            .retain(|name, _| active_task_names.contains(name));
    }

    /// 获取全部任务运行时状态的只读快照 (键为任务名称)
    ///
    /// # 设计原理
    /// - **实现初衷**: 供 Web 控制台展示各任务的同步时间、连续失败次数与域名级
    ///   解析结果，使前端无需解析日志文本反推状态。
    /// - **核心优势**: 在只读分段锁遍历中生成脱敏副本并一次性收集为独立映射，各分片独立查放，
    ///   避免持有全局互斥锁导致读写阻塞与长临界区。
    /// - **代价与局限**: 数据量与任务数、域名数成正比；调用方应按需使用，
    ///   避免高频轮询造成无谓的深拷贝。
    pub fn snapshot_all(&self) -> HashMap<String, TaskRuntimeState> {
        self.tasks
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().sanitized()))
            .collect()
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
        assert_eq!(mgr.tasks.len(), 2);
        mgr.retain_active_tasks(&["task1".to_string()]);
        assert_eq!(mgr.tasks.len(), 1);
        assert!(mgr.tasks.contains_key("task1"));
        assert!(!mgr.tasks.contains_key("obsolete_task"));
    }
}
