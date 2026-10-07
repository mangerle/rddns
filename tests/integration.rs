//! 配置持久化与调度引擎热重载的跨模块集成测试
//!
//! # 覆盖范围
//! 验证「配置写入 → 原子落盘 → watch 广播 → 引擎感知变更」这条此前
//! 只能靠单元测试间接覆盖的链路。属主模块内的 `#[cfg(test)]` 因无法
//! 模拟完整装配而难以覆盖此处，故置于集成测试。

use rddns::config::model::{
    AppConfig, DnsTaskConfig, IpFetchConfig, IpSourceType, NotificationConfig, ProviderConfig,
};
use rddns::config::storage::ConfigManager;
use rddns::core::engine::DdnsEngine;
use rddns::core::state::StateManager;
use std::sync::Arc;

/// 构造一个仅配置 IPv4 URL 探测的最小任务
fn build_task(name: &str, domains: Vec<&str>) -> DnsTaskConfig {
    DnsTaskConfig {
        name: name.to_string(),
        enabled: true,
        provider: ProviderConfig::Cloudflare {
            api_token: Some("integration_test_token".to_string()),
            api_key: None,
            email: None,
        },
        ipv4: IpFetchConfig {
            enabled: true,
            source_type: IpSourceType::Url,
            url_endpoints: vec!["https://api.ipify.org".to_string()],
            domains: domains.into_iter().map(String::from).collect(),
            ..Default::default()
        },
        ..Default::default()
    }
}

#[test]
fn test_config_persists_across_manager_instances() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("persist.toml");

    // 首个实例写入配置
    {
        let manager = ConfigManager::load_or_create(config_path.clone()).unwrap();
        manager
            .update_config(AppConfig {
                interval_secs: 120,
                cache_times: 7,
                dns_tasks: vec![build_task("持久化任务", vec!["a.example.com"])],
                ..Default::default()
            })
            .unwrap();
    }

    // 新实例应从磁盘完整恢复
    let reopened = ConfigManager::load_or_create(config_path).unwrap();
    let conf = reopened.get_config();
    assert_eq!(conf.interval_secs, 120);
    assert_eq!(conf.cache_times, 7);
    assert_eq!(conf.dns_tasks.len(), 1);
    assert_eq!(conf.dns_tasks[0].name, "持久化任务");
    assert_eq!(conf.dns_tasks[0].ipv4.domains, vec!["a.example.com"]);
    assert!(conf.dns_tasks[0].enabled);
}

#[tokio::test]
async fn test_watch_broadcasts_interval_change_to_subscribers() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("watch.toml");
    let manager = ConfigManager::load_or_create(config_path).unwrap();

    // 订阅变更广播
    let mut rx = manager.subscribe();
    let initial_interval = manager.get_config().interval_secs;
    assert_ne!(initial_interval, 45, "前置条件：默认值应与测试目标值不同");

    // 触发更新
    let mut updated = (*manager.get_config()).clone();
    updated.interval_secs = 45;
    manager.update_config(updated).unwrap();

    // 订阅者应收到新值，引擎据此热更新轮询周期
    rx.changed().await.expect("应收到变更通知");
    let observed = rx.borrow_and_update().clone();
    assert_eq!(observed.interval_secs, 45);
    assert_eq!(
        observed.interval_secs,
        manager.get_config().interval_secs,
        "广播值与当前快照应一致"
    );
}

#[tokio::test]
async fn test_concurrent_config_updates_do_not_lose_writes() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("concurrent.toml");
    let manager = Arc::new(ConfigManager::load_or_create(config_path.clone()).unwrap());

    let base = manager.get_config().interval_secs;

    // 并发累加 20 次
    let mut handles = Vec::new();
    for _ in 0..20 {
        let mgr = manager.clone();
        handles.push(tokio::spawn(async move {
            mgr.modify_config_async::<_, rddns::config::storage::ConfigError>(|conf| {
                let mut c = conf.clone();
                c.interval_secs += 1;
                Ok(c)
            })
            .await
        }));
    }

    // 等待全部完成
    for h in handles {
        h.await.unwrap().unwrap();
    }

    // 20 次累加应精确生效，无更新丢失
    assert_eq!(manager.get_config().interval_secs, base + 20);

    // 落盘值与内存一致
    let reopened = ConfigManager::load_or_create(config_path).unwrap();
    assert_eq!(reopened.get_config().interval_secs, base + 20);
}

#[test]
fn test_engine_and_web_share_same_state_manager() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("shared_state.toml");
    let config_manager = Arc::new(ConfigManager::load_or_create(config_path).unwrap());

    config_manager
        .update_config(AppConfig {
            dns_tasks: vec![build_task("共享状态任务", vec!["nas.example.com"])],
            notifications: NotificationConfig::default(),
            ..Default::default()
        })
        .unwrap();

    // 模拟 main.rs 的装配：创建一份 StateManager 并同时交给引擎与 Web
    let state_manager = StateManager::new();
    let (engine, _trigger_tx) = DdnsEngine::new(config_manager.clone(), state_manager.clone());

    // 引擎侧写入状态
    engine
        .state_manager()
        .update_task_state("共享状态任务", |s| {
            s.last_ipv4 = Some("203.0.113.10".parse().unwrap());
            s.last_sync_time = Some("2026-10-04 20:00:00".to_string());
            s.synced_domains
                .insert("nas.example.com:A".to_string(), "203.0.113.10".to_string());
        });

    // Web 侧应能读到同一份数据（StateManager 内部 Arc 共享）
    let snapshot = state_manager.snapshot_all();
    let task = snapshot
        .get("共享状态任务")
        .expect("Web 层应能看到引擎写入的任务状态");
    assert_eq!(task.last_ipv4, Some("203.0.113.10".parse().unwrap()));
    assert_eq!(task.last_sync_time.as_deref(), Some("2026-10-04 20:00:00"));
    assert_eq!(
        task.synced_domains.get("nas.example.com:A"),
        Some(&"203.0.113.10".to_string())
    );
}

#[tokio::test]
async fn test_disabled_task_state_is_not_created() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("disabled.toml");
    let config_manager = Arc::new(ConfigManager::load_or_create(config_path).unwrap());

    let mut task = build_task("禁用任务", vec!["x.example.com"]);
    task.enabled = false;
    config_manager
        .update_config(AppConfig {
            dns_tasks: vec![task],
            ..Default::default()
        })
        .unwrap();

    let state_manager = StateManager::new();
    let (engine, _tx) = DdnsEngine::new(config_manager.clone(), state_manager.clone());

    // 执行一轮同步，禁用任务应被跳过
    engine.run_once(false, false).await;

    // 状态表应保持为空，证明前置校验确实短路了流程
    assert!(
        state_manager.snapshot_all().is_empty(),
        "禁用任务不应产生任何运行时状态"
    );
}

#[tokio::test]
async fn test_retain_active_tasks_purges_deleted_task_state() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("retain.toml");
    let config_manager = Arc::new(ConfigManager::load_or_create(config_path).unwrap());

    config_manager
        .update_config(AppConfig {
            dns_tasks: vec![
                build_task("保留任务", vec!["keep.example.com"]),
                build_task("删除任务", vec!["gone.example.com"]),
            ],
            ..Default::default()
        })
        .unwrap();

    let state_manager = StateManager::new();
    let (engine, _tx) = DdnsEngine::new(config_manager.clone(), state_manager.clone());

    state_manager.update_task_state("保留任务", |s| {
        s.last_sync_time = Some("2026-10-04 20:00:00".to_string())
    });
    state_manager.update_task_state("删除任务", |s| {
        s.last_sync_time = Some("2026-10-04 19:00:00".to_string())
    });
    assert_eq!(state_manager.snapshot_all().len(), 2);

    // 从配置中移除「删除任务」后触发一轮同步
    config_manager
        .update_config(AppConfig {
            dns_tasks: vec![build_task("保留任务", vec!["keep.example.com"])],
            ..Default::default()
        })
        .unwrap();
    engine.run_once(false, false).await;

    // 引擎内的生命周期回收应清除已删除任务的状态
    let snapshot = state_manager.snapshot_all();
    assert_eq!(
        snapshot.len(),
        1,
        "已从配置中删除的任务，其残留状态必须被生命周期回收清除"
    );
    assert!(
        snapshot.contains_key("保留任务"),
        "仍在配置中的任务状态不应被误删"
    );
    assert!(
        !snapshot.contains_key("删除任务"),
        "已删除任务的状态必须被清除，避免内存长期驻留"
    );
}
