use super::*;
use crate::config::model::{AppConfig, IpFetchConfig, IpSourceType, ProviderConfig};
use crate::core::domain::ParsedDomain;
use crate::core::state::TaskRuntimeState;
use crate::dns::trait_def::{DnsRecordType, SyncRecordResult};
use std::net::{Ipv4Addr, Ipv6Addr};

#[tokio::test]
async fn test_disabled_task_skipped_in_run_once() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    let config_manager = Arc::new(ConfigManager::load_or_create(config_path).unwrap());

    config_manager
        .update_config(AppConfig {
            dns_tasks: vec![DnsTaskConfig {
                name: "已关闭的任务".to_string(),
                enabled: false,
                provider: ProviderConfig::Cloudflare {
                    api_token: Some("dummy_token".to_string()),
                    api_key: None,
                    email: None,
                },
                ipv4: IpFetchConfig {
                    enabled: true,
                    source_type: IpSourceType::Url,
                    url_endpoints: vec!["https://api.ipify.org".to_string()],
                    domains: vec!["test.example.com".to_string()],
                    ..Default::default()
                },
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap();

    let (engine, _tx) = DdnsEngine::new(config_manager.clone(), StateManager::new());
    engine.run_once(false).await;

    // 验证由于任务被禁用，state_manager 中不应存在该任务的状态记录（从未执行 process_task）
    let state = engine.state_manager.get_task_state("已关闭的任务");
    assert_eq!(state.last_sync_time, None);
    assert_eq!(state.check_counter, 0);
}

// ===== 以下为调度引擎核心决策函数的边界测试 =====
// 这些纯函数决定「是否发起云端请求」与「如何更新状态」，
// 是整个项目行为正确性的关键。

/// 评估参数构建器：测试专用聚合入参
///
/// # 设计原理
/// 项目规范要求「函数入参超过 4 个时必须收敛为参数对象」。
/// 本结构体仅服务于测试代码，用于避免 `build_eval_params` 触发
/// clippy 的 `too_many_arguments` 与 `type_complexity` 告警，
/// 从而让 CI 的 `-D warnings` 门禁真正可用。
struct EvalArgs<'a> {
    task: &'a DnsTaskConfig,
    state: &'a TaskRuntimeState,
    v4_domains: &'a [ParsedDomain],
    v6_domains: &'a [ParsedDomain],
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
    cache_times: u32,
    force_sync: bool,
}

/// 依据聚合入参构造评估参数对象
fn build_eval_params<'a>(args: EvalArgs<'a>) -> SyncEvaluationParams<'a> {
    SyncEvaluationParams {
        task: args.task,
        cache_times: args.cache_times,
        current_state: args.state,
        v4_domains: args.v4_domains,
        v6_domains: args.v6_domains,
        ipv4_opt: args.ipv4,
        ipv6_opt: args.ipv6,
        force_sync: args.force_sync,
    }
}

/// 构造仅启用 IPv4 的最小任务
fn build_ipv4_task(domains: &[&str]) -> DnsTaskConfig {
    DnsTaskConfig {
        name: "评估测试任务".to_string(),
        enabled: true,
        provider: ProviderConfig::Cloudflare {
            api_token: Some("dummy".to_string()),
            api_key: None,
            email: None,
        },
        ipv4: IpFetchConfig {
            enabled: true,
            domains: domains.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        },
        ..Default::default()
    }
}

#[test]
fn test_evaluate_sync_triggers_on_ip_change() {
    let task = build_ipv4_task(&["a.example.com"]);
    let parsed = parse_domain_list(&task.ipv4.domains);
    let state = TaskRuntimeState::default();

    // 本地 IP 与上次不同 -> 必须触发同步
    let params = build_eval_params(EvalArgs {
        task: &task,
        state: &state,
        v4_domains: &parsed,
        v6_domains: &[],
        ipv4: Some("1.2.3.4".parse().unwrap()),
        ipv6: None,
        cache_times: 10,
        force_sync: false,
    });
    assert!(DdnsEngine::evaluate_sync_necessity(&params));
}

#[test]
fn test_evaluate_sync_skips_when_nothing_changed() {
    let task = build_ipv4_task(&["a.example.com"]);
    let parsed = parse_domain_list(&task.ipv4.domains);

    // 上次已同步同样的 IP，且未达校对周期 -> 应跳过云端请求
    let mut state = TaskRuntimeState {
        last_ipv4: Some("1.2.3.4".parse().unwrap()),
        check_counter: 1,
        ..Default::default()
    };
    state
        .synced_domains
        .insert("a.example.com:A".to_string(), "1.2.3.4".to_string());

    let params = build_eval_params(EvalArgs {
        task: &task,
        state: &state,
        v4_domains: &parsed,
        v6_domains: &[],
        ipv4: Some("1.2.3.4".parse().unwrap()),
        ipv6: None,
        cache_times: 10,
        force_sync: false,
    });
    assert!(
        !DdnsEngine::evaluate_sync_necessity(&params),
        "IP 未变且未达校对周期时不应发起云端请求"
    );
}

#[test]
fn test_evaluate_sync_triggers_on_cache_limit_reached() {
    let task = build_ipv4_task(&["a.example.com"]);
    let parsed = parse_domain_list(&task.ipv4.domains);

    // IP 完全一致，但轮询次数已达校对阈值 -> 必须强制比对云端记录
    let mut state = TaskRuntimeState {
        last_ipv4: Some("1.2.3.4".parse().unwrap()),
        check_counter: 10,
        ..Default::default()
    };
    state
        .synced_domains
        .insert("a.example.com:A".to_string(), "1.2.3.4".to_string());

    let params = build_eval_params(EvalArgs {
        task: &task,
        state: &state,
        v4_domains: &parsed,
        v6_domains: &[],
        ipv4: Some("1.2.3.4".parse().unwrap()),
        ipv6: None,
        cache_times: 10,
        force_sync: false,
    });
    assert!(
        DdnsEngine::evaluate_sync_necessity(&params),
        "达到校对周期时必须强制与云端真实记录比对"
    );
}

#[test]
fn test_evaluate_sync_triggers_on_unsynced_domain() {
    let task = build_ipv4_task(&["a.example.com"]);
    let parsed = parse_domain_list(&task.ipv4.domains);

    // IP 未变且未达周期，但新增了一个尚未同步的域名 -> 必须同步
    let mut state = TaskRuntimeState {
        last_ipv4: Some("1.2.3.4".parse().unwrap()),
        check_counter: 1,
        ..Default::default()
    };
    state
        .synced_domains
        .insert("other.example.com:A".to_string(), "1.2.3.4".to_string());

    let params = build_eval_params(EvalArgs {
        task: &task,
        state: &state,
        v4_domains: &parsed,
        v6_domains: &[],
        ipv4: Some("1.2.3.4".parse().unwrap()),
        ipv6: None,
        cache_times: 10,
        force_sync: false,
    });
    assert!(
        DdnsEngine::evaluate_sync_necessity(&params),
        "存在未同步域名时必须发起同步"
    );
}

#[test]
fn test_evaluate_sync_never_triggers_without_ip() {
    let task = build_ipv4_task(&["a.example.com"]);
    let parsed = parse_domain_list(&task.ipv4.domains);
    let state = TaskRuntimeState::default();

    // 未探测到 IP 时不应触发任何云端同步
    let params = build_eval_params(EvalArgs {
        task: &task,
        state: &state,
        v4_domains: &parsed,
        v6_domains: &[],
        ipv4: None,
        ipv6: None,
        cache_times: 10,
        force_sync: false,
    });
    assert!(
        !DdnsEngine::evaluate_sync_necessity(&params),
        "无公网 IP 时不应触发同步"
    );
}

#[test]
fn test_evaluate_sync_respects_force_flag() {
    let task = build_ipv4_task(&["a.example.com"]);
    let parsed = parse_domain_list(&task.ipv4.domains);
    let mut state = TaskRuntimeState {
        last_ipv4: Some("1.2.3.4".parse().unwrap()),
        check_counter: 1,
        ..Default::default()
    };
    state
        .synced_domains
        .insert("a.example.com:A".to_string(), "1.2.3.4".to_string());

    // 手动触发时即便无任何变化也必须全量同步
    let params = build_eval_params(EvalArgs {
        task: &task,
        state: &state,
        v4_domains: &parsed,
        v6_domains: &[],
        ipv4: Some("1.2.3.4".parse().unwrap()),
        ipv6: None,
        cache_times: 10,
        force_sync: true,
    });
    assert!(DdnsEngine::evaluate_sync_necessity(&params));
}

#[test]
fn test_is_protocol_all_ok_boundaries() {
    // 协议未启用 -> 视为正常（不参与本轮判定）
    assert!(DdnsEngine::is_protocol_all_ok(
        false,
        true,
        3,
        DnsRecordType::A,
        &[]
    ));

    // 无IP 但协议已启用 -> 视为异常
    assert!(!DdnsEngine::is_protocol_all_ok(
        true,
        false,
        0,
        DnsRecordType::A,
        &[]
    ));

    // 协议启用、无域名 -> 视为正常
    assert!(DdnsEngine::is_protocol_all_ok(
        true,
        true,
        0,
        DnsRecordType::A,
        &[]
    ));

    // 全部成功
    let ok_results = vec![
        SyncRecordResult::unchanged("a.example.com", DnsRecordType::A, "1.2.3.4"),
        SyncRecordResult::updated("b.example.com", DnsRecordType::A, "1.2.3.4"),
    ];
    assert!(DdnsEngine::is_protocol_all_ok(
        true,
        true,
        2,
        DnsRecordType::A,
        &ok_results
    ));

    // 存在失败项 -> 视为异常
    let mixed_results = vec![
        SyncRecordResult::updated("a.example.com", DnsRecordType::A, "1.2.3.4"),
        SyncRecordResult::failed("b.example.com", DnsRecordType::A, "1.2.3.4", "超时"),
    ];
    assert!(!DdnsEngine::is_protocol_all_ok(
        true,
        true,
        2,
        DnsRecordType::A,
        &mixed_results
    ));

    // 结果数量不足 -> 视为异常（防止漏同步被误判为成功）
    assert!(!DdnsEngine::is_protocol_all_ok(
        true,
        true,
        3,
        DnsRecordType::A,
        &ok_results
    ));

    // 记录类型不匹配时不应计入本协议的成功数
    let wrong_type = vec![SyncRecordResult::updated(
        "a.example.com",
        DnsRecordType::AAAA,
        "::1",
    )];
    assert!(!DdnsEngine::is_protocol_all_ok(
        true,
        true,
        1,
        DnsRecordType::A,
        &wrong_type
    ));
}

#[test]
fn test_update_runtime_state_clears_failure_on_recovery() {
    let mut task = build_ipv4_task(&["a.example.com"]);
    task.ipv6.enabled = false;

    let mut state = TaskRuntimeState {
        consecutive_failures: 3,
        last_error: Some("历史失败".to_string()),
        last_ipv4: Some("1.2.3.4".parse().unwrap()),
        ..Default::default()
    };

    let results = vec![SyncRecordResult::updated(
        "a.example.com",
        DnsRecordType::A,
        "1.2.3.4",
    )];

    DdnsEngine::update_runtime_state_after_sync(SyncStateUpdateParams {
        task: &task,
        current_state: &mut state,
        v4_count: 1,
        v6_count: 0,
        ipv4_opt: Some("1.2.3.4".parse().unwrap()),
        ipv6_opt: None,
        sync_results: &results,
        reach_cache_limit: false,
    });

    // 恢复正常后应清零失败计数与错误摘要
    assert_eq!(state.consecutive_failures, 0);
    assert!(state.last_error.is_none());
    assert!(state.last_sync_time.is_some());
    assert_eq!(
        state.synced_domains.get("a.example.com:A"),
        Some(&"1.2.3.4".to_string())
    );
}

#[test]
fn test_update_runtime_state_records_failure() {
    let mut task = build_ipv4_task(&["a.example.com"]);
    task.ipv6.enabled = false;

    let mut state = TaskRuntimeState::default();
    let results = vec![SyncRecordResult::failed(
        "a.example.com",
        DnsRecordType::A,
        "1.2.3.4",
        "连接超时",
    )];

    DdnsEngine::update_runtime_state_after_sync(SyncStateUpdateParams {
        task: &task,
        current_state: &mut state,
        v4_count: 1,
        v6_count: 0,
        ipv4_opt: Some("1.2.3.4".parse().unwrap()),
        ipv6_opt: None,
        sync_results: &results,
        reach_cache_limit: false,
    });

    // 失败应累加计数并保留错误摘要
    assert_eq!(state.consecutive_failures, 1);
    let err = state.last_error.expect("失败时应记录错误摘要");
    assert!(err.contains("a.example.com"));
    assert!(err.contains("连接超时"));
    // 失败的域名不得写入成功缓存，否则下次会误判为已同步
    assert!(!state.synced_domains.contains_key("a.example.com:A"));
}

#[test]
fn test_update_runtime_state_resets_counter_on_cache_limit() {
    let mut task = build_ipv4_task(&["a.example.com"]);
    task.ipv6.enabled = false;

    // 达到校对周期并全部成功时，轮询计数应归零
    let mut state = TaskRuntimeState {
        check_counter: 10,
        ..Default::default()
    };
    let results = vec![SyncRecordResult::unchanged(
        "a.example.com",
        DnsRecordType::A,
        "1.2.3.4",
    )];

    DdnsEngine::update_runtime_state_after_sync(SyncStateUpdateParams {
        task: &task,
        current_state: &mut state,
        v4_count: 1,
        v6_count: 0,
        ipv4_opt: Some("1.2.3.4".parse().unwrap()),
        ipv6_opt: None,
        sync_results: &results,
        reach_cache_limit: true,
    });

    assert_eq!(state.check_counter, 0);
}

#[tokio::test]
async fn test_run_loop_graceful_shutdown() {
    let dir = tempfile::tempdir().unwrap();
    let config_file = dir.path().join(".rddns.toml");
    let manager = Arc::new(ConfigManager::load_or_create(config_file).unwrap());
    let state_mgr = StateManager::new();

    let (engine, _tx) = DdnsEngine::new(manager, state_mgr);
    let cancel_token = tokio_util::sync::CancellationToken::new();

    // 预设取消状态，验证 run_loop 立即平滑退出
    cancel_token.cancel();
    engine.run_loop(cancel_token).await;
}
