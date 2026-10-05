//! DNS 服务商驱动端到端 Mock 集成测试
//!
//! # 覆盖范围
//! 通过轻量本地 Axum HTTP Mock 服务模拟权威 DNS 系统的真实交互，
//! 验证 DNS 提供商驱动（如 HiPM DNSMgr）在网络通信、记录匹配、
//! 状态判定（新增、更新、未变跳过）以及异常返回（401 鉴权失败、Zone 不存在）
//! 时的全流程闭环行为。

use axum::extract::{Path, Query};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, put};
use axum::{Json, Router};
use rddns::config::model::ProviderConfig;
use rddns::core::domain::parse_domain;
use rddns::dns::create_dns_provider;
use rddns::dns::trait_def::{DnsProviderError, DnsRecordType, SyncStatus};
use serde::Deserialize;
use serde_json::{Value, json};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::TcpListener;
use tokio::sync::RwLock;

/// Mock 服务的共享运行时状态
#[derive(Default)]
struct MockState {
    records: RwLock<Vec<Value>>,
    add_count: AtomicUsize,
    update_count: AtomicUsize,
    require_auth: bool,
}

#[derive(Deserialize)]
struct DomainQuery {
    keyword: Option<String>,
}

#[derive(Deserialize)]
struct RecordQuery {
    subdomain: Option<String>,
    #[serde(rename = "type")]
    record_type: Option<String>,
}

/// 启动轻量本地 DNS 提供商 Mock 服务器
async fn start_mock_server(state: Arc<MockState>) -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route(
            "/api/domains",
            get({
                let state = state.clone();
                move |headers: HeaderMap, Query(query): Query<DomainQuery>| {
                    let state = state.clone();
                    async move {
                        if state.require_auth {
                            let auth = headers.get("authorization").and_then(|h| h.to_str().ok());
                            if auth != Some("Bearer valid_test_token") {
                                return (
                                    StatusCode::UNAUTHORIZED,
                                    Json(json!({"code": 401, "msg": "未授权"})),
                                )
                                    .into_response();
                            }
                        }

                        let kw = query.keyword.unwrap_or_default();
                        if kw == "notfound.com" {
                            return (
                                StatusCode::OK,
                                Json(json!({
                                    "code": 0,
                                    "msg": "ok",
                                    "data": []
                                })),
                            )
                                .into_response();
                        }

                        (
                            StatusCode::OK,
                            Json(json!({
                                "code": 0,
                                "msg": "ok",
                                "data": [
                                    {
                                        "id": 8888,
                                        "name": kw
                                    }
                                ]
                            })),
                        )
                            .into_response()
                    }
                }
            }),
        )
        .route(
            "/api/domains/{id}/records",
            get({
                let state = state.clone();
                move |Path(_id): Path<i64>, Query(query): Query<RecordQuery>| {
                    let state = state.clone();
                    async move {
                        let sub = query.subdomain.unwrap_or_default();
                        let rtype = query.record_type.unwrap_or_default();
                        let records = state.records.read().await;

                        let matched: Vec<Value> = records
                            .iter()
                            .filter(|r| {
                                r["name"].as_str() == Some(&sub)
                                    && r["type"].as_str() == Some(&rtype)
                            })
                            .cloned()
                            .collect();

                        (
                            StatusCode::OK,
                            Json(json!({
                                "code": 0,
                                "msg": "ok",
                                "data": matched
                            })),
                        )
                    }
                }
            })
            .post({
                let state = state.clone();
                move |Path(_id): Path<i64>, Json(body): Json<Value>| {
                    let state = state.clone();
                    async move {
                        state.add_count.fetch_add(1, Ordering::SeqCst);
                        let mut records = state.records.write().await;
                        let new_id = (records.len() + 100) as i64;
                        let mut item = body.clone();
                        item["id"] = json!(new_id);
                        records.push(item);

                        (
                            StatusCode::OK,
                            Json(json!({
                                "code": 0,
                                "msg": "ok",
                                "data": {"id": new_id}
                            })),
                        )
                    }
                }
            }),
        )
        .route(
            "/api/domains/{id}/records/{rid}",
            put({
                let state = state.clone();
                move |Path((_id, rid)): Path<(i64, String)>, Json(body): Json<Value>| {
                    let state = state.clone();
                    async move {
                        state.update_count.fetch_add(1, Ordering::SeqCst);
                        let mut records = state.records.write().await;
                        for r in records.iter_mut() {
                            let match_id = r["id"]
                                .as_i64()
                                .map(|n| n.to_string())
                                .or_else(|| r["id"].as_str().map(|s| s.to_string()));
                            if match_id == Some(rid.clone()) {
                                *r = body.clone();
                                r["id"] = json!(rid.parse::<i64>().unwrap_or(9999));
                                break;
                            }
                        }

                        (
                            StatusCode::OK,
                            Json(json!({
                                "code": 0,
                                "msg": "ok",
                                "data": null
                            })),
                        )
                    }
                }
            }),
        );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    (format!("http://{}", addr), server_handle)
}

#[tokio::test]
async fn test_hipm_dnsmgr_mock_add_record() {
    let state = Arc::new(MockState::default());
    let (base_url, _server) = start_mock_server(state.clone()).await;

    let config = ProviderConfig::HipmDnsMgr {
        endpoint: Some(base_url),
        api_token: "valid_test_token".to_string(),
    };
    let provider = create_dns_provider(&config, None).unwrap();
    let domain = parse_domain("sub.example.com").unwrap();
    let ip: IpAddr = "198.51.100.1".parse().unwrap();

    let res = provider
        .sync_record(&domain, DnsRecordType::A, &ip, Some(600))
        .await
        .unwrap();

    assert_eq!(res.status, SyncStatus::Created);
    assert_eq!(state.add_count.load(Ordering::SeqCst), 1);
    assert_eq!(state.update_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn test_hipm_dnsmgr_mock_unchanged_record() {
    let state = Arc::new(MockState::default());
    // 预填已有解析记录，IP 与目标一致
    {
        let mut records = state.records.write().await;
        records.push(json!({
            "id": 101,
            "name": "sub",
            "type": "A",
            "value": "198.51.100.1",
            "ttl": 600
        }));
    }

    let (base_url, _server) = start_mock_server(state.clone()).await;
    let config = ProviderConfig::HipmDnsMgr {
        endpoint: Some(base_url),
        api_token: "valid_test_token".to_string(),
    };
    let provider = create_dns_provider(&config, None).unwrap();
    let domain = parse_domain("sub.example.com").unwrap();
    let ip: IpAddr = "198.51.100.1".parse().unwrap();

    let res = provider
        .sync_record(&domain, DnsRecordType::A, &ip, Some(600))
        .await
        .unwrap();

    assert_eq!(res.status, SyncStatus::Unchanged);
    assert_eq!(state.add_count.load(Ordering::SeqCst), 0);
    assert_eq!(state.update_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn test_hipm_dnsmgr_mock_update_record() {
    let state = Arc::new(MockState::default());
    // 预填已有解析记录，但 IP 发生变更
    {
        let mut records = state.records.write().await;
        records.push(json!({
            "id": 102,
            "name": "sub",
            "type": "A",
            "value": "198.51.100.1",
            "ttl": 600
        }));
    }

    let (base_url, _server) = start_mock_server(state.clone()).await;
    let config = ProviderConfig::HipmDnsMgr {
        endpoint: Some(base_url),
        api_token: "valid_test_token".to_string(),
    };
    let provider = create_dns_provider(&config, None).unwrap();
    let domain = parse_domain("sub.example.com").unwrap();
    let new_ip: IpAddr = "203.0.113.88".parse().unwrap();

    let res = provider
        .sync_record(&domain, DnsRecordType::A, &new_ip, Some(600))
        .await
        .unwrap();

    assert_eq!(res.status, SyncStatus::Updated);
    assert_eq!(state.add_count.load(Ordering::SeqCst), 0);
    assert_eq!(state.update_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_hipm_dnsmgr_mock_unauthorized() {
    let state = Arc::new(MockState {
        require_auth: true,
        ..Default::default()
    });

    let (base_url, _server) = start_mock_server(state).await;
    // 使用错误的 token 访问
    let config = ProviderConfig::HipmDnsMgr {
        endpoint: Some(base_url),
        api_token: "wrong_token".to_string(),
    };
    let provider = create_dns_provider(&config, None).unwrap();
    let domain = parse_domain("sub.example.com").unwrap();
    let ip: IpAddr = "198.51.100.1".parse().unwrap();

    let err = provider
        .sync_record(&domain, DnsRecordType::A, &ip, Some(600))
        .await
        .unwrap_err();

    match err {
        DnsProviderError::ApiError { code, message } => {
            assert!(code.contains("401"));
            assert!(message.contains("HTTP 错误"));
        }
        other => panic!("预期为 ApiError，实际为: {:?}", other),
    }
}

#[tokio::test]
async fn test_hipm_dnsmgr_mock_zone_not_found() {
    let state = Arc::new(MockState::default());
    let (base_url, _server) = start_mock_server(state).await;

    let config = ProviderConfig::HipmDnsMgr {
        endpoint: Some(base_url),
        api_token: "valid_test_token".to_string(),
    };
    let provider = create_dns_provider(&config, None).unwrap();
    let domain = parse_domain("test.notfound.com").unwrap();
    let ip: IpAddr = "198.51.100.1".parse().unwrap();

    let err = provider
        .sync_record(&domain, DnsRecordType::A, &ip, Some(600))
        .await
        .unwrap_err();

    match err {
        DnsProviderError::ZoneNotFound(msg) => {
            assert!(msg.contains("notfound.com"));
        }
        other => panic!("预期为 ZoneNotFound，实际为: {:?}", other),
    }
}
