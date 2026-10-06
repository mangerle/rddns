//! 通知模块发送逻辑端到端 Mock 集成测试
//!
//! # 覆盖范围
//! 通过轻量本地 Axum HTTP 服务模拟三方通知服务接口（如 Webhook 等），
//! 验证通知驱动在 HTTP 请求构造、模板变量安全替换、自定义鉴权标头注入、
//! 成功响应解析以及远端异常状态码（如 500 服务端故障）下的完整处理逻辑。

use axum::extract::Query;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Local;
use rddns::config::model::{BarkConfig, TelegramConfig, WebhookConfig};
use rddns::dns::trait_def::{DnsRecordType, SyncRecordResult};
use rddns::notifier::bark::BarkNotifier;
use rddns::notifier::telegram::TelegramNotifier;
use rddns::notifier::trait_def::{
    NotificationEvent, NotificationOverallStatus, Notifier, NotifyError,
};
use rddns::notifier::webhook::CustomWebhookNotifier;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::TcpListener;
use tokio::sync::RwLock;

/// 通知 Mock 服务的运行时状态
#[derive(Default)]
struct NotifierMockState {
    received_bodies: RwLock<Vec<Value>>,
    received_headers: RwLock<Vec<HashMap<String, String>>>,
    request_count: AtomicUsize,
    should_fail: bool,
}

#[derive(Deserialize)]
struct QueryParams {
    task: Option<String>,
    ip: Option<String>,
}

/// 启动轻量本地通知 Mock 服务器
async fn start_notifier_mock_server(
    state: Arc<NotifierMockState>,
) -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route(
            "/mock/webhook",
            post({
                let state = state.clone();
                move |headers: HeaderMap, Json(body): Json<Value>| {
                    let state = state.clone();
                    async move {
                        state.request_count.fetch_add(1, Ordering::SeqCst);

                        if state.should_fail {
                            return (StatusCode::INTERNAL_SERVER_ERROR, "远端通知网关内部异常")
                                .into_response();
                        }

                        let mut hdr_map = HashMap::new();
                        for (k, v) in headers.iter() {
                            if let Ok(v_str) = v.to_str() {
                                hdr_map.insert(k.to_string(), v_str.to_string());
                            }
                        }

                        state.received_headers.write().await.push(hdr_map);
                        state.received_bodies.write().await.push(body);

                        (StatusCode::OK, Json(json!({"code": 0, "msg": "success"}))).into_response()
                    }
                }
            }),
        )
        .route(
            "/bot{token}/sendMessage",
            post({
                let state = state.clone();
                move |axum::extract::Path(_token): axum::extract::Path<String>,
                      Json(body): Json<Value>| {
                    let state = state.clone();
                    async move {
                        state.request_count.fetch_add(1, Ordering::SeqCst);
                        if state.should_fail {
                            return (
                                StatusCode::BAD_REQUEST,
                                Json(json!({
                                    "ok": false,
                                    "error_code": 400,
                                    "description": "Bad Request: chat not found"
                                })),
                            )
                                .into_response();
                        }
                        state.received_bodies.write().await.push(body);
                        (
                            StatusCode::OK,
                            Json(json!({
                                "ok": true,
                                "result": {
                                    "message_id": 12345
                                }
                            })),
                        )
                            .into_response()
                    }
                }
            }),
        )
        .route(
            "/push",
            post({
                let state = state.clone();
                move |Json(body): Json<Value>| {
                    let state = state.clone();
                    async move {
                        state.request_count.fetch_add(1, Ordering::SeqCst);
                        if state.should_fail {
                            return (StatusCode::INTERNAL_SERVER_ERROR, "Bark 服务器内部错误")
                                .into_response();
                        }
                        state.received_bodies.write().await.push(body);
                        (
                            StatusCode::OK,
                            Json(json!({
                                "code": 200,
                                "message": "success"
                            })),
                        )
                            .into_response()
                    }
                }
            }),
        )
        .route(
            "/mock/query_notify",
            get({
                let state = state.clone();
                move |Query(q): Query<QueryParams>| {
                    let state = state.clone();
                    async move {
                        state.request_count.fetch_add(1, Ordering::SeqCst);

                        if q.task.as_deref() == Some("测试任务")
                            && q.ip.as_deref() == Some("198.51.100.1")
                        {
                            (StatusCode::OK, "ok").into_response()
                        } else {
                            (StatusCode::BAD_REQUEST, "参数不匹配").into_response()
                        }
                    }
                }
            }),
        );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    (format!("http://{}", addr), handle)
}

/// 辅助构造测试通知事件
fn build_test_event(task_name: &str, ipv4: Option<Ipv4Addr>) -> NotificationEvent {
    NotificationEvent {
        overall_status: NotificationOverallStatus::Success,
        task_name: task_name.to_string(),
        ipv4,
        ipv6: None,
        ip_changed: true,
        results: vec![SyncRecordResult::created(
            "sub.example.com",
            DnsRecordType::A,
            "198.51.100.1",
        )],
        timestamp: Local::now(),
    }
}

#[tokio::test]
async fn test_webhook_notifier_mock_send_success() {
    let state = Arc::new(NotifierMockState::default());
    let (base_url, _handle) = start_notifier_mock_server(state.clone()).await;

    let mut custom_headers = HashMap::new();
    custom_headers.insert("content-type".to_string(), "application/json".to_string());
    custom_headers.insert("x-custom-token".to_string(), "my-secret-token".to_string());

    let config = WebhookConfig {
        enabled: true,
        url: format!("{}/mock/webhook", base_url),
        method: "POST".to_string(),
        body: Some(r##"{"task":"#{taskName}","ip":"#{ipv4Addr}"}"##.to_string()),
        headers: Some(custom_headers),
    };

    let notifier = CustomWebhookNotifier::new(config);
    let event = build_test_event("家庭宽带DDNS", Some("198.51.100.1".parse().unwrap()));

    let res = notifier.send(&event).await;
    assert!(res.is_ok(), "通知发送预期成功，实际失败: {:?}", res);

    assert_eq!(state.request_count.load(Ordering::SeqCst), 1);

    // 验证收到的请求体中变量被正确渲染替换
    let bodies = state.received_bodies.read().await;
    assert_eq!(bodies.len(), 1);
    assert_eq!(bodies[0]["task"], "家庭宽带DDNS");
    assert_eq!(bodies[0]["ip"], "198.51.100.1");

    // 验证自定义 Header 被正确注入
    let headers = state.received_headers.read().await;
    assert_eq!(headers.len(), 1);
    assert_eq!(
        headers[0].get("x-custom-token").map(|s| s.as_str()),
        Some("my-secret-token")
    );
}

#[tokio::test]
async fn test_webhook_notifier_mock_server_error() {
    let state = Arc::new(NotifierMockState {
        should_fail: true,
        ..Default::default()
    });
    let (base_url, _handle) = start_notifier_mock_server(state.clone()).await;

    let mut error_headers = HashMap::new();
    error_headers.insert("content-type".to_string(), "application/json".to_string());

    let config = WebhookConfig {
        enabled: true,
        url: format!("{}/mock/webhook", base_url),
        method: "POST".to_string(),
        body: Some(r##"{"task":"#{taskName}"}"##.to_string()),
        headers: Some(error_headers),
    };

    let notifier = CustomWebhookNotifier::new(config);
    let event = build_test_event("告警测试", Some("198.51.100.1".parse().unwrap()));

    let res = notifier.send(&event).await;
    assert!(res.is_err(), "服务端返回 500 时预期返回错误");

    match res.unwrap_err() {
        NotifyError::Provider(msg) => {
            assert!(msg.contains("500") || msg.contains("远端通知网关内部异常"));
        }
        other => panic!("预期为 NotifyError::Provider，实际为: {:?}", other),
    }

    assert_eq!(state.request_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_webhook_notifier_mock_url_query_template_interpolation() {
    let state = Arc::new(NotifierMockState::default());
    let (base_url, _handle) = start_notifier_mock_server(state.clone()).await;

    let config = WebhookConfig {
        enabled: true,
        url: format!(
            "{}/mock/query_notify?task=#{{taskName}}&ip=#{{ipv4Addr}}",
            base_url
        ),
        method: "GET".to_string(),
        body: None,
        headers: None,
    };

    let notifier = CustomWebhookNotifier::new(config);
    let event = build_test_event("测试任务", Some("198.51.100.1".parse().unwrap()));

    let res = notifier.send(&event).await;
    assert!(res.is_ok(), "GET 请求参数插值发送预期成功: {:?}", res);
    assert_eq!(state.request_count.load(Ordering::SeqCst), 1);
}

// ==========================================
// Telegram Bot 端到端 Mock 测试
// ==========================================

#[tokio::test]
async fn test_telegram_notifier_mock_send_success() {
    let state = Arc::new(NotifierMockState::default());
    let (base_url, _handle) = start_notifier_mock_server(state.clone()).await;

    let config = TelegramConfig {
        enabled: true,
        bot_token: "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11".to_string(),
        chat_id: "-100123456789".to_string(),
        api_proxy: Some(base_url),
    };

    let notifier = TelegramNotifier::new(config);
    let event = build_test_event("TG通知任务", Some("198.51.100.1".parse().unwrap()));

    let res = notifier.send(&event).await;
    assert!(res.is_ok(), "Telegram 发送预期成功: {:?}", res);

    assert_eq!(state.request_count.load(Ordering::SeqCst), 1);
    let bodies = state.received_bodies.read().await;
    assert_eq!(bodies.len(), 1);
    assert_eq!(bodies[0]["chat_id"], "-100123456789");
    assert_eq!(bodies[0]["parse_mode"], "HTML");
    assert!(
        bodies[0]["text"]
            .as_str()
            .unwrap()
            .contains("rddns 域名解析通知")
    );
}

#[tokio::test]
async fn test_telegram_notifier_mock_api_error() {
    let state = Arc::new(NotifierMockState {
        should_fail: true,
        ..Default::default()
    });
    let (base_url, _handle) = start_notifier_mock_server(state.clone()).await;

    let config = TelegramConfig {
        enabled: true,
        bot_token: "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11".to_string(),
        chat_id: "-100123456789".to_string(),
        api_proxy: Some(base_url),
    };

    let notifier = TelegramNotifier::new(config);
    let event = build_test_event("TG错误任务", Some("198.51.100.1".parse().unwrap()));

    let res = notifier.send(&event).await;
    assert!(res.is_err(), "Telegram API 返回错误时预期失败");

    match res.unwrap_err() {
        NotifyError::Provider(msg) => {
            assert!(
                msg.contains("chat not found") || msg.contains("400"),
                "应包含 Telegram API 错误信息: {}",
                msg
            );
        }
        other => panic!("预期为 NotifyError::Provider，实际为: {:?}", other),
    }

    assert_eq!(state.request_count.load(Ordering::SeqCst), 1);
}

// ==========================================
// Bark (iOS) 端到端 Mock 测试
// ==========================================

#[tokio::test]
async fn test_bark_notifier_mock_send_success() {
    let state = Arc::new(NotifierMockState::default());
    let (base_url, _handle) = start_notifier_mock_server(state.clone()).await;

    let config = BarkConfig {
        enabled: true,
        server_url: base_url,
        device_key: "mock_bark_device_key_123".to_string(),
        group: Some("RDDNS".to_string()),
        sound: Some("bell".to_string()),
    };

    let notifier = BarkNotifier::new(config);
    let event = build_test_event("Bark通知任务", Some("198.51.100.1".parse().unwrap()));

    let res = notifier.send(&event).await;
    assert!(res.is_ok(), "Bark 推送预期成功: {:?}", res);

    assert_eq!(state.request_count.load(Ordering::SeqCst), 1);
    let bodies = state.received_bodies.read().await;
    assert_eq!(bodies.len(), 1);
    assert_eq!(bodies[0]["device_key"], "mock_bark_device_key_123");
    assert_eq!(bodies[0]["group"], "RDDNS");
    assert_eq!(bodies[0]["sound"], "bell");
}

#[tokio::test]
async fn test_bark_notifier_mock_server_error() {
    let state = Arc::new(NotifierMockState {
        should_fail: true,
        ..Default::default()
    });
    let (base_url, _handle) = start_notifier_mock_server(state.clone()).await;

    let config = BarkConfig {
        enabled: true,
        server_url: base_url,
        device_key: "mock_bark_device_key_123".to_string(),
        group: None,
        sound: None,
    };

    let notifier = BarkNotifier::new(config);
    let event = build_test_event("Bark错误任务", Some("198.51.100.1".parse().unwrap()));

    let res = notifier.send(&event).await;
    assert!(res.is_err(), "Bark 服务端异常时预期失败");

    match res.unwrap_err() {
        NotifyError::Provider(msg) => {
            assert!(
                msg.contains("500") || msg.contains("Bark 服务器内部错误"),
                "应包含 Bark 失败详情: {}",
                msg
            );
        }
        other => panic!("预期为 NotifyError::Provider，实际为: {:?}", other),
    }

    assert_eq!(state.request_count.load(Ordering::SeqCst), 1);
}
