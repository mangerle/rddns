//! 基于 tower::ServiceExt 的端到端 HTTP 鉴权与安全防护集成测试
//!
//! # 覆盖范围
//! - 阶段一：未初始化管理员状态探测与受保护接口拦截 (403 Forbidden)
//! - 阶段二：非本地回环地址尝试首次初始化防御 (403 Forbidden)
//! - 阶段三：本地回环地址合法初始化管理员账号与强密码校验 (200 OK)
//! - 阶段四：未认证请求与合法 Basic Auth 凭据认证访问 (401 vs 200)
//! - 阶段五：暴力破解连续失败频控锁定与锁定期间正误凭据全面拦截 (429 Too Many Requests)
//! - 阶段六：跨站请求伪造 (CSRF) 头部拦截校验

use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use rddns::config::storage::ConfigManager;
use rddns::core::state::StateManager;
use rddns::util::logging::LogBuffer;
use rddns::web::handlers::AppState;
use rddns::web::server::WebServer;
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

/// 构造用于集成测试的内存级 Web 路由器与配套状态
fn create_test_app() -> (axum::Router, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("创建临时配置目录失败");
    let config_path = dir.path().join("rddns_auth_test.toml");
    let config_manager =
        Arc::new(ConfigManager::load_or_create(config_path).expect("加载临时配置管理器失败"));
    let (trigger_tx, _trigger_rx) = mpsc::channel(1);
    let log_buffer = LogBuffer::new(50);
    let state_manager = StateManager::new();
    let cancel_token = CancellationToken::new();

    let state = AppState {
        config_manager,
        trigger_sender: trigger_tx,
        log_buffer,
        state_manager,
        cancel_token,
        active_listen_port: 9876,
        active_not_allow_wan_access: true,
    };

    let router = WebServer::build_router(state);
    (router, dir)
}

/// 辅助函数：构造携带特定连接对端 IP 的请求
fn build_request_with_peer(
    method: &str,
    uri: &str,
    peer_addr: SocketAddr,
    body_str: Option<&str>,
) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);

    if body_str.is_some() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }

    let mut req = builder
        .body(match body_str {
            Some(s) => Body::from(s.to_string()),
            None => Body::empty(),
        })
        .expect("构造 HTTP 请求失败");

    req.extensions_mut().insert(ConnectInfo(peer_addr));
    req
}

#[tokio::test]
async fn test_e2e_auth_workflow_and_rate_limiting() {
    let (app, _dir) = create_test_app();
    let loopback_addr = SocketAddr::from(([127, 0, 0, 1], 54321));
    let remote_addr = SocketAddr::from(([192, 168, 1, 100], 54321));

    // ==========================================
    // 阶段一：未配置管理员凭据状态下的访问防护
    // ==========================================
    {
        // 1.1 查询初始化状态：need_init 应为 true
        let req = build_request_with_peer("GET", "/api/v1/auth/status", loopback_addr, None);
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(json["data"]["need_init"], true);

        // 1.2 访问受保护的配置接口：未初始化前必须被强制拒绝 (403 Forbidden)
        let req = build_request_with_peer("GET", "/api/v1/config", loopback_addr, None);
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // ==========================================
    // 阶段二：首发管理员初始化的来源 IP 防护 (L-7)
    // ==========================================
    {
        // 尝试从非本地回环地址（如局域网 192.168.1.100）调用初始化接口，必须拦截
        let init_body = r#"{"username":"e2eadmin","password":"Strong#Password987"}"#;
        let req =
            build_request_with_peer("POST", "/api/v1/auth/init", remote_addr, Some(init_body));
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // ==========================================
    // 阶段三：本地回环地址初始化管理员与弱密码防御
    // ==========================================
    let username = "e2eadmin";
    let valid_password = "Strong#Password987";
    {
        // 3.1 尝试使用弱密码初始化，必须拦截 (400 Bad Request)
        let weak_body = r#"{"username":"e2eadmin","password":"123"}"#;
        let req =
            build_request_with_peer("POST", "/api/v1/auth/init", loopback_addr, Some(weak_body));
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // 3.2 使用符合复杂度要求的强口令初始化，应成功 (200 OK)
        let valid_body = format!(
            r#"{{"username":"{}","password":"{}"}}"#,
            username, valid_password
        );
        let req = build_request_with_peer(
            "POST",
            "/api/v1/auth/init",
            loopback_addr,
            Some(&valid_body),
        );
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // 3.3 再次查询初始化状态：need_init 应变更为 false
        let req = build_request_with_peer("GET", "/api/v1/auth/status", loopback_addr, None);
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(json["data"]["need_init"], false);
    }

    // ==========================================
    // 阶段四：凭据验证与受保护接口访问
    // ==========================================
    let correct_basic_token = BASE64_STANDARD.encode(format!("{}:{}", username, valid_password));
    let wrong_basic_token = BASE64_STANDARD.encode(format!("{}:WrongPassword!456", username));
    {
        // 4.1 未带凭据访问受保护接口，返回 401 Unauthorized
        let req = build_request_with_peer("GET", "/api/v1/config", loopback_addr, None);
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // 4.2 携带正确凭据访问受保护接口，返回 200 OK
        let mut req = build_request_with_peer("GET", "/api/v1/config", loopback_addr, None);
        req.headers_mut().insert(
            header::AUTHORIZATION,
            format!("Basic {}", correct_basic_token).parse().unwrap(),
        );
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ==========================================
    // 阶段五：连续失败频控与账号锁定拦截
    // ==========================================
    {
        // 连续发送 5 次错误密码请求，触发频控阈值
        for i in 1..=5 {
            let mut req = build_request_with_peer("GET", "/api/v1/config", loopback_addr, None);
            req.headers_mut().insert(
                header::AUTHORIZATION,
                format!("Basic {}", wrong_basic_token).parse().unwrap(),
            );
            let resp = app.clone().oneshot(req).await.unwrap();
            if i < 5 {
                assert_eq!(
                    resp.status(),
                    StatusCode::UNAUTHORIZED,
                    "第 {} 次错误密码应返回 401",
                    i
                );
            }
        }

        // 第 6 次请求（即使携带正确的 Basic Auth 凭据），也必须因账号锁定而被严格拦截 (429 Too Many Requests)
        let mut req = build_request_with_peer("GET", "/api/v1/config", loopback_addr, None);
        req.headers_mut().insert(
            header::AUTHORIZATION,
            format!("Basic {}", correct_basic_token).parse().unwrap(),
        );
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "账号锁定期间即使凭据正确也必须拒绝访问"
        );
    }

    // ==========================================
    // 阶段六：跨站请求伪造 (CSRF) 头部拦截
    // ==========================================
    {
        // 带有 sec-fetch-site: cross-site 的请求必须被明确拒绝 (403 Forbidden)
        let mut req = build_request_with_peer(
            "POST",
            "/api/v1/auth/init",
            loopback_addr,
            Some(r#"{"username":"attacker","password":"Attacker#Password123"}"#),
        );
        req.headers_mut()
            .insert("sec-fetch-site", "cross-site".parse().unwrap());
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "检测到 Sec-Fetch-Site: cross-site 必须拒绝请求"
        );

        // Origin 与 Host 不一致时也必须被明确拒绝 (403 Forbidden)
        let mut req = build_request_with_peer(
            "POST",
            "/api/v1/auth/init",
            loopback_addr,
            Some(r#"{"username":"attacker","password":"Attacker#Password123"}"#),
        );
        req.headers_mut()
            .insert("host", "127.0.0.1:9876".parse().unwrap());
        req.headers_mut()
            .insert("origin", "http://evil-website.com".parse().unwrap());
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "检测到 Origin 与 Host 不一致必须拒绝请求"
        );
    }
}
