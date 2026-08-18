use crate::config::storage::ConfigManager;
use crate::util::log_buffer::LogBuffer;
use crate::web::assets::static_handler;
use crate::web::auth::auth_middleware;
use crate::web::handlers::{
    AppState, get_auth_status_handler, get_config_handler, get_logs_handler,
    get_network_interfaces_handler, get_version_handler, init_auth_handler, login_auth_handler,
    manual_sync_handler, save_config_handler, test_ip_handler, test_notify_handler,
    trigger_upgrade_handler,
};
use crate::web::sse::sse_log_handler;
use axum::Router;
use axum::middleware::from_fn_with_state;
use axum::routing::{get, post};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tower_http::cors::CorsLayer;

pub struct WebServer {
    config_manager: Arc<ConfigManager>,
    trigger_sender: mpsc::Sender<()>,
    log_buffer: LogBuffer,
    cli_listen: Option<String>,
}

impl WebServer {
    pub fn new(
        config_manager: Arc<ConfigManager>,
        trigger_sender: mpsc::Sender<()>,
        log_buffer: LogBuffer,
        cli_listen: Option<String>,
    ) -> Self {
        Self {
            config_manager,
            trigger_sender,
            log_buffer,
            cli_listen,
        }
    }

    /// 解析最终绑定的网络套接字地址（默认纯本地 127.0.0.1）
    fn resolve_bind_addr(cli_listen: Option<&str>, default_port: u16) -> SocketAddr {
        if let Some(s) = cli_listen {
            let s = s.trim();
            // 纯数字端口，如 "8888"
            if let Ok(p) = s.parse::<u16>() {
                return SocketAddr::from(([127, 0, 0, 1], p));
            }
            // 冒号端口，如 ":8888" -> 全网卡监听
            if let Some(p) = s.strip_prefix(':').and_then(|ps| ps.parse::<u16>().ok()) {
                return SocketAddr::from(([0, 0, 0, 0], p));
            }
            // 完整地址，如 "0.0.0.0:8888" 或 "127.0.0.1:8888"
            if let Ok(addr) = s.parse::<SocketAddr>() {
                return addr;
            }
            tracing::warn!("无法解析命令行传入的监听地址 [{}]，将回退至默认地址", s);
        }
        SocketAddr::from(([127, 0, 0, 1], default_port))
    }

    pub async fn run(self, cancel_token: CancellationToken) -> Result<(), anyhow::Error> {
        let port = self.config_manager.get_config().listen_port;
        let addr = Self::resolve_bind_addr(self.cli_listen.as_deref(), port);

        let state = AppState {
            config_manager: self.config_manager.clone(),
            trigger_sender: self.trigger_sender,
            log_buffer: self.log_buffer.clone(),
        };

        // 需受保护的 API 路由 (附带 Basic Auth 校验中间件)
        let protected_routes = Router::new()
            .route("/config", get(get_config_handler).post(save_config_handler))
            .route("/network-interfaces", get(get_network_interfaces_handler))
            .route("/sync", post(manual_sync_handler))
            .route("/test/ip", post(test_ip_handler))
            .route("/test/notify", post(test_notify_handler))
            .route("/logs", get(get_logs_handler))
            .route("/logs/sse", get(sse_log_handler))
            .route("/version", get(get_version_handler))
            .route("/upgrade", post(trigger_upgrade_handler))
            .layer(from_fn_with_state(state.clone(), auth_middleware));

        // 公开 API 路由 (免鉴权，用于首次初始化与登录校验)
        let public_routes = Router::new()
            .route("/auth/status", get(get_auth_status_handler))
            .route("/auth/init", post(init_auth_handler))
            .route("/auth/login", post(login_auth_handler));

        let api_routes = Router::new().merge(protected_routes).merge(public_routes);

        let app = Router::new()
            .nest("/api/v1", api_routes)
            .fallback(static_handler)
            .layer(CorsLayer::permissive())
            .with_state(state);

        let listener = TcpListener::bind(addr).await?;
        tracing::info!("Web 服务已成功监听在: http://{}", addr);

        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            cancel_token.cancelled().await;
            tracing::info!("收到退出信号，Web 服务优雅关闭");
        })
        .await?;

        Ok(())
    }
}
