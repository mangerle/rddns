use crate::config::storage::ConfigManager;
use crate::util::log_buffer::LogBuffer;
use crate::web::assets::static_handler;
use crate::web::auth::auth_middleware;
use crate::web::handlers::{
    get_config_handler, get_logs_handler, manual_sync_handler, save_config_handler,
    test_ip_handler, test_notify_handler, AppState,
};
use crate::web::sse::sse_log_handler;
use axum::middleware::from_fn_with_state;
use axum::routing::{get, post};
use axum::Router;
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
}

impl WebServer {
    pub fn new(
        config_manager: Arc<ConfigManager>,
        trigger_sender: mpsc::Sender<()>,
        log_buffer: LogBuffer,
    ) -> Self {
        Self {
            config_manager,
            trigger_sender,
            log_buffer,
        }
    }

    pub async fn run(self, cancel_token: CancellationToken) -> Result<(), anyhow::Error> {
        let listen_addr_str = self.config_manager.get_config().listen_addr.clone();
        let addr: SocketAddr = listen_addr_str
            .parse()
            .unwrap_or_else(|_| "127.0.0.1:9876".parse().unwrap());

        let state = AppState {
            config_manager: self.config_manager.clone(),
            trigger_sender: self.trigger_sender,
            log_buffer: self.log_buffer.clone(),
        };

        // API 路由
        let api_routes = Router::new()
            .route("/config", get(get_config_handler).post(save_config_handler))
            .route("/sync", post(manual_sync_handler))
            .route("/test/ip", post(test_ip_handler))
            .route("/test/notify", post(test_notify_handler))
            .route("/logs", get(get_logs_handler))
            .route("/logs/sse", get(sse_log_handler))
            .layer(from_fn_with_state(
                state.clone(),
                auth_middleware,
            ));

        let app = Router::new()
            .nest("/api/v1", api_routes)
            .fallback(static_handler)
            .layer(CorsLayer::permissive())
            .with_state(state);

        let listener = TcpListener::bind(addr).await?;
        tracing::info!("Web 服务已成功监听在: http://{}", addr);

        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                cancel_token.cancelled().await;
                tracing::info!("收到退出信号，Web 服务优雅关闭");
            })
            .await?;

        Ok(())
    }
}
