use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// 全局跳过 TLS 证书验证开关
static SKIP_VERIFY: AtomicBool = AtomicBool::new(false);

/// 设置全局是否跳过 TLS 证书验证
pub fn set_skip_verify(skip: bool) {
    SKIP_VERIFY.store(skip, Ordering::SeqCst);
    if skip {
        tracing::warn!("⚠️ 已开启 --skipVerify 跳过 TLS 证书验证模式，请注意网络通信安全");
    }
}

/// 获取全局是否跳过 TLS 证书验证
pub fn is_skip_verify() -> bool {
    SKIP_VERIFY.load(Ordering::SeqCst)
}

/// 创建预置安全/跳过证书策略的 Reqwest ClientBuilder
pub fn create_http_client_builder() -> reqwest::ClientBuilder {
    let mut builder = reqwest::Client::builder();
    if is_skip_verify() {
        builder = builder.danger_accept_invalid_certs(true);
    }
    builder
}

/// 创建带指定超时的 Reqwest Client
pub fn create_http_client(timeout: Duration) -> Result<reqwest::Client, reqwest::Error> {
    create_http_client_builder().timeout(timeout).build()
}
