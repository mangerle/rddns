pub mod alidns;
pub mod callback;
pub mod cloudflare;
pub mod dnspod;
pub mod trait_def;

pub use alidns::*;
pub use callback::*;
pub use cloudflare::*;
pub use dnspod::*;
pub use trait_def::*;

use crate::config::model::ProviderConfig;
use std::sync::Arc;

/// 根据配置创建 DNS 驱动实例
pub fn create_dns_provider(config: &ProviderConfig) -> Result<Arc<dyn DnsProvider>, DnsProviderError> {
    match config {
        ProviderConfig::Cloudflare {
            api_token,
            api_key,
            email,
        } => Ok(Arc::new(CloudflareProvider::new(
            api_token.clone(),
            api_key.clone(),
            email.clone(),
        )?)),
        ProviderConfig::AliDns {
            access_key_id,
            access_key_secret,
            endpoint,
        } => Ok(Arc::new(AliDnsProvider::new(
            access_key_id.clone(),
            access_key_secret.clone(),
            endpoint.clone(),
        )?)),
        ProviderConfig::TencentCloud {
            secret_id,
            secret_key,
        } => Ok(Arc::new(TencentCloudProvider::new(
            secret_id.clone(),
            secret_key.clone(),
        )?)),
        ProviderConfig::HuaweiCloud { .. } => Err(DnsProviderError::Other(
            "华为云驱动将在后续扩展版本中支持".to_string(),
        )),
        ProviderConfig::Callback {
            url,
            method,
            headers,
            body,
        } => Ok(Arc::new(CallbackProvider::new(
            url.clone(),
            method.clone(),
            headers.clone(),
            body.clone(),
        )?)),
    }
}
