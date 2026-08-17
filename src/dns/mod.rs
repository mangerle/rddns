pub mod alidns;
pub mod baidu;
pub mod callback;
pub mod cloudflare;
pub mod dnspod;
pub mod dynv6;
pub mod godaddy;
pub mod huawei;
pub mod namecheap;
pub mod namesilo;
pub mod porkbun;
pub mod traffic_route;
pub mod trait_def;

pub use alidns::*;
pub use baidu::*;
pub use callback::*;
pub use cloudflare::*;
pub use dnspod::*;
pub use dynv6::*;
pub use godaddy::*;
pub use huawei::*;
pub use namecheap::*;
pub use namesilo::*;
pub use porkbun::*;
pub use traffic_route::*;
pub use trait_def::*;

use crate::config::model::ProviderConfig;
use std::sync::Arc;

/// 根据配置创建 DNS 驱动实例
pub fn create_dns_provider(
    config: &ProviderConfig,
) -> Result<Arc<dyn DnsProvider>, DnsProviderError> {
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
        ProviderConfig::HuaweiCloud {
            access_key_id,
            secret_access_key,
            endpoint,
            ..
        } => Ok(Arc::new(HuaweiDnsProvider::new(
            access_key_id.clone(),
            secret_access_key.clone(),
            endpoint.clone(),
        ))),
        ProviderConfig::Porkbun {
            api_key,
            secret_key,
        } => Ok(Arc::new(PorkbunProvider::new(
            api_key.clone(),
            secret_key.clone(),
        ))),
        ProviderConfig::GoDaddy {
            api_key,
            api_secret,
        } => Ok(Arc::new(GoDaddyProvider::new(
            api_key.clone(),
            api_secret.clone(),
        ))),
        ProviderConfig::Dynv6 { token } => Ok(Arc::new(Dynv6Provider::new(token.clone()))),
        ProviderConfig::BaiduCloud {
            access_key_id,
            secret_access_key,
        } => Ok(Arc::new(BaiduCloudProvider::new(
            access_key_id.clone(),
            secret_access_key.clone(),
        ))),
        ProviderConfig::TrafficRoute {
            access_key_id,
            secret_access_key,
        } => Ok(Arc::new(TrafficRouteProvider::new(
            access_key_id.clone(),
            secret_access_key.clone(),
        ))),
        ProviderConfig::Namecheap { password } => {
            Ok(Arc::new(NamecheapProvider::new(password.clone())))
        }
        ProviderConfig::NameSilo { api_key } => {
            Ok(Arc::new(NameSiloProvider::new(api_key.clone())))
        }
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
