pub mod alidns;
pub mod aliesa;
pub mod baidu;
pub mod callback;
pub mod cloudflare;
pub mod cloudns;
pub mod dnsla;
pub mod dnspod;
pub mod dynadot;
pub mod dynv6;
pub mod gcore;
pub mod godaddy;
pub mod huawei;
pub mod name_com;
pub mod namecheap;
pub mod namesilo;
pub mod nowcn;
pub mod porkbun;
pub mod rainyun;
pub mod spaceship;
pub mod tencent_eo;
pub mod traffic_route;
pub mod trait_def;
pub mod vercel;

pub use alidns::*;
pub use aliesa::*;
pub use baidu::*;
pub use callback::*;
pub use cloudflare::*;
pub use cloudns::*;
pub use dnsla::*;
pub use dnspod::*;
pub use dynadot::*;
pub use dynv6::*;
pub use gcore::*;
pub use godaddy::*;
pub use huawei::*;
pub use name_com::*;
pub use namecheap::*;
pub use namesilo::*;
pub use nowcn::*;
pub use porkbun::*;
pub use rainyun::*;
pub use spaceship::*;
pub use tencent_eo::*;
pub use traffic_route::*;
pub use trait_def::*;
pub use vercel::*;

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
        ProviderConfig::Spaceship {
            api_key,
            api_secret,
        } => Ok(Arc::new(SpaceshipProvider::new(
            api_key.clone(),
            api_secret.clone(),
        ))),
        ProviderConfig::Dynadot { password } => {
            Ok(Arc::new(DynadotProvider::new(password.clone())))
        }
        ProviderConfig::Vercel { token, team_id } => Ok(Arc::new(VercelProvider::new(
            token.clone(),
            team_id.clone(),
        ))),
        ProviderConfig::RainYun { api_key, domain_id } => Ok(Arc::new(RainYunProvider::new(
            api_key.clone(),
            domain_id.clone(),
        ))),
        ProviderConfig::ClouDNS {
            auth_id,
            auth_password,
        } => Ok(Arc::new(ClouDnsProvider::new(
            auth_id.clone(),
            auth_password.clone(),
        ))),
        ProviderConfig::Gcore { api_key } => Ok(Arc::new(GcoreProvider::new(api_key.clone()))),
        ProviderConfig::NameCom {
            username,
            api_token,
        } => Ok(Arc::new(NameComProvider::new(
            username.clone(),
            api_token.clone(),
        ))),
        ProviderConfig::DnsLa { api_id, api_secret } => Ok(Arc::new(DnsLaProvider::new(
            api_id.clone(),
            api_secret.clone(),
        ))),
        ProviderConfig::AliEsa {
            access_key_id,
            access_key_secret,
            endpoint,
        } => Ok(Arc::new(AliEsaProvider::new(
            access_key_id.clone(),
            access_key_secret.clone(),
            endpoint.clone(),
        )?)),
        ProviderConfig::EdgeOne {
            secret_id,
            secret_key,
        } => Ok(Arc::new(TencentEoProvider::new(
            secret_id.clone(),
            secret_key.clone(),
        )?)),
        ProviderConfig::NowCn { id, secret } => Ok(Arc::new(NowcnProvider::new_nowcn(
            id.clone(),
            secret.clone(),
        )?)),
        ProviderConfig::Eranet { id, secret } => Ok(Arc::new(NowcnProvider::new_eranet(
            id.clone(),
            secret.clone(),
        )?)),
        ProviderConfig::TNetHk { id, secret } => Ok(Arc::new(NowcnProvider::new_tnethk(
            id.clone(),
            secret.clone(),
        )?)),
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
