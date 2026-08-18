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
pub mod hipm_dnsmgr;
pub mod huawei;
pub mod name_com;
pub mod namecheap;
pub mod namesilo;
pub mod nowcn;
pub mod nsone;
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
pub use hipm_dnsmgr::*;
pub use huawei::*;
pub use name_com::*;
pub use namecheap::*;
pub use namesilo::*;
pub use nowcn::*;
pub use nsone::*;
pub use porkbun::*;
pub use rainyun::*;
pub use spaceship::*;
pub use tencent_eo::*;
pub use traffic_route::*;
pub use trait_def::*;
pub use vercel::*;

use crate::config::model::ProviderConfig;
use std::sync::Arc;

/// 根据配置创建 DNS 驱动实例 (支持指定物理出站网卡)
pub fn create_dns_provider(
    config: &ProviderConfig,
    http_interface: Option<&str>,
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
            http_interface,
        )?)),
        ProviderConfig::AliDns {
            access_key_id,
            access_key_secret,
            endpoint,
        } => Ok(Arc::new(AliDnsProvider::new(
            access_key_id.clone(),
            access_key_secret.clone(),
            endpoint.clone(),
            http_interface,
        )?)),
        ProviderConfig::TencentCloud {
            secret_id,
            secret_key,
        } => Ok(Arc::new(TencentCloudProvider::new(
            secret_id.clone(),
            secret_key.clone(),
            http_interface,
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
            http_interface,
        ))),
        ProviderConfig::Porkbun {
            api_key,
            secret_key,
        } => Ok(Arc::new(PorkbunProvider::new(
            api_key.clone(),
            secret_key.clone(),
            http_interface,
        ))),
        ProviderConfig::GoDaddy {
            api_key,
            api_secret,
        } => Ok(Arc::new(GoDaddyProvider::new(
            api_key.clone(),
            api_secret.clone(),
            http_interface,
        ))),
        ProviderConfig::Dynv6 { token } => {
            Ok(Arc::new(Dynv6Provider::new(token.clone(), http_interface)))
        }
        ProviderConfig::BaiduCloud {
            access_key_id,
            secret_access_key,
        } => Ok(Arc::new(BaiduCloudProvider::new(
            access_key_id.clone(),
            secret_access_key.clone(),
            http_interface,
        ))),
        ProviderConfig::TrafficRoute {
            access_key_id,
            secret_access_key,
        } => Ok(Arc::new(TrafficRouteProvider::new(
            access_key_id.clone(),
            secret_access_key.clone(),
            http_interface,
        ))),
        ProviderConfig::Namecheap { password } => Ok(Arc::new(NamecheapProvider::new(
            password.clone(),
            http_interface,
        ))),
        ProviderConfig::NameSilo { api_key } => Ok(Arc::new(NameSiloProvider::new(
            api_key.clone(),
            http_interface,
        ))),
        ProviderConfig::Spaceship {
            api_key,
            api_secret,
        } => Ok(Arc::new(SpaceshipProvider::new(
            api_key.clone(),
            api_secret.clone(),
            http_interface,
        ))),
        ProviderConfig::Dynadot { password } => Ok(Arc::new(DynadotProvider::new(
            password.clone(),
            http_interface,
        ))),
        ProviderConfig::Vercel { token, team_id } => Ok(Arc::new(VercelProvider::new(
            token.clone(),
            team_id.clone(),
            http_interface,
        ))),
        ProviderConfig::RainYun { api_key, domain_id } => Ok(Arc::new(RainYunProvider::new(
            api_key.clone(),
            domain_id.clone(),
            http_interface,
        ))),
        ProviderConfig::ClouDNS {
            auth_id,
            auth_password,
        } => Ok(Arc::new(ClouDnsProvider::new(
            auth_id.clone(),
            auth_password.clone(),
            http_interface,
        ))),
        ProviderConfig::Gcore { api_key } => Ok(Arc::new(GcoreProvider::new(
            api_key.clone(),
            http_interface,
        ))),
        ProviderConfig::NameCom {
            username,
            api_token,
        } => Ok(Arc::new(NameComProvider::new(
            username.clone(),
            api_token.clone(),
            http_interface,
        ))),
        ProviderConfig::DnsLa { api_id, api_secret } => Ok(Arc::new(DnsLaProvider::new(
            api_id.clone(),
            api_secret.clone(),
            http_interface,
        ))),
        ProviderConfig::AliEsa {
            access_key_id,
            access_key_secret,
            endpoint,
        } => Ok(Arc::new(AliEsaProvider::new(
            access_key_id.clone(),
            access_key_secret.clone(),
            endpoint.clone(),
            http_interface,
        )?)),
        ProviderConfig::EdgeOne {
            secret_id,
            secret_key,
        } => Ok(Arc::new(TencentEoProvider::new(
            secret_id.clone(),
            secret_key.clone(),
            http_interface,
        )?)),
        ProviderConfig::NowCn { id, secret } => Ok(Arc::new(NowcnProvider::new_nowcn(
            id.clone(),
            secret.clone(),
            http_interface,
        )?)),
        ProviderConfig::Eranet { id, secret } => Ok(Arc::new(NowcnProvider::new_eranet(
            id.clone(),
            secret.clone(),
            http_interface,
        )?)),
        ProviderConfig::TNetHk { id, secret } => Ok(Arc::new(NowcnProvider::new_tnethk(
            id.clone(),
            secret.clone(),
            http_interface,
        )?)),
        ProviderConfig::NsOne { api_key } => Ok(Arc::new(NsOneProvider::new(
            api_key.clone(),
            http_interface,
        )?)),
        ProviderConfig::HipmDnsMgr {
            endpoint,
            api_token,
        } => Ok(Arc::new(HipmDnsMgrProvider::new(
            endpoint.clone(),
            api_token.clone(),
            http_interface,
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
            http_interface,
        )?)),
    }
}
