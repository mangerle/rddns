use super::ProviderConfig;
use crate::config::model::{mask_opt, mask_str, restore_opt, restore_str};

impl ProviderConfig {
    /// 对配置中的敏感凭据进行掩码脱敏 (P1-5)
    pub fn mask_credentials(&mut self) {
        match self {
            Self::Cloudflare {
                api_token, api_key, ..
            } => {
                mask_opt(api_token);
                mask_opt(api_key);
            }
            Self::AliDns {
                access_key_secret, ..
            }
            | Self::AliEsa {
                access_key_secret, ..
            } => mask_str(access_key_secret),
            Self::TencentCloud { secret_key, .. } | Self::EdgeOne { secret_key, .. } => {
                mask_str(secret_key);
            }
            Self::HuaweiCloud {
                secret_access_key, ..
            }
            | Self::BaiduCloud {
                secret_access_key, ..
            }
            | Self::TrafficRoute {
                secret_access_key, ..
            } => mask_str(secret_access_key),
            Self::Porkbun { secret_key, .. } => mask_str(secret_key),
            Self::GoDaddy { api_secret, .. }
            | Self::Spaceship { api_secret, .. }
            | Self::DnsLa { api_secret, .. } => mask_str(api_secret),
            Self::ClouDNS { auth_password, .. } => mask_str(auth_password),
            Self::NameCom { api_token, .. } | Self::HipmDnsMgr { api_token, .. } => {
                mask_str(api_token);
            }
            Self::NowCn { secret, .. }
            | Self::Eranet { secret, .. }
            | Self::TNetHk { secret, .. } => mask_str(secret),
            Self::Namecheap { password } | Self::Dynadot { password } => mask_str(password),
            Self::Dynv6 { token } | Self::Vercel { token, .. } => mask_str(token),
            Self::NameSilo { api_key }
            | Self::RainYun { api_key, .. }
            | Self::Gcore { api_key }
            | Self::NsOne { api_key } => mask_str(api_key),
            Self::Callback { .. } => {}
        }
    }

    /// 根据旧配置还原未被修改的掩码凭据 (P1-5)
    pub fn restore_masked_credentials(&mut self, old: &Self) {
        match (self, old) {
            (
                Self::Cloudflare {
                    api_token, api_key, ..
                },
                Self::Cloudflare {
                    api_token: old_token,
                    api_key: old_key,
                    ..
                },
            ) => {
                restore_opt(api_token, old_token);
                restore_opt(api_key, old_key);
            }
            (
                Self::AliDns {
                    access_key_secret, ..
                },
                Self::AliDns {
                    access_key_secret: old_sec,
                    ..
                },
            )
            | (
                Self::AliEsa {
                    access_key_secret, ..
                },
                Self::AliEsa {
                    access_key_secret: old_sec,
                    ..
                },
            ) => restore_str(access_key_secret, old_sec),
            (
                Self::TencentCloud { secret_key, .. },
                Self::TencentCloud {
                    secret_key: old_sec,
                    ..
                },
            )
            | (
                Self::EdgeOne { secret_key, .. },
                Self::EdgeOne {
                    secret_key: old_sec,
                    ..
                },
            ) => restore_str(secret_key, old_sec),
            (
                Self::HuaweiCloud {
                    secret_access_key, ..
                },
                Self::HuaweiCloud {
                    secret_access_key: old_sec,
                    ..
                },
            )
            | (
                Self::BaiduCloud {
                    secret_access_key, ..
                },
                Self::BaiduCloud {
                    secret_access_key: old_sec,
                    ..
                },
            )
            | (
                Self::TrafficRoute {
                    secret_access_key, ..
                },
                Self::TrafficRoute {
                    secret_access_key: old_sec,
                    ..
                },
            ) => restore_str(secret_access_key, old_sec),
            (
                Self::Porkbun { secret_key, .. },
                Self::Porkbun {
                    secret_key: old_sec,
                    ..
                },
            ) => restore_str(secret_key, old_sec),
            (
                Self::GoDaddy { api_secret, .. },
                Self::GoDaddy {
                    api_secret: old_sec,
                    ..
                },
            )
            | (
                Self::Spaceship { api_secret, .. },
                Self::Spaceship {
                    api_secret: old_sec,
                    ..
                },
            )
            | (
                Self::DnsLa { api_secret, .. },
                Self::DnsLa {
                    api_secret: old_sec,
                    ..
                },
            ) => restore_str(api_secret, old_sec),
            (
                Self::ClouDNS { auth_password, .. },
                Self::ClouDNS {
                    auth_password: old_sec,
                    ..
                },
            ) => restore_str(auth_password, old_sec),
            (
                Self::NameCom { api_token, .. },
                Self::NameCom {
                    api_token: old_sec, ..
                },
            )
            | (
                Self::HipmDnsMgr { api_token, .. },
                Self::HipmDnsMgr {
                    api_token: old_sec, ..
                },
            ) => restore_str(api_token, old_sec),
            (
                Self::NowCn { secret, .. },
                Self::NowCn {
                    secret: old_sec, ..
                },
            )
            | (
                Self::Eranet { secret, .. },
                Self::Eranet {
                    secret: old_sec, ..
                },
            )
            | (
                Self::TNetHk { secret, .. },
                Self::TNetHk {
                    secret: old_sec, ..
                },
            ) => restore_str(secret, old_sec),
            (
                Self::Namecheap { password },
                Self::Namecheap {
                    password: old_pwd, ..
                },
            )
            | (
                Self::Dynadot { password },
                Self::Dynadot {
                    password: old_pwd, ..
                },
            ) => restore_str(password, old_pwd),
            (Self::Dynv6 { token }, Self::Dynv6 { token: old_tok })
            | (Self::Vercel { token, .. }, Self::Vercel { token: old_tok, .. }) => {
                restore_str(token, old_tok)
            }
            (
                Self::NameSilo { api_key },
                Self::NameSilo {
                    api_key: old_key, ..
                },
            )
            | (
                Self::RainYun { api_key, .. },
                Self::RainYun {
                    api_key: old_key, ..
                },
            )
            | (Self::Gcore { api_key }, Self::Gcore { api_key: old_key })
            | (Self::NsOne { api_key }, Self::NsOne { api_key: old_key }) => {
                restore_str(api_key, old_key);
            }
            _ => {}
        }
    }

    /// 判断两个服务商配置是否属于同一公开账号标识（用于原地重命名任务时的安全凭据回退核验）
    pub(crate) fn is_same_account_identity(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Cloudflare { email: a, .. }, Self::Cloudflare { email: b, .. }) => a == b,
            (
                Self::AliDns {
                    access_key_id: a, ..
                },
                Self::AliDns {
                    access_key_id: b, ..
                },
            )
            | (
                Self::AliEsa {
                    access_key_id: a, ..
                },
                Self::AliEsa {
                    access_key_id: b, ..
                },
            ) => a == b,
            (Self::TencentCloud { secret_id: a, .. }, Self::TencentCloud { secret_id: b, .. })
            | (Self::EdgeOne { secret_id: a, .. }, Self::EdgeOne { secret_id: b, .. }) => a == b,
            (
                Self::HuaweiCloud {
                    access_key_id: a, ..
                },
                Self::HuaweiCloud {
                    access_key_id: b, ..
                },
            )
            | (
                Self::BaiduCloud {
                    access_key_id: a, ..
                },
                Self::BaiduCloud {
                    access_key_id: b, ..
                },
            )
            | (
                Self::TrafficRoute {
                    access_key_id: a, ..
                },
                Self::TrafficRoute {
                    access_key_id: b, ..
                },
            ) => a == b,
            (Self::Porkbun { api_key: a, .. }, Self::Porkbun { api_key: b, .. })
            | (Self::GoDaddy { api_key: a, .. }, Self::GoDaddy { api_key: b, .. })
            | (Self::Spaceship { api_key: a, .. }, Self::Spaceship { api_key: b, .. }) => a == b,
            (Self::DnsLa { api_id: a, .. }, Self::DnsLa { api_id: b, .. }) => a == b,
            (Self::ClouDNS { auth_id: a, .. }, Self::ClouDNS { auth_id: b, .. }) => a == b,
            (Self::NameCom { username: a, .. }, Self::NameCom { username: b, .. }) => a == b,
            (Self::HipmDnsMgr { endpoint: a, .. }, Self::HipmDnsMgr { endpoint: b, .. }) => a == b,
            (Self::NowCn { id: a, .. }, Self::NowCn { id: b, .. })
            | (Self::Eranet { id: a, .. }, Self::Eranet { id: b, .. })
            | (Self::TNetHk { id: a, .. }, Self::TNetHk { id: b, .. }) => a == b,
            (Self::Vercel { team_id: a, .. }, Self::Vercel { team_id: b, .. }) => a == b,
            (Self::Namecheap { .. }, Self::Namecheap { .. })
            | (Self::Dynadot { .. }, Self::Dynadot { .. })
            | (Self::Dynv6 { .. }, Self::Dynv6 { .. })
            | (Self::NameSilo { .. }, Self::NameSilo { .. })
            | (Self::RainYun { .. }, Self::RainYun { .. })
            | (Self::Gcore { .. }, Self::Gcore { .. })
            | (Self::NsOne { .. }, Self::NsOne { .. }) => true,
            _ => false,
        }
    }
}
