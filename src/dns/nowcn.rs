use crate::core::domain::ParsedDomain;
use crate::dns::trait_def::{DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult};
use crate::util::crypto::{hmac_sha1_base64, pop_url_encode};
use async_trait::async_trait;
use chrono::Utc;
use log::info;
use reqwest::Client;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::net::IpAddr;

pub const NOWCN_ENDPOINT: &str = "https://api.now.cn";
pub const ERANET_ENDPOINT: &str = "https://www.eranet.com";
pub const TNETHK_ENDPOINT: &str = "https://www.tnet.hk";

/// 时代互联 / 时代互联国际版 / TNetHK 通用 DNS 提供商
pub struct NowcnProvider {
    access_instance_id: String,
    secret_key: String,
    endpoint: String,
    provider_name: &'static str,
    client: Client,
}

#[derive(Debug, Deserialize)]
struct NowcnRecordItem {
    id: i64,
    #[serde(rename = "Host")]
    host: Option<String>,
    #[serde(rename = "Type")]
    record_type: Option<String>,
    #[serde(rename = "Value")]
    value: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NowcnListResp {
    #[serde(rename = "Data")]
    data: Option<Vec<NowcnRecordItem>>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NowcnActionResp {
    error: Option<String>,
}

impl NowcnProvider {
    pub fn new_nowcn(
        access_instance_id: String,
        secret_key: String,
        http_interface: Option<&str>,
    ) -> Result<Self, DnsProviderError> {
        Self::new(
            access_instance_id,
            secret_key,
            NOWCN_ENDPOINT.to_string(),
            "时代互联 (NowCN)",
            http_interface,
        )
    }

    pub fn new_eranet(
        access_instance_id: String,
        secret_key: String,
        http_interface: Option<&str>,
    ) -> Result<Self, DnsProviderError> {
        Self::new(
            access_instance_id,
            secret_key,
            ERANET_ENDPOINT.to_string(),
            "时代互联国际版 (Eranet)",
            http_interface,
        )
    }

    pub fn new_tnethk(
        access_instance_id: String,
        secret_key: String,
        http_interface: Option<&str>,
    ) -> Result<Self, DnsProviderError> {
        Self::new(
            access_instance_id,
            secret_key,
            TNETHK_ENDPOINT.to_string(),
            "TNetHK",
            http_interface,
        )
    }

    pub fn new(
        access_instance_id: String,
        secret_key: String,
        endpoint: String,
        provider_name: &'static str,
        http_interface: Option<&str>,
    ) -> Result<Self, DnsProviderError> {
        if access_instance_id.trim().is_empty() || secret_key.trim().is_empty() {
            return Err(DnsProviderError::MissingCredentials(format!(
                "{} 需要配置 AccessInstanceID 与 SecretKey",
                provider_name
            )));
        }

        let client = crate::util::http::create_default_dns_client(http_interface);

        Ok(Self {
            access_instance_id,
            secret_key,
            endpoint,
            provider_name,
            client,
        })
    }

    /// 发送请求并处理 POP 签名
    async fn request_api<T: for<'de> Deserialize<'de>>(
        &self,
        api_path: &str,
        mut params: BTreeMap<String, String>,
    ) -> Result<T, DnsProviderError> {
        let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let nonce = format!("{}", Utc::now().timestamp_nanos_opt().unwrap_or(0));

        params.insert(
            "AccessInstanceID".to_string(),
            self.access_instance_id.clone(),
        );
        params.insert("SignatureMethod".to_string(), "HMAC-SHA1".to_string());
        params.insert("SignatureNonce".to_string(), nonce);
        params.insert("Timestamp".to_string(), timestamp);

        let canonicalized_query: Vec<String> = params
            .iter()
            .map(|(k, v)| format!("{}={}", pop_url_encode(k), pop_url_encode(v)))
            .collect();
        let canonicalized_query_str = canonicalized_query.join("&");

        let string_to_sign = format!(
            "GET&{}&{}",
            pop_url_encode("/"),
            pop_url_encode(&canonicalized_query_str)
        );

        let sign_key = format!("{}&", self.secret_key);
        let signature = hmac_sha1_base64(sign_key.as_bytes(), string_to_sign.as_bytes());

        params.insert("Signature".to_string(), signature);

        let final_query: Vec<String> = params
            .iter()
            .map(|(k, v)| format!("{}={}", pop_url_encode(k), pop_url_encode(v)))
            .collect();
        let final_query_str = final_query.join("&");

        let path_prefix = if api_path.starts_with('/') {
            api_path.to_string()
        } else {
            format!("/{}", api_path)
        };
        let full_url = format!("{}{}?{}", self.endpoint, path_prefix, final_query_str);

        let resp = self
            .client
            .get(&full_url)
            .header("Accept", "application/json")
            .send()
            .await?;

        let status = resp.status();
        let body_text = resp.text().await?;

        if !status.is_success() {
            return Err(DnsProviderError::ApiError {
                code: status.to_string(),
                message: format!("{} 请求失败: {}", self.provider_name, body_text),
            });
        }

        let parsed = serde_json::from_str::<T>(&body_text)?;
        Ok(parsed)
    }
}

#[async_trait]
impl DnsProvider for NowcnProvider {
    fn provider_name(&self) -> &'static str {
        self.provider_name
    }

    async fn sync_record(
        &self,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
        ip: &IpAddr,
        ttl: Option<u32>,
    ) -> Result<SyncRecordResult, DnsProviderError> {
        let full_domain = domain.full_domain();
        let target_ip_str = ip.to_string();
        let ttl_val = ttl.unwrap_or(600).max(1);
        let sub = domain.sub_domain_or_at();

        // 1. 查询解析记录
        let mut list_params = BTreeMap::new();
        list_params.insert("Domain".to_string(), domain.root_domain.clone());
        list_params.insert("Type".to_string(), record_type.to_string());
        list_params.insert("Host".to_string(), sub.to_string());

        let list_resp: NowcnListResp = self
            .request_api("/api/Dns/DescribeRecordIndex", list_params)
            .await?;

        if let Some(err) = list_resp.error.filter(|e| !e.trim().is_empty()) {
            return Err(DnsProviderError::ApiError {
                code: "NowcnListError".to_string(),
                message: format!("{} 查询记录失败: {}", self.provider_name, err),
            });
        }

        let records = list_resp.data.unwrap_or_default();
        let matched = records.into_iter().find(|r| {
            r.record_type
                .as_deref()
                .unwrap_or("")
                .eq_ignore_ascii_case(&record_type.to_string())
                && r.host.as_deref().unwrap_or("").eq_ignore_ascii_case(sub)
        });

        if let Some(existing) = matched {
            if existing.value.as_deref() == Some(&target_ip_str) {
                info!(
                    "[{}] 域名 {} 记录未变化 ({}), 跳过更新",
                    self.provider_name(),
                    full_domain,
                    target_ip_str
                );
                return Ok(SyncRecordResult::unchanged(
                    full_domain,
                    record_type,
                    target_ip_str,
                ));
            }

            // 更新记录 (UpdateDomainRecord)
            let mut mod_params = BTreeMap::new();
            mod_params.insert("Id".to_string(), existing.id.to_string());
            mod_params.insert("Domain".to_string(), domain.root_domain.clone());
            mod_params.insert("Host".to_string(), sub.to_string());
            mod_params.insert("Type".to_string(), record_type.to_string());
            mod_params.insert("Value".to_string(), target_ip_str.clone());
            mod_params.insert("Ttl".to_string(), ttl_val.to_string());

            let act_resp: NowcnActionResp = self
                .request_api("/api/Dns/UpdateDomainRecord", mod_params)
                .await?;

            if let Some(err) = act_resp.error.filter(|e| !e.trim().is_empty()) {
                return Err(DnsProviderError::ApiError {
                    code: "NowcnUpdateError".to_string(),
                    message: format!("{} 更新记录失败: {}", self.provider_name, err),
                });
            }

            info!(
                "[{}] 成功更新域名 {} -> {}",
                self.provider_name(),
                full_domain,
                target_ip_str
            );
            Ok(SyncRecordResult::updated(
                full_domain,
                record_type,
                target_ip_str,
            ))
        } else {
            // 创建记录 (AddDomainRecord)
            let mut add_params = BTreeMap::new();
            add_params.insert("Domain".to_string(), domain.root_domain.clone());
            add_params.insert("Host".to_string(), sub.to_string());
            add_params.insert("Type".to_string(), record_type.to_string());
            add_params.insert("Value".to_string(), target_ip_str.clone());
            add_params.insert("Ttl".to_string(), ttl_val.to_string());

            let act_resp: NowcnActionResp = self
                .request_api("/api/Dns/AddDomainRecord", add_params)
                .await?;

            if let Some(err) = act_resp.error.filter(|e| !e.trim().is_empty()) {
                return Err(DnsProviderError::ApiError {
                    code: "NowcnCreateError".to_string(),
                    message: format!("{} 创建记录失败: {}", self.provider_name, err),
                });
            }

            info!(
                "[{}] 成功创建域名解析 {} -> {}",
                self.provider_name(),
                full_domain,
                target_ip_str
            );
            Ok(SyncRecordResult::created(
                full_domain,
                record_type,
                target_ip_str,
            ))
        }
    }
}
