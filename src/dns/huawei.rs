use crate::core::domain::ParsedDomain;
use crate::dns::trait_def::{
    DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult, SyncStatus,
};
use crate::util::crypto::{append_ntp_hint_if_expired, hmac_sha256_hex, sha256_hex};
use async_trait::async_trait;
use chrono::Utc;
use log::info;
use reqwest::header::{CONTENT_TYPE, HOST, HeaderMap, HeaderName, HeaderValue};
use reqwest::{Client, Method};
use serde::Deserialize;
use serde_json::json;
use std::net::IpAddr;
use std::time::Duration;

const DEFAULT_HUAWEI_ENDPOINT: &str = "https://dns.myhuaweicloud.com";

/// 华为云 DNS 提供商
pub struct HuaweiDnsProvider {
    ak: String,
    sk: String,
    endpoint: String,
    client: Client,
}

#[derive(Debug, Deserialize)]
struct HwZoneItem {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct HwZonesResponse {
    zones: Option<Vec<HwZoneItem>>,
}

#[derive(Debug, Deserialize)]
struct HwRecordsetItem {
    id: String,
    name: String,
    zone_id: Option<String>,
    #[serde(rename = "type")]
    record_type: String,
    records: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct HwRecordsetsResponse {
    recordsets: Option<Vec<HwRecordsetItem>>,
}

#[derive(Debug, Deserialize)]
struct HwErrorResponse {
    code: Option<String>,
    message: Option<String>,
}

impl HuaweiDnsProvider {
    pub fn new(
        ak: String,
        sk: String,
        endpoint: Option<String>,
        http_interface: Option<&str>,
    ) -> Self {
        let ep = endpoint
            .unwrap_or_default()
            .trim()
            .trim_end_matches('/')
            .to_string();
        let endpoint = if ep.is_empty() {
            DEFAULT_HUAWEI_ENDPOINT.to_string()
        } else {
            ep
        };

        let client =
            crate::util::http::create_task_http_client(http_interface, Duration::from_secs(15))
                .unwrap_or_default();

        Self {
            ak,
            sk,
            endpoint,
            client,
        }
    }

    /// 发起经过 SDK-HMAC-SHA256 签名的华为云 API 请求
    async fn request_hw_api<T: for<'de> Deserialize<'de>>(
        &self,
        method: Method,
        path: &str,
        query_params: Vec<(&str, String)>,
        body: Option<String>,
    ) -> Result<T, DnsProviderError> {
        let url_obj = reqwest::Url::parse(&self.endpoint)
            .map_err(|e| DnsProviderError::Other(format!("解析 Endpoint URL 失败: {}", e)))?;
        let host = url_obj.host_str().unwrap_or("dns.myhuaweicloud.com");

        let body_str = body.unwrap_or_default();
        let body_hash = sha256_hex(body_str.as_bytes());
        let x_sdk_date = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();

        // 1. 构建标准化查询字符串 (Canonical Query String)
        let mut sorted_query = query_params.clone();
        sorted_query.sort_by(|a, b| a.0.cmp(b.0));
        let canonical_query_str = sorted_query
            .iter()
            .map(|(k, v)| {
                format!(
                    "{}={}",
                    url::form_urlencoded::byte_serialize(k.as_bytes()).collect::<String>(),
                    url::form_urlencoded::byte_serialize(v.as_bytes()).collect::<String>()
                )
            })
            .collect::<Vec<_>>()
            .join("&");

        // 2. 构建标准化标头 (Canonical Headers)
        let canonical_headers = format!(
            "host:{}\nx-sdk-content-sha256:{}\nx-sdk-date:{}\n",
            host, body_hash, x_sdk_date
        );
        let signed_headers = "host;x-sdk-content-sha256;x-sdk-date";

        // 3. 构建 Canonical Request
        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method.as_str(),
            path,
            canonical_query_str,
            canonical_headers,
            signed_headers,
            body_hash
        );

        // 4. 计算 StringToSign
        let string_to_sign = format!(
            "SDK-HMAC-SHA256\n{}\n{}",
            x_sdk_date,
            sha256_hex(canonical_request.as_bytes())
        );

        // 5. 计算签名
        let signature = hmac_sha256_hex(self.sk.as_bytes(), string_to_sign.as_bytes());

        // 6. 构造 Authorization 标头
        let auth_header_val = format!(
            "SDK-HMAC-SHA256 Access={}, SignedHeaders={}, Signature={}",
            self.ak, signed_headers, signature
        );

        let full_url = if canonical_query_str.is_empty() {
            format!("{}{}", self.endpoint, path)
        } else {
            format!("{}{}?{}", self.endpoint, path, canonical_query_str)
        };

        let mut header_map = HeaderMap::new();
        if let Ok(hv) = HeaderValue::from_str(host) {
            header_map.insert(HOST, hv);
        }
        if let Ok(hv) = HeaderValue::from_str(&x_sdk_date) {
            header_map.insert(HeaderName::from_static("x-sdk-date"), hv);
        }
        if let Ok(hv) = HeaderValue::from_str(&body_hash) {
            header_map.insert(HeaderName::from_static("x-sdk-content-sha256"), hv);
        }
        if let Ok(hv) = HeaderValue::from_str(&auth_header_val) {
            header_map.insert(HeaderName::from_static("authorization"), hv);
        }
        header_map.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/json;charset=utf-8"),
        );

        let mut req = self.client.request(method, &full_url).headers(header_map);
        if !body_str.is_empty() {
            req = req.body(body_str);
        }

        let resp = req.send().await?;
        let status = resp.status();
        let body_text = resp.text().await?;

        if !status.is_success() {
            if let Ok(err_resp) = serde_json::from_str::<HwErrorResponse>(&body_text) {
                let mut msg = err_resp.message.unwrap_or_else(|| body_text.clone());
                let code = err_resp.code.unwrap_or_else(|| status.to_string());
                append_ntp_hint_if_expired(&mut msg, &code);
                return Err(DnsProviderError::ApiError { code, message: msg });
            }
            return Err(DnsProviderError::ApiError {
                code: status.to_string(),
                message: body_text,
            });
        }

        let parsed: T = serde_json::from_str(&body_text)?;
        Ok(parsed)
    }
}

#[async_trait]
impl DnsProvider for HuaweiDnsProvider {
    fn provider_name(&self) -> &'static str {
        "华为云 (Huawei Cloud)"
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
        let ttl_val = ttl.unwrap_or(300).max(1);

        // 华为云要求域名末尾必须带点号 "."
        let hw_domain_name = format!("{}.", full_domain);
        let hw_root_name = format!("{}.", domain.root_domain);

        // 1. 查询现有解析记录集
        let query_params = vec![
            ("name", hw_domain_name.clone()),
            ("type", record_type.to_string()),
        ];

        let list_resp: HwRecordsetsResponse = self
            .request_hw_api(Method::GET, "/v2.1/recordsets", query_params, None)
            .await?;

        let recordsets = list_resp.recordsets.unwrap_or_default();
        let matched = recordsets.into_iter().find(|r| {
            r.name.eq_ignore_ascii_case(&hw_domain_name)
                && r.record_type.eq_ignore_ascii_case(&record_type.to_string())
        });

        if let Some(existing) = matched {
            let cur_records = existing.records.unwrap_or_default();
            if cur_records.len() == 1 && cur_records[0] == target_ip_str {
                info!(
                    "[{}] 域名 {} 记录未变化 ({}), 跳过更新",
                    self.provider_name(),
                    full_domain,
                    target_ip_str
                );
                return Ok(SyncRecordResult {
                    domain: full_domain,
                    record_type,
                    target_ip: target_ip_str,
                    status: SyncStatus::Unchanged,
                    message: "记录未发生变化，无需更新".to_string(),
                });
            }

            // 更新记录 (PUT /v2.1/zones/{zone_id}/recordsets/{recordset_id})
            let zone_id = existing.zone_id.ok_or_else(|| {
                DnsProviderError::Other("华为云记录未返回关联的 zone_id".to_string())
            })?;
            let path = format!("/v2.1/zones/{}/recordsets/{}", zone_id, existing.id);
            let body = json!({
                "records": [target_ip_str],
                "ttl": ttl_val,
            })
            .to_string();

            let _: serde_json::Value = self
                .request_hw_api(Method::PUT, &path, vec![], Some(body))
                .await?;

            info!(
                "[{}] 成功更新域名 {} -> {}",
                self.provider_name(),
                full_domain,
                target_ip_str
            );
            Ok(SyncRecordResult {
                domain: full_domain,
                record_type,
                target_ip: target_ip_str,
                status: SyncStatus::Updated,
                message: "记录更新成功".to_string(),
            })
        } else {
            // 2. 不存在时，查询 Zone ID 并创建
            let zones_resp: HwZonesResponse = self
                .request_hw_api(
                    Method::GET,
                    "/v2.1/zones",
                    vec![("name", hw_root_name.clone())],
                    None,
                )
                .await?;

            let zones = zones_resp.zones.unwrap_or_default();
            let zone = zones
                .into_iter()
                .find(|z| z.name.eq_ignore_ascii_case(&hw_root_name))
                .ok_or_else(|| {
                    DnsProviderError::ZoneNotFound(format!(
                        "在华为云 DNS 中未找到根域名 [{}] 对应的公网 Zone",
                        domain.root_domain
                    ))
                })?;

            let path = format!("/v2.1/zones/{}/recordsets", zone.id);
            let body = json!({
                "name": hw_domain_name,
                "type": record_type.to_string(),
                "records": [target_ip_str],
                "ttl": ttl_val,
            })
            .to_string();

            let _: serde_json::Value = self
                .request_hw_api(Method::POST, &path, vec![], Some(body))
                .await?;

            info!(
                "[{}] 成功创建域名解析 {} -> {}",
                self.provider_name(),
                full_domain,
                target_ip_str
            );
            Ok(SyncRecordResult {
                domain: full_domain,
                record_type,
                target_ip: target_ip_str,
                status: SyncStatus::Created,
                message: "解析记录创建成功".to_string(),
            })
        }
    }
}
