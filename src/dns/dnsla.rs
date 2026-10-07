use crate::core::domain::ParsedDomain;
use crate::dns::ops::{RecordOps, RecordParams, RemoteRecord};
use crate::dns::trait_def::{DnsProviderError, DnsRecordType, default_ttl};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use reqwest::Client;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::Deserialize;
use serde_json::json;

const DNSLA_RECORD_LIST_URL: &str = "https://api.dns.la/api/recordList";
const DNSLA_RECORD_URL: &str = "https://api.dns.la/api/record";

/// DNS.LA 提供商
pub struct DnsLaProvider {
    api_id: String,
    api_secret: String,
    client: Client,
}

#[derive(Debug, Deserialize)]
struct DnsLaRecord {
    id: String,
    host: String,
    #[serde(rename = "type")]
    record_type: i32,
    data: String,
}

#[derive(Debug, Deserialize)]
struct DnsLaListData {
    results: Option<Vec<DnsLaRecord>>,
}

#[derive(Debug, Deserialize)]
struct DnsLaListResp {
    code: i32,
    msg: Option<String>,
    data: Option<DnsLaListData>,
}

#[derive(Debug, Deserialize)]
struct DnsLaActionResp {
    code: i32,
    msg: Option<String>,
}

impl DnsLaProvider {
    pub fn new(api_id: String, api_secret: String, http_interface: Option<&str>) -> Self {
        Self {
            api_id,
            api_secret,
            client: crate::util::http::create_default_dns_client(http_interface),
        }
    }

    fn build_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let raw = format!("{}:{}", self.api_id, self.api_secret);
        let encoded = BASE64.encode(raw.as_bytes());
        if let Ok(mut hv) = HeaderValue::from_str(&format!("Basic {}", encoded)) {
            hv.set_sensitive(true);
            headers.insert(AUTHORIZATION, hv);
        }
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/json;charset=utf-8"),
        );
        headers
    }

    fn record_type_to_int(record_type: DnsRecordType) -> i32 {
        match record_type {
            DnsRecordType::A => 1,
            DnsRecordType::AAAA => 28,
        }
    }
}

#[async_trait]
impl RecordOps for DnsLaProvider {
    fn provider_name(&self) -> &'static str {
        "DNS.LA"
    }

    async fn list_records(
        &self,
        _zone: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
    ) -> Result<Vec<RemoteRecord>, DnsProviderError> {
        let sub = domain.sub_domain_or_at();
        let type_int = Self::record_type_to_int(record_type);
        let type_int_str = type_int.to_string();

        let list_resp = self
            .client
            .get(DNSLA_RECORD_LIST_URL)
            .headers(self.build_headers())
            .query(&[
                ("domain", domain.root_domain.as_str()),
                ("host", sub),
                ("type", type_int_str.as_str()),
                ("pageIndex", "1"),
                ("pageSize", "100"),
            ])
            .send()
            .await?;

        let status = list_resp.status();
        let body_text = list_resp.text().await?;

        if !status.is_success() {
            return Err(DnsProviderError::http_status(status, &body_text));
        }

        let parsed: DnsLaListResp = serde_json::from_str(&body_text)?;
        if parsed.code != 200 {
            return Err(DnsProviderError::ApiError {
                code: parsed.code.to_string(),
                message: parsed.msg.unwrap_or_else(|| "DNS.LA 查询失败".to_string()),
            });
        }

        let records = parsed.data.and_then(|d| d.results).unwrap_or_default();
        let matched = records
            .into_iter()
            .filter(|r| r.record_type == type_int && r.host.eq_ignore_ascii_case(sub))
            .map(|r| RemoteRecord::new(r.id, r.data))
            .collect();

        Ok(matched)
    }

    async fn create_record(
        &self,
        _zone: &str,
        params: &RecordParams<'_>,
    ) -> Result<(), DnsProviderError> {
        let ttl_val = default_ttl(params.ttl);
        let sub = params.domain.sub_domain_or_at();
        let type_int = Self::record_type_to_int(params.record_type);
        let target_ip_str = params.ip.to_string();

        let create_payload = json!({
            "Domain": params.domain.root_domain,
            "Host": sub,
            "Type": type_int,
            "Data": target_ip_str,
            "TTL": ttl_val
        });

        let post_resp = self
            .client
            .post(DNSLA_RECORD_URL)
            .headers(self.build_headers())
            .json(&create_payload)
            .send()
            .await?;

        let status = post_resp.status();
        let post_text = post_resp.text().await?;
        if !status.is_success() {
            return Err(DnsProviderError::http_status(status, &post_text));
        }

        let act_res: DnsLaActionResp =
            serde_json::from_str(&post_text).unwrap_or(DnsLaActionResp {
                code: -1,
                msg: Some(post_text.clone()),
            });

        if act_res.code == 200 {
            Ok(())
        } else {
            let err_msg = act_res.msg.unwrap_or(post_text);
            Err(DnsProviderError::ApiError {
                code: act_res.code.to_string(),
                message: format!("DNS.LA 创建记录失败: {}", err_msg),
            })
        }
    }

    async fn update_record(
        &self,
        _zone: &str,
        record_id: &str,
        params: &RecordParams<'_>,
    ) -> Result<(), DnsProviderError> {
        let ttl_val = default_ttl(params.ttl);
        let sub = params.domain.sub_domain_or_at();
        let type_int = Self::record_type_to_int(params.record_type);
        let target_ip_str = params.ip.to_string();

        let modify_payload = json!({
            "Id": record_id,
            "Host": sub,
            "Type": type_int,
            "Data": target_ip_str,
            "TTL": ttl_val
        });

        let put_resp = self
            .client
            .put(DNSLA_RECORD_URL)
            .headers(self.build_headers())
            .json(&modify_payload)
            .send()
            .await?;

        let status = put_resp.status();
        let put_text = put_resp.text().await?;
        if !status.is_success() {
            return Err(DnsProviderError::http_status(status, &put_text));
        }

        let act_res: DnsLaActionResp = serde_json::from_str(&put_text).unwrap_or(DnsLaActionResp {
            code: -1,
            msg: Some(put_text.clone()),
        });

        if act_res.code == 200 {
            Ok(())
        } else {
            let err_msg = act_res.msg.unwrap_or(put_text);
            Err(DnsProviderError::ApiError {
                code: act_res.code.to_string(),
                message: format!("DNS.LA 更新记录失败: {}", err_msg),
            })
        }
    }

    async fn delete_record(
        &self,
        _zone: &str,
        record: &RemoteRecord,
        _params: &RecordParams<'_>,
    ) -> Result<(), DnsProviderError> {
        let resp = self
            .client
            .delete(DNSLA_RECORD_URL)
            .headers(self.build_headers())
            .query(&[("id", &record.id)])
            .send()
            .await?;

        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(DnsProviderError::http_status(status, &text));
        }

        let act_res: DnsLaActionResp = serde_json::from_str(&text).unwrap_or(DnsLaActionResp {
            code: -1,
            msg: Some(text.clone()),
        });

        if act_res.code == 200 {
            Ok(())
        } else {
            let err_msg = act_res.msg.unwrap_or(text);
            Err(DnsProviderError::ApiError {
                code: act_res.code.to_string(),
                message: format!("DNS.LA 删除记录失败: {}", err_msg),
            })
        }
    }
}
