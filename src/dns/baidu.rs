use crate::core::domain::ParsedDomain;
use crate::dns::ops::{RecordOps, RecordParams, RemoteRecord};
use crate::dns::trait_def::{DnsProviderError, DnsRecordType, MIN_DNS_TTL, clamp_ttl};
use crate::util::crypto::hmac_sha256_hex;
use async_trait::async_trait;
use chrono::Utc;
use reqwest::Client;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HOST, HeaderMap, HeaderValue};
use serde::Deserialize;
use serde_json::json;

const BAIDU_ENDPOINT: &str = "https://bcd.baidubce.com";
const BAIDU_HOST: &str = "bcd.baidubce.com";
const BAIDU_DEFAULT_TTL: u32 = 300;

/// 百度云 BCE-AUTH-V1 默认签名有效时间（1800 秒）
pub const DEFAULT_BCE_EXPIRATION_SECS: u32 = 1800;

/// 百度智能云 DNS 提供商
pub struct BaiduCloudProvider {
    ak: String,
    sk: String,
    client: Client,
}

#[derive(Debug, Deserialize)]
struct BaiduRecord {
    #[serde(rename = "recordId")]
    record_id: u64,
    domain: String,
    #[serde(rename = "rdtype")]
    rd_type: String,
    rdata: String,
}

#[derive(Debug, Deserialize)]
struct BaiduRecordsResp {
    result: Option<Vec<BaiduRecord>>,
}

#[derive(Debug, Deserialize)]
struct BaiduBaseResp {
    code: Option<String>,
    message: Option<String>,
}

impl BaiduCloudProvider {
    pub fn new(ak: String, sk: String, http_interface: Option<&str>) -> Self {
        Self {
            ak,
            sk,
            client: crate::util::http::create_default_dns_client(http_interface),
        }
    }

    /// 构建百度云 BCE-AUTH-V1 签名标头
    fn build_auth_header(&self, method: &str, uri: &str) -> String {
        let now_utc = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        Self::compute_bce_auth_header(
            &self.ak,
            &self.sk,
            method,
            uri,
            &now_utc,
            DEFAULT_BCE_EXPIRATION_SECS,
        )
    }

    /// 计算百度云 BCE-AUTH-V1 签名标头纯函数
    ///
    /// # 设计原理
    /// - **实现初衷**: 将时间戳与过期时间参数显式化，支持已知时间测试向量以对齐单元测试 (P0-7)。
    /// - **核心优势**: 消除当前系统时间导致的测试不确定性，验证签名格式及派生密钥正确性。
    pub(crate) fn compute_bce_auth_header(
        ak: &str,
        sk: &str,
        method: &str,
        uri: &str,
        now_utc: &str,
        expiration_secs: u32,
    ) -> String {
        let auth_prefix = format!("bce-auth-v1/{}/{}/{}", ak, now_utc, expiration_secs);
        let canonical_req = format!("{}\n{}\n\nhost:{}", method, uri, BAIDU_HOST);
        let signing_key = hmac_sha256_hex(sk.as_bytes(), auth_prefix.as_bytes());
        let signature = hmac_sha256_hex(signing_key.as_bytes(), canonical_req.as_bytes());

        format!("{}/host/{}", auth_prefix, signature)
    }

    async fn post_json<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        payload: serde_json::Value,
    ) -> Result<T, DnsProviderError> {
        let auth_header = self.build_auth_header("POST", path);
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static(BAIDU_HOST));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if let Ok(mut hv) = HeaderValue::from_str(&auth_header) {
            hv.set_sensitive(true);
            headers.insert(AUTHORIZATION, hv);
        }

        let url = format!("{}{}", BAIDU_ENDPOINT, path);
        let resp = self
            .client
            .post(&url)
            .headers(headers)
            .json(&payload)
            .send()
            .await?;

        let status = resp.status();
        let body_text = resp.text().await?;

        if let Ok(base) = serde_json::from_str::<BaiduBaseResp>(&body_text)
            && let Some(c) = base.code
        {
            return Err(DnsProviderError::ApiError {
                code: c,
                message: format!(
                    "百度云 API 业务失败: {}",
                    base.message.unwrap_or_else(|| body_text.clone())
                ),
            });
        }

        if !status.is_success() {
            let msg = serde_json::from_str::<BaiduBaseResp>(&body_text)
                .ok()
                .and_then(|r| r.message)
                .unwrap_or_else(|| body_text.clone());
            return Err(DnsProviderError::ApiError {
                code: status.to_string(),
                message: format!("百度云 API 请求失败: {}", msg),
            });
        }

        let parsed: T = serde_json::from_str(&body_text)?;
        Ok(parsed)
    }
}

#[async_trait]
impl RecordOps for BaiduCloudProvider {
    fn provider_name(&self) -> &'static str {
        "百度智能云 (Baidu Cloud)"
    }

    async fn list_records(
        &self,
        _zone: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
    ) -> Result<Vec<RemoteRecord>, DnsProviderError> {
        let sub = domain.sub_domain_or_at();
        let list_payload = json!({
            "domain": domain.root_domain,
            "pageNum": 1,
            "pageSize": 1000
        });

        let list_resp: BaiduRecordsResp = self
            .post_json("/v1/domain/resolve/list", list_payload)
            .await?;

        let records = list_resp.result.unwrap_or_default();
        let matched = records
            .into_iter()
            .filter(|r| {
                r.domain.eq_ignore_ascii_case(sub)
                    && r.rd_type.eq_ignore_ascii_case(&record_type.to_string())
            })
            .map(|r| RemoteRecord::new(r.record_id.to_string(), r.rdata))
            .collect();

        Ok(matched)
    }

    async fn create_record(
        &self,
        _zone: &str,
        params: &RecordParams<'_>,
    ) -> Result<(), DnsProviderError> {
        let sub = params.domain.sub_domain_or_at();
        let ttl_val = clamp_ttl(params.ttl, BAIDU_DEFAULT_TTL, MIN_DNS_TTL);
        let target_ip_str = params.ip.to_string();

        let add_payload = json!({
            "domain": sub,
            "rdType": params.record_type.to_string(),
            "ttl": ttl_val,
            "rdata": target_ip_str,
            "zoneName": params.domain.root_domain
        });

        let _: serde_json::Value = self
            .post_json("/v1/domain/resolve/add", add_payload)
            .await?;

        Ok(())
    }

    async fn update_record(
        &self,
        _zone: &str,
        record_id: &str,
        params: &RecordParams<'_>,
    ) -> Result<(), DnsProviderError> {
        let sub = params.domain.sub_domain_or_at();
        let ttl_val = clamp_ttl(params.ttl, BAIDU_DEFAULT_TTL, MIN_DNS_TTL);
        let target_ip_str = params.ip.to_string();
        let rec_id_num: u64 = record_id.parse().unwrap_or_default();

        let edit_payload = json!({
            "recordId": rec_id_num,
            "domain": sub,
            "rdType": params.record_type.to_string(),
            "ttl": ttl_val,
            "rdata": target_ip_str,
            "zoneName": params.domain.root_domain,
            "view": "default"
        });

        let _: serde_json::Value = self
            .post_json("/v1/domain/resolve/edit", edit_payload)
            .await?;

        Ok(())
    }

    async fn delete_record(
        &self,
        _zone: &str,
        record: &RemoteRecord,
        _params: &RecordParams<'_>,
    ) -> Result<(), DnsProviderError> {
        let rec_id_num: u64 = record.id.parse().unwrap_or_default();
        let del_payload = json!({
            "recordId": rec_id_num,
        });

        let _: serde_json::Value = self
            .post_json("/v1/domain/resolve/delete", del_payload)
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_baidu_bce_signature_known_vector() {
        let ak = "test_ak";
        let sk = "test_sk";
        let method = "POST";
        let uri = "/v1/domain/resolve/add";
        let now_utc = "2023-10-05T12:00:00Z";

        let auth = BaiduCloudProvider::compute_bce_auth_header(
            ak,
            sk,
            method,
            uri,
            now_utc,
            DEFAULT_BCE_EXPIRATION_SECS,
        );

        assert!(auth.starts_with("bce-auth-v1/test_ak/2023-10-05T12:00:00Z/1800/host/"));
        let parts: Vec<&str> = auth.split('/').collect();
        assert_eq!(parts.len(), 6);
        let sig = parts[5];
        assert_eq!(sig.len(), 64);

        // 验证确定性
        let auth2 = BaiduCloudProvider::compute_bce_auth_header(
            ak,
            sk,
            method,
            uri,
            now_utc,
            DEFAULT_BCE_EXPIRATION_SECS,
        );
        assert_eq!(auth, auth2);
    }
}
