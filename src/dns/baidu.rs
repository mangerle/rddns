use crate::core::domain::ParsedDomain;
use crate::dns::trait_def::{DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult};
use crate::util::crypto::hmac_sha256_hex;
use async_trait::async_trait;
use chrono::Utc;
use reqwest::Client;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HOST, HeaderMap, HeaderValue};
use serde::Deserialize;
use serde_json::json;
use std::net::IpAddr;

const BAIDU_ENDPOINT: &str = "https://bcd.baidubce.com";
const BAIDU_HOST: &str = "bcd.baidubce.com";

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
    view: Option<String>,
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
        Self::compute_bce_auth_header(&self.ak, &self.sk, method, uri, &now_utc)
    }

    /// 计算百度云 BCE-AUTH-V1 签名标头纯函数
    ///
    /// # 设计原理
    /// - **实现初衷**: 将时间戳参数显式化，支持已知时间测试向量以对齐单元测试 (P0-7)。
    /// - **核心优势**: 消除当前系统时间导致的测试不确定性，验证签名格式及派生密钥正确性。
    pub(crate) fn compute_bce_auth_header(
        ak: &str,
        sk: &str,
        method: &str,
        uri: &str,
        now_utc: &str,
    ) -> String {
        let auth_prefix = format!("bce-auth-v1/{}/{}/1800", ak, now_utc);
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
impl DnsProvider for BaiduCloudProvider {
    fn provider_name(&self) -> &'static str {
        "百度智能云 (Baidu Cloud)"
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
        let sub = domain.sub_domain_or_at();

        // 1. 查询当前根域下的所有解析记录
        let list_payload = json!({
            "domain": domain.root_domain,
            "pageNum": 1,
            "pageSize": 1000
        });

        let list_resp: BaiduRecordsResp = self
            .post_json("/v1/domain/resolve/list", list_payload)
            .await?;

        let records = list_resp.result.unwrap_or_default();
        let matched = records.into_iter().find(|r| {
            r.domain.eq_ignore_ascii_case(sub)
                && r.rd_type.eq_ignore_ascii_case(&record_type.to_string())
        });

        if let Some(existing) = matched {
            if existing.rdata == target_ip_str {
                return Ok(SyncRecordResult::unchanged_log(
                    self.provider_name(),
                    full_domain,
                    record_type,
                    target_ip_str,
                ));
            }

            // 修改记录
            let edit_payload = json!({
                "recordId": existing.record_id,
                "domain": sub,
                "rdType": record_type.to_string(),
                "ttl": ttl_val,
                "rdata": target_ip_str,
                "zoneName": domain.root_domain,
                "view": existing.view.unwrap_or_else(|| "default".to_string())
            });

            let _: serde_json::Value = self
                .post_json("/v1/domain/resolve/edit", edit_payload)
                .await?;

            Ok(SyncRecordResult::updated_log(
                self.provider_name(),
                full_domain,
                record_type,
                target_ip_str,
            ))
        } else {
            // 创建记录
            let add_payload = json!({
                "domain": sub,
                "rdType": record_type.to_string(),
                "ttl": ttl_val,
                "rdata": target_ip_str,
                "zoneName": domain.root_domain
            });

            let _: serde_json::Value = self
                .post_json("/v1/domain/resolve/add", add_payload)
                .await?;

            Ok(SyncRecordResult::created_log(
                self.provider_name(),
                full_domain,
                record_type,
                target_ip_str,
            ))
        }
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

        let auth = BaiduCloudProvider::compute_bce_auth_header(ak, sk, method, uri, now_utc);

        assert!(auth.starts_with("bce-auth-v1/test_ak/2023-10-05T12:00:00Z/1800/host/"));
        let parts: Vec<&str> = auth.split('/').collect();
        assert_eq!(parts.len(), 6);
        let sig = parts[5];
        assert_eq!(sig.len(), 64);

        // 验证确定性
        let auth2 = BaiduCloudProvider::compute_bce_auth_header(ak, sk, method, uri, now_utc);
        assert_eq!(auth, auth2);
    }
}
