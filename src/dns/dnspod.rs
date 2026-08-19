use crate::core::domain::ParsedDomain;
use crate::dns::trait_def::{
    DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult, SyncStatus,
};
use crate::util::crypto::{hmac_sha256, sha256_hex};
use async_trait::async_trait;
use chrono::Utc;
use log::info;
use reqwest::Client;
use reqwest::header::{CONTENT_TYPE, HOST, HeaderMap, HeaderValue};
use serde::Deserialize;
use serde_json::json;
use std::net::IpAddr;
use std::time::Duration;

const TENCENT_ENDPOINT: &str = "https://dnspod.tencentcloudapi.com";
const TENCENT_HOST: &str = "dnspod.tencentcloudapi.com";
const TENCENT_SERVICE: &str = "dnspod";
const TENCENT_VERSION: &str = "2021-03-23";

pub struct TencentCloudProvider {
    client: Client,
    secret_id: String,
    secret_key: String,
}

impl TencentCloudProvider {
    pub fn new(
        secret_id: String,
        secret_key: String,
        http_interface: Option<&str>,
    ) -> Result<Self, DnsProviderError> {
        if secret_id.trim().is_empty() || secret_key.trim().is_empty() {
            return Err(DnsProviderError::MissingCredentials(
                "腾讯云 DNSPod 需要配置 SecretId 与 SecretKey".to_string(),
            ));
        }

        let client = crate::util::http::create_task_http_client_builder(http_interface)
            .timeout(Duration::from_secs(15))
            .build()?;

        Ok(Self {
            client,
            secret_id,
            secret_key,
        })
    }

    /// 发起腾讯云 TC3-HMAC-SHA256 签名请求
    async fn request_tc3_api<T: for<'de> Deserialize<'de>>(
        &self,
        action: &str,
        payload_json: serde_json::Value,
    ) -> Result<T, DnsProviderError> {
        let payload_str = payload_json.to_string();
        let timestamp = Utc::now().timestamp();
        let date = Utc::now().format("%Y-%m-%d").to_string();

        // 1. 构造规范请求串 CanonicalRequest
        let canonical_headers = format!(
            "content-type:application/json; charset=utf-8\nhost:{}\nx-tc-action:{}\nx-tc-timestamp:{}\n",
            TENCENT_HOST,
            action.to_ascii_lowercase(),
            timestamp
        );
        let signed_headers = "content-type;host;x-tc-action;x-tc-timestamp";
        let hashed_payload = sha256_hex(payload_str.as_bytes());

        let canonical_request = format!(
            "POST\n/\n\n{}\n{}\n{}",
            canonical_headers, signed_headers, hashed_payload
        );

        // 2. 构造待签名字符串 StringToSign
        let credential_scope = format!("{}/{}/tc3_request", date, TENCENT_SERVICE);
        let hashed_canonical_request = sha256_hex(canonical_request.as_bytes());
        let string_to_sign = format!(
            "TC3-HMAC-SHA256\n{}\n{}\n{}",
            timestamp, credential_scope, hashed_canonical_request
        );

        // 3. 计算签名 Signature
        let secret_date = hmac_sha256(
            format!("TC3{}", self.secret_key).as_bytes(),
            date.as_bytes(),
        );
        let secret_service = hmac_sha256(&secret_date, TENCENT_SERVICE.as_bytes());
        let secret_signing = hmac_sha256(&secret_service, b"tc3_request");
        let signature = hex::encode(hmac_sha256(&secret_signing, string_to_sign.as_bytes()));

        // 4. 构造 Authorization
        let authorization = format!(
            "TC3-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            self.secret_id, credential_scope, signed_headers, signature
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        );
        headers.insert(HOST, HeaderValue::from_static(TENCENT_HOST));
        if let Ok(act_val) = HeaderValue::from_str(action) {
            headers.insert("X-TC-Action", act_val);
        }
        headers.insert("X-TC-Version", HeaderValue::from_static(TENCENT_VERSION));
        if let Ok(ts_val) = HeaderValue::from_str(&timestamp.to_string()) {
            headers.insert("X-TC-Timestamp", ts_val);
        }
        if let Ok(auth_val) = HeaderValue::from_str(&authorization) {
            headers.insert("Authorization", auth_val);
        }

        let resp = self
            .client
            .post(TENCENT_ENDPOINT)
            .headers(headers)
            .body(payload_str)
            .send()
            .await?;

        let status = resp.status();
        let body_text = resp.text().await?;

        if !status.is_success() {
            return Err(DnsProviderError::ApiError {
                code: status.to_string(),
                message: body_text,
            });
        }

        let full_resp: TcWrapperResponse<T> = serde_json::from_str(&body_text)?;
        if let Some(err) = full_resp.response.error {
            let mut msg = err.message;
            if err.code.contains("Expire")
                || msg.to_ascii_lowercase().contains("expired")
                || msg.to_ascii_lowercase().contains("timestamp")
            {
                msg.push_str(" (💡 提示: 当前服务器系统时钟与网络标准时间偏差过大，请检查并同步系统 NTP 时间)");
            }
            return Err(DnsProviderError::ApiError {
                code: err.code,
                message: msg,
            });
        }

        full_resp
            .response
            .data
            .ok_or_else(|| DnsProviderError::Other("腾讯云 API 响应缺少数据实体".to_string()))
    }
}

#[async_trait]
impl DnsProvider for TencentCloudProvider {
    fn provider_name(&self) -> &'static str {
        "腾讯云 (DNSPod)"
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
        let sub_domain = domain.sub_domain_or_at().to_string();
        let root_domain = domain.root_domain.clone();
        let record_line = domain
            .custom_params
            .get("line")
            .cloned()
            .unwrap_or_else(|| "默认".to_string());
        let ttl_val = ttl.unwrap_or(600).max(1);

        // 1. 查询现有解析记录列表 (单页最大 100 条)
        let list_payload = json!({
            "Domain": root_domain,
            "Subdomain": sub_domain,
            "RecordType": record_type.to_string(),
            "Limit": 100,
        });

        let list_res: Result<TcRecordListResponse, DnsProviderError> = self
            .request_tc3_api("DescribeRecordList", list_payload)
            .await;

        let records = match list_res {
            Ok(data) => data.record_list.unwrap_or_default(),
            Err(DnsProviderError::ApiError { ref code, .. })
                if code == "ResourceNotFound.NoDataOfRecord"
                    || code == "ResourceNotFound.NoDataOfDomain" =>
            {
                // 腾讯云 DNSPod 在没有查到记录时会返回 ResourceNotFound 错误码，此处应视为空记录列表
                Vec::new()
            }
            Err(e) => return Err(e),
        };

        let matched = records.into_iter().find(|r| {
            let name_match = r.name.eq_ignore_ascii_case(&sub_domain);
            let type_match = r.record_type.eq_ignore_ascii_case(&record_type.to_string());
            let line_match = if let Some(ref l) = r.line {
                l.eq_ignore_ascii_case(&record_line)
            } else {
                true
            };
            name_match && type_match && line_match
        });

        if let Some(existing) = matched {
            if existing.value == target_ip_str {
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

            // 修改记录
            let modify_payload = json!({
                "Domain": root_domain,
                "RecordId": existing.record_id,
                "SubDomain": sub_domain,
                "RecordType": record_type.to_string(),
                "RecordLine": record_line,
                "Value": target_ip_str,
                "TTL": ttl_val,
            });

            let _: serde_json::Value = self.request_tc3_api("ModifyRecord", modify_payload).await?;

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
            // 创建记录
            let create_payload = json!({
                "Domain": root_domain,
                "SubDomain": sub_domain,
                "RecordType": record_type.to_string(),
                "RecordLine": record_line,
                "Value": target_ip_str,
                "TTL": ttl_val,
            });

            let _: serde_json::Value = self.request_tc3_api("CreateRecord", create_payload).await?;

            info!(
                "[{}] 成功创建域名 {} -> {}",
                self.provider_name(),
                full_domain,
                target_ip_str
            );
            Ok(SyncRecordResult {
                domain: full_domain,
                record_type,
                target_ip: target_ip_str,
                status: SyncStatus::Created,
                message: "记录添加成功".to_string(),
            })
        }
    }
}

#[derive(Debug, Deserialize)]
struct TcWrapperResponse<T> {
    #[serde(rename = "Response")]
    response: TcInnerResponse<T>,
}

#[derive(Debug, Deserialize)]
struct TcInnerResponse<T> {
    #[serde(rename = "Error")]
    error: Option<TcApiError>,
    #[serde(flatten)]
    data: Option<T>,
}

#[derive(Debug, Deserialize)]
struct TcApiError {
    #[serde(rename = "Code")]
    code: String,
    #[serde(rename = "Message")]
    message: String,
}

#[derive(Debug, Deserialize)]
struct TcRecordListResponse {
    #[serde(rename = "RecordList")]
    record_list: Option<Vec<TcRecordItem>>,
}

#[derive(Debug, Deserialize)]
struct TcRecordItem {
    #[serde(rename = "RecordId")]
    record_id: u64,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Type")]
    record_type: String,
    #[serde(rename = "Value")]
    value: String,
    #[serde(rename = "Line")]
    line: Option<String>,
}
