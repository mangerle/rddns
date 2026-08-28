use crate::dns::trait_def::DnsProviderError;
use crate::util::crypto::{append_ntp_hint_if_expired, hmac_sha256, sha256_hex};
use reqwest::header::{CONTENT_TYPE, HOST, HeaderMap, HeaderValue};
use serde::Deserialize;

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

/// 腾讯云 API 端点元数据配置
#[derive(Debug, Clone, Copy)]
pub struct Tc3ApiEndpoint {
    pub host: &'static str,
    pub service: &'static str,
    pub version: &'static str,
}

/// 腾讯云 API v3 客户端封装
#[derive(Debug, Clone)]
pub struct Tc3Client {
    client: reqwest::Client,
    secret_id: String,
    secret_key: String,
    endpoint: Tc3ApiEndpoint,
}

impl Tc3Client {
    /// 构造新的腾讯云 TC3 客户端
    pub fn new(
        client: reqwest::Client,
        secret_id: impl Into<String>,
        secret_key: impl Into<String>,
        endpoint: Tc3ApiEndpoint,
    ) -> Self {
        Self {
            client,
            secret_id: secret_id.into(),
            secret_key: secret_key.into(),
            endpoint,
        }
    }

    /// 发起 TC3 API 请求
    pub async fn request_api<T: for<'de> Deserialize<'de>>(
        &self,
        action: &str,
        payload_json: serde_json::Value,
    ) -> Result<T, DnsProviderError> {
        request_tc3_api(
            &self.client,
            &self.secret_id,
            &self.secret_key,
            &self.endpoint,
            action,
            payload_json,
        )
        .await
    }
}

/// 执行标准腾讯云 API v3 (TC3-HMAC-SHA256) 签名请求并解析响应
pub async fn request_tc3_api<T: for<'de> Deserialize<'de>>(
    client: &reqwest::Client,
    secret_id: &str,
    secret_key: &str,
    endpoint_config: &Tc3ApiEndpoint,
    action: &str,
    payload_json: serde_json::Value,
) -> Result<T, DnsProviderError> {
    let payload_str = payload_json.to_string();
    let now = chrono::Utc::now();
    let timestamp = now.timestamp();
    let date = now.format("%Y-%m-%d").to_string();

    // 1. 构造规范请求串 CanonicalRequest
    let canonical_headers = format!(
        "content-type:application/json; charset=utf-8\nhost:{}\nx-tc-action:{}\nx-tc-timestamp:{}\n",
        endpoint_config.host,
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
    let credential_scope = format!("{}/{}/tc3_request", date, endpoint_config.service);
    let hashed_canonical_request = sha256_hex(canonical_request.as_bytes());
    let string_to_sign = format!(
        "TC3-HMAC-SHA256\n{}\n{}\n{}",
        timestamp, credential_scope, hashed_canonical_request
    );

    // 3. 计算签名 Signature
    let secret_date = hmac_sha256(format!("TC3{}", secret_key).as_bytes(), date.as_bytes());
    let secret_service = hmac_sha256(&secret_date, endpoint_config.service.as_bytes());
    let secret_signing = hmac_sha256(&secret_service, b"tc3_request");
    let signature = hex::encode(hmac_sha256(&secret_signing, string_to_sign.as_bytes()));

    // 4. 构造 Authorization
    let authorization = format!(
        "TC3-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        secret_id, credential_scope, signed_headers, signature
    );

    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    if let Ok(h_val) = HeaderValue::from_str(endpoint_config.host) {
        headers.insert(HOST, h_val);
    }
    if let Ok(act_val) = HeaderValue::from_str(action) {
        headers.insert("X-TC-Action", act_val);
    }
    if let Ok(ver_val) = HeaderValue::from_str(endpoint_config.version) {
        headers.insert("X-TC-Version", ver_val);
    }
    if let Ok(ts_val) = HeaderValue::from_str(&timestamp.to_string()) {
        headers.insert("X-TC-Timestamp", ts_val);
    }
    if let Ok(auth_val) = HeaderValue::from_str(&authorization) {
        headers.insert("Authorization", auth_val);
    }

    let endpoint_url = format!("https://{}", endpoint_config.host);
    let resp = client
        .post(&endpoint_url)
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
        append_ntp_hint_if_expired(&mut msg, &err.code);
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
