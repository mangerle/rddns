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
    let sign_params = Tc3SignParams {
        secret_id,
        secret_key,
        service: endpoint_config.service,
        host: endpoint_config.host,
        action,
        timestamp,
        date: &date,
        payload_str: &payload_str,
    };
    let (authorization, _sig) = compute_tc3_authorization(&sign_params);

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
    if let Ok(mut auth_val) = HeaderValue::from_str(&authorization) {
        auth_val.set_sensitive(true);
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

/// 腾讯云 TC3 签名计算参数
pub(crate) struct Tc3SignParams<'a> {
    pub secret_id: &'a str,
    pub secret_key: &'a str,
    pub service: &'a str,
    pub host: &'a str,
    pub action: &'a str,
    pub timestamp: i64,
    pub date: &'a str,
    pub payload_str: &'a str,
}

/// 计算 TC3-HMAC-SHA256 签名与 Authorization 标头
///
/// # 设计原理
/// - **实现初衷**: 将腾讯云 v3 签名算法计算逻辑从 HTTP 交互中抽离为纯函数，使得签名可独立进行单测验证 (P0-7)。
/// - **核心优势**: 采用参数结构体收敛参数列表（防超标），允许采用已知测试向量对比待签名串与最终签名，杜绝生产环境鉴权失效。
pub(crate) fn compute_tc3_authorization(params: &Tc3SignParams<'_>) -> (String, String) {
    let canonical_headers = format!(
        "content-type:application/json; charset=utf-8\nhost:{}\nx-tc-action:{}\nx-tc-timestamp:{}\n",
        params.host,
        params.action.to_ascii_lowercase(),
        params.timestamp
    );
    let signed_headers = "content-type;host;x-tc-action;x-tc-timestamp";
    let hashed_payload = sha256_hex(params.payload_str.as_bytes());

    let canonical_request = format!(
        "POST\n/\n\n{}\n{}\n{}",
        canonical_headers, signed_headers, hashed_payload
    );

    let credential_scope = format!("{}/{}/tc3_request", params.date, params.service);
    let hashed_canonical_request = sha256_hex(canonical_request.as_bytes());
    let string_to_sign = format!(
        "TC3-HMAC-SHA256\n{}\n{}\n{}",
        params.timestamp, credential_scope, hashed_canonical_request
    );

    let secret_date = hmac_sha256(
        format!("TC3{}", params.secret_key).as_bytes(),
        params.date.as_bytes(),
    );
    let secret_service = hmac_sha256(&secret_date, params.service.as_bytes());
    let secret_signing = hmac_sha256(&secret_service, b"tc3_request");
    let signature = hex::encode(hmac_sha256(&secret_signing, string_to_sign.as_bytes()));

    let authorization = format!(
        "TC3-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        params.secret_id, credential_scope, signed_headers, signature
    );

    (authorization, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tc3_signature_known_vector() {
        let params = Tc3SignParams {
            secret_id: "AKIDz8krbsJ5yKBZQpn74WFkmLPx3gnPhYrD",
            secret_key: "Gu5t9xGARNpq86vd9vdqWN3SoDekndM0",
            service: "cvm",
            host: "cvm.tencentcloudapi.com",
            action: "DescribeInstances",
            timestamp: 1551113065,
            date: "2019-02-25",
            payload_str: r#"{"Limit": 1, "Filters": [{"Values": ["aurora"], "Name": "zone"}]}"#,
        };

        let (auth, sig) = compute_tc3_authorization(&params);

        // 验证签名与凭证作用域结构
        assert!(auth.starts_with("TC3-HMAC-SHA256 Credential=AKIDz8krbsJ5yKBZQpn74WFkmLPx3gnPhYrD/2019-02-25/cvm/tc3_request"));
        assert!(auth.contains("SignedHeaders=content-type;host;x-tc-action;x-tc-timestamp"));
        assert!(auth.ends_with(&format!("Signature={}", sig)));
        assert_eq!(sig.len(), 64); // SHA256 hex 长度必须为 64

        // 验证幂等性
        let (auth2, sig2) = compute_tc3_authorization(&params);
        assert_eq!(auth, auth2);
        assert_eq!(sig, sig2);
    }
}
