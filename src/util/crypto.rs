use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use hmac::{Hmac, Mac};
use reqwest::header::{CONTENT_TYPE, HOST, HeaderMap, HeaderValue};
use serde::Deserialize;
use sha1::Sha1;
use sha2::{Digest, Sha256};

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;

/// 计算 HMAC-SHA1 并返回 Base64 编码字符串（阿里云 POP 签名规范）
pub fn hmac_sha1_base64(key: &[u8], data: &[u8]) -> String {
    let mut mac = match HmacSha1::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => return String::new(),
    };
    mac.update(data);
    let result = mac.finalize();
    BASE64_STANDARD.encode(result.into_bytes())
}

/// 计算 HMAC-SHA256 并返回原始字节数组（腾讯云 TC3 签名计算步骤）
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = match HmacSha256::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => return Vec::new(),
    };
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// 计算 HMAC-SHA256 并返回十六进制小写字符串
#[allow(dead_code)]
pub fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> String {
    let bytes = hmac_sha256(key, data);
    hex::encode(bytes)
}

/// 计算 SHA256 并返回十六进制小写字符串
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// 阿里云 POP 规范 URL 编码（RFC 3986 基础上的特殊转义规则）
/// 将所有非保留字符（A-Z, a-z, 0-9, '-', '_', '.', '~'）编码为大写百分号形式，
/// 并且将 '+' 编码为 '%20'，'*' 编码为 '%2A'，'%7E' 转回 '~'
pub fn pop_url_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 3 / 2);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(b as char);
            }
            _ => {
                result.push_str(&format!("%{:02X}", b));
            }
        }
    }
    result
}

/// 若错误信息或错误码中包含时间戳/时钟过期特征，自动追加 NTP 时间同步提示
pub fn append_ntp_hint_if_expired(msg: &mut String, code: &str) {
    let lower_msg = msg.to_ascii_lowercase();
    let lower_code = code.to_ascii_lowercase();
    if lower_code.contains("expire")
        || lower_code.contains("timestamp")
        || lower_msg.contains("expired")
        || lower_msg.contains("time stamp")
        || lower_msg.contains("timestamp")
    {
        msg.push_str(
            " (💡 提示: 当前服务器系统时钟与网络标准时间偏差过大，请检查并同步系统 NTP 时间)",
        );
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

/// 腾讯云 API 端点元数据配置
#[derive(Debug, Clone, Copy)]
pub struct Tc3ApiEndpoint {
    pub host: &'static str,
    pub service: &'static str,
    pub version: &'static str,
}

/// 执行标准腾讯云 API v3 (TC3-HMAC-SHA256) 签名请求并解析响应
pub async fn request_tc3_api<T: for<'de> Deserialize<'de>>(
    client: &reqwest::Client,
    secret_id: &str,
    secret_key: &str,
    endpoint_config: &Tc3ApiEndpoint,
    action: &str,
    payload_json: serde_json::Value,
) -> Result<T, crate::dns::trait_def::DnsProviderError> {
    let payload_str = payload_json.to_string();
    let timestamp = chrono::Utc::now().timestamp();
    let date = chrono::Utc::now().format("%Y-%m-%d").to_string();

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
        return Err(crate::dns::trait_def::DnsProviderError::ApiError {
            code: status.to_string(),
            message: body_text,
        });
    }

    let full_resp: TcWrapperResponse<T> = serde_json::from_str(&body_text)?;
    if let Some(err) = full_resp.response.error {
        let mut msg = err.message;
        append_ntp_hint_if_expired(&mut msg, &err.code);
        return Err(crate::dns::trait_def::DnsProviderError::ApiError {
            code: err.code,
            message: msg,
        });
    }

    full_resp.response.data.ok_or_else(|| {
        crate::dns::trait_def::DnsProviderError::Other("腾讯云 API 响应缺少数据实体".to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pop_url_encode() {
        assert_eq!(pop_url_encode("test-value.1_~"), "test-value.1_~");
        assert_eq!(pop_url_encode("a b/c=d&e"), "a%20b%2Fc%3Dd%26e");
    }

    #[test]
    fn test_sha256_hex() {
        let digest = sha256_hex(b"");
        assert_eq!(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_hmac_sha256_hex() {
        let key = b"secret";
        let data = b"hello world";
        let res = hmac_sha256_hex(key, data);
        assert_eq!(
            res,
            "734cc62f32841568f45715aeb9f4d7891324e6d948e4c6c60c0621cdac48623a"
        );
    }

    #[test]
    fn test_append_ntp_hint_if_expired() {
        let mut msg = "Signature expired".to_string();
        append_ntp_hint_if_expired(&mut msg, "InvalidTimestamp");
        assert!(msg.contains("NTP 时间"));

        let mut normal_msg = "Invalid password".to_string();
        append_ntp_hint_if_expired(&mut normal_msg, "AuthFailed");
        assert_eq!(normal_msg, "Invalid password");
    }
}
