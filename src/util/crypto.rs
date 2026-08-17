use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;

/// 计算 HMAC-SHA1 并返回 Base64 编码字符串（阿里云 POP 签名规范）
pub fn hmac_sha1_base64(key: &[u8], data: &[u8]) -> String {
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC 密钥初始化失败");
    mac.update(data);
    let result = mac.finalize();
    BASE64_STANDARD.encode(result.into_bytes())
}

/// 计算 HMAC-SHA256 并返回原始字节数组（腾讯云 TC3 签名计算步骤）
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC 密钥初始化失败");
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
}
