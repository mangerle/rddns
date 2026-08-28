use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use hmac::{Hmac, Mac};
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

/// 使用操作系统密码学安全熵源填充随机字节数组 (CSPRNG, 熵源不可用时 fail-fast 终止，防止降级为全零弱密钥)
pub fn fill_random_bytes(dest: &mut [u8]) {
    if let Err(e) = getrandom::fill(dest) {
        panic!("系统密码学安全熵源不可用: {}", e);
    }
}

/// 生成密码学安全的 16 位无符号随机整数 (CSPRNG)
pub fn random_u16() -> u16 {
    let mut bytes = [0u8; 2];
    fill_random_bytes(&mut bytes);
    u16::from_ne_bytes(bytes)
}

/// 生成密码学安全的 32 位无符号随机整数 (CSPRNG)
pub fn random_u32() -> u32 {
    let mut bytes = [0u8; 4];
    fill_random_bytes(&mut bytes);
    u32::from_ne_bytes(bytes)
}

/// 异步执行 bcrypt 密码哈希生成 (移入后台阻塞线程池，防止阻塞 async runtime)
pub async fn hash_password_async(password: String) -> Result<String, String> {
    tokio::task::spawn_blocking(move || {
        bcrypt::hash(password, bcrypt::DEFAULT_COST).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("执行后台哈希任务失败: {}", e))?
}

/// 异步校验 bcrypt 密码哈希 (移入后台阻塞线程池)
pub async fn verify_password_async(password: String, hash: String) -> bool {
    tokio::task::spawn_blocking(move || bcrypt::verify(password, &hash).unwrap_or(false))
        .await
        .unwrap_or(false)
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

/// 构建符合 AWS SigV4 规范的规范化 URL 查询字符串 (按键名升序排序并逐字段 URL 编码)
pub fn build_canonical_query_string<K: AsRef<str>, V: AsRef<str>>(query: &[(K, V)]) -> String {
    let mut sorted: Vec<(&str, &str)> = query
        .iter()
        .map(|(k, v)| (k.as_ref(), v.as_ref()))
        .collect();
    sorted.sort_by(|a, b| a.0.cmp(b.0));

    sorted
        .iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                url::form_urlencoded::byte_serialize(k.as_bytes()).collect::<String>(),
                url::form_urlencoded::byte_serialize(v.as_bytes()).collect::<String>()
            )
        })
        .collect::<Vec<_>>()
        .join("&")
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
            " (提示: 当前服务器系统时钟与网络标准时间偏差过大，请检查并同步系统 NTP 时间)",
        );
    }
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

    #[test]
    fn test_build_canonical_query_string() {
        let query = vec![("b", "2"), ("a", "1 2"), ("c", "3/4")];
        let res = build_canonical_query_string(&query);
        assert_eq!(res, "a=1+2&b=2&c=3%2F4");
    }

    #[test]
    fn test_csprng_random_generation() {
        let mut buf1 = [0u8; 16];
        let mut buf2 = [0u8; 16];
        fill_random_bytes(&mut buf1);
        fill_random_bytes(&mut buf2);
        assert_ne!(buf1, [0u8; 16]);
        assert_ne!(buf1, buf2);

        let r1 = random_u16();
        let r2 = random_u16();
        let r3 = random_u32();
        assert!(r1 != r2 || r3 != 0);
    }
}
