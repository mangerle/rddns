use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::sync::LazyLock;
use tokio::sync::Semaphore;
use tokio::task::spawn_blocking;

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;

/// 计算 HMAC-SHA1 并返回 Base64 编码字符串（阿里云 POP 签名规范）
///
/// # 设计原理
/// - **实现初衷**：兼容阿里云旧版 POP API 接口签名标准。
/// - **核心优势**：快速哈希与 Base64 编码组合，无多余分配。
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
///
/// # 设计原理
/// - **实现初衷**：支持腾讯云 TC3-HMAC-SHA256 递归多级密钥派生（如 SecretDate, SecretService 等）。
/// - **核心优势**：直接输出原始字节切片容器，避免中间 Hex 编解码损耗。
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = match HmacSha256::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => return Vec::new(),
    };
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// 计算 HMAC-SHA256 并返回十六进制小写字符串
///
/// # 设计原理
/// - **实现初衷**：为 AWS SigV4、火山引擎、百度云等提供最终签名 Hex 串生成。
pub fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> String {
    let bytes = hmac_sha256(key, data);
    hex::encode(bytes)
}

/// 计算 SHA256 并返回十六进制小写字符串
///
/// # 设计原理
/// - **实现初衷**：用于计算 HTTP 请求体 Payload 哈希与版本更新包校验。
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// 使用操作系统密码学安全熵源填充随机字节数组 (CSPRNG)
///
/// # 设计原理
/// - **实现初衷**：为 STUN 事务 ID、DNS 查询 ID 与临时会话 Token 提供高强度随机源。
/// - **核心优势**：直接调用操作系统底层硬件/内核 CSPRNG。
///
/// # Panics
/// 当操作系统底层熵源完全不可用（极罕见内核级故障）时，为了安全防御杜绝降级为全零弱随机数而立即 panic。
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
///
/// # 设计原理
/// - **实现初衷**：bcrypt 属于密集 CPU 计算，若在 Tokio 工作线程直接计算会引发严重事件循环延迟。
/// - **核心优势**：通过 `spawn_blocking` 将密集计算移交专用线程池。
///
/// 全局 bcrypt 计算并发闸门，限制同时执行的密码哈希校验数量，彻底防范 CPU DoS 耗尽攻击
static BCRYPT_SEMAPHORE: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(4));

/// 异步计算 bcrypt 密码哈希 (移入后台阻塞线程池)
///
/// # Errors
/// 当密码过长（>72字节）或后台阻塞任务执行异常时返回错误。
pub async fn hash_password_async(password: String) -> Result<String, String> {
    let _permit = BCRYPT_SEMAPHORE
        .acquire()
        .await
        .map_err(|e| e.to_string())?;
    spawn_blocking(move || bcrypt::hash(password, bcrypt::DEFAULT_COST).map_err(|e| e.to_string()))
        .await
        .map_err(|e| format!("执行后台哈希任务失败: {}", e))?
}

/// 校验密码强度与合法长度 (S-7)
///
/// # 设计原理
/// - **实现初衷**: 统一密码长度下限（>= 8 位）与上限（<= 72 字节），杜绝 bcrypt 截断风险与弱密码爆破。
/// - **核心优势**: 严格比对字符与字节长度，不执行 `.trim()` 以确保与各端传输的真实凭据完全一致。
///
/// # Errors
/// 当密码为空、长度小于 8 或大于 72 字节时返回错误提示。
pub fn validate_password_strength(password: &str) -> Result<(), &'static str> {
    if password.is_empty() {
        return Err("密码不能为空");
    }
    if password.len() < 8 {
        return Err("密码长度不能少于 8 个字符");
    }
    if password.len() > 72 {
        return Err("密码长度不能超过 72 字节（受 bcrypt 算法上限限制）");
    }
    Ok(())
}

/// 异步校验 bcrypt 密码哈希 (移入后台阻塞线程池)
///
/// # 设计原理
/// - **实现初衷**：避免在 Web 身份验证接口中阻塞异步运行时。
/// - **核心优势**：通过并发闸门控制 CPU 资源消耗，杜绝并发暴破 DoS，并在发生异常时输出明确日志。
pub async fn verify_password_async(password: String, hash: String) -> bool {
    let _permit = match BCRYPT_SEMAPHORE.acquire().await {
        Ok(p) => p,
        Err(e) => {
            log::error!("获取 bcrypt 信号量失败: {}", e);
            return false;
        }
    };
    spawn_blocking(move || match bcrypt::verify(password, &hash) {
        Ok(v) => v,
        Err(e) => {
            log::warn!("密码哈希格式校验异常: {}", e);
            false
        }
    })
    .await
    .unwrap_or_else(|e| {
        log::error!("执行密码校验后台任务异常: {}", e);
        false
    })
}

/// 预置合法 bcrypt 假哈希（cost=12，与 bcrypt::DEFAULT_COST 保持严格一致），用于用户名不匹配时执行常量时间耗时验证，防止时序侧信道攻击枚举用户名 (P1-8/P-5)
pub const DUMMY_BCRYPT_HASH: &str = "$2b$12$BFz/a8fpzpBYZcvfvRG/V.z/jZBasZIV34dyHfiiGhB3UN8EU78ty";

/// 统一常量时间凭据校验，防止利用 bcrypt 耗时与快速短路的时序侧信道攻击枚举系统用户名 (P1-8)
///
/// # 设计原理
/// - **实现初衷**: 当攻击者提交不存在的用户名时，若系统直接返回错误，耗时仅微秒级；而提交存在的用户名时，
///   由于执行了 bcrypt 哈希计算，耗时需 100ms~300ms。攻击者可利用这一时间差精确枚举系统管理员用户名。
/// - **核心优势**: 无论用户名匹配与否，恒定调用 `verify_password_async` 执行哈希计算（用户名错误时验证预设的 Dummy Hash），
///   消除时间侧信道特征。
pub async fn verify_credentials_constant_time(
    input_username: &str,
    input_password: &str,
    target_username: &str,
    target_password_hash: &str,
) -> bool {
    let user_matched = input_username == target_username;
    let hash_to_verify = if user_matched {
        target_password_hash
    } else {
        DUMMY_BCRYPT_HASH
    };

    let pass_matched =
        verify_password_async(input_password.to_string(), hash_to_verify.to_string()).await;
    user_matched && pass_matched
}

/// 阿里云 POP 规范 URL 编码（RFC 3986 基础上的特殊转义规则）
/// 将所有非保留字符（A-Z, a-z, 0-9, '-', '_', '.', '~'）编码为大写百分号形式，
/// 并且将 '+' 编码为 '%20'，'*' 编码为 '%2A'，'%7E' 转回 '~'
///
/// # 设计原理
/// - **实现初衷**：精确满足阿里云 API 网关对请求签名的特殊百分号大写编码要求。
/// - **核心优势**：使用 `String::with_capacity` 预分配内存，避免多次扩容。
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
///
/// # 设计原理
/// - **实现初衷**：满足 AWS / 火山引擎等主流云厂商 SigV4 规范的 Query 参数严格升序排序与编码。
pub fn build_canonical_query_string<K: AsRef<str>, V: AsRef<str>>(query: &[(K, V)]) -> String {
    let mut sorted = Vec::with_capacity(query.len());
    for (k, v) in query {
        sorted.push((k.as_ref(), v.as_ref()));
    }
    sorted.sort_by(|a, b| a.0.cmp(b.0));

    sorted
        .iter()
        .map(|(k, v)| format!("{}={}", pop_url_encode(k), pop_url_encode(v)))
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
        assert_eq!(res, "a=1%202&b=2&c=3%2F4");
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

    #[test]
    fn test_validate_password_strength() {
        assert!(validate_password_strength("").is_err());
        assert!(validate_password_strength("1234567").is_err());
        assert!(validate_password_strength("12345678").is_ok());
        assert!(validate_password_strength("a".repeat(72).as_str()).is_ok());
        assert!(validate_password_strength("a".repeat(73).as_str()).is_err());
    }

    #[tokio::test]
    async fn test_verify_credentials_constant_time() {
        // 使用已知密码生成哈希
        let real_user = "admin";
        let real_pass = "MySecretPass123";
        let real_hash = hash_password_async(real_pass.to_string()).await.unwrap();

        // 1. 正确用户名 + 正确密码
        assert!(
            verify_credentials_constant_time(real_user, real_pass, real_user, &real_hash).await
        );

        // 2. 正确用户名 + 错误密码
        assert!(
            !verify_credentials_constant_time(real_user, "WrongPass", real_user, &real_hash).await
        );

        // 3. 错误用户名 + 正确密码
        assert!(
            !verify_credentials_constant_time("attacker", real_pass, real_user, &real_hash).await
        );

        // 4. 错误用户名 + 错误密码
        assert!(
            !verify_credentials_constant_time("attacker", "WrongPass", real_user, &real_hash).await
        );
    }

    #[test]
    fn test_dummy_bcrypt_hash_cost_matches_default_cost() {
        // 校验 DUMMY_BCRYPT_HASH 的 cost 必须与 bcrypt::DEFAULT_COST 严格一致，防止时序侧信道特征漂移 (P-5)
        let expected_prefix = format!("$2b${:02}$", bcrypt::DEFAULT_COST);
        assert!(
            DUMMY_BCRYPT_HASH.starts_with(&expected_prefix),
            "DUMMY_BCRYPT_HASH 的 cost 与生产系统默认 cost 不一致"
        );
        // 验证该哈希格式为有效 bcrypt 哈希，能够被安全验证
        assert!(!bcrypt::verify("any_password", DUMMY_BCRYPT_HASH).unwrap_or(true));
    }
}
