use crate::core::domain::ParsedDomain;
use crate::dns::ops::{RecordOps, RecordParams, RemoteRecord};
use crate::dns::trait_def::{DnsProviderError, DnsRecordType, default_ttl};
use crate::dns::zone_cache::TtlCache;
use async_trait::async_trait;
use reqwest::Client;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::LazyLock;
use std::time::Duration;

/// HiPM Domain ID 缓存生存期（2 小时）
const HIPM_DOMAIN_CACHE_TTL: Duration = Duration::from_secs(7200);

/// HiPM Domain ID 缓存容量硬上限
const HIPM_DOMAIN_CACHE_CAPACITY: usize = 128;

/// HiPM Domain ID 缓存键（端点 + 根域名）
///
/// # 设计原理
/// 以端点参与键构造，确保多套 HiPM 实例（不同面板）的缓存互不污染。
#[derive(Debug, Hash, PartialEq, Eq, Clone)]
struct HipmDomainCacheKey {
    endpoint: String,
    root_domain: String,
}

/// 全局 HiPM Domain ID 缓存池
///
/// # 设计原理
/// 原实现每次 `sync_record` 都重新解析 Domain ID（1 次关键字查询 + 最多
/// 5 次分页查询），配合上层「每域名 × 每协议一次调度」的单轮 HTTP 请求
/// 放大可达 12~36 倍。Zone 解析结果在 TTL 窗口内保持稳定，缓存可消除
/// 该放大。
static HIPM_DOMAIN_CACHE: LazyLock<TtlCache<HipmDomainCacheKey, i64>> =
    LazyLock::new(|| TtlCache::new(HIPM_DOMAIN_CACHE_TTL, HIPM_DOMAIN_CACHE_CAPACITY));

/// HiPM DNSMgr 驱动提供商
pub struct HipmDnsMgrProvider {
    client: Client,
    /// 逐请求携带的鉴权头（含敏感凭据，禁止写入日志）
    headers: HeaderMap,
    endpoint: String,
}

#[derive(Debug, Deserialize)]
struct DnsMgrApiResponse {
    code: i32,
    data: Option<Value>,
    #[serde(default)]
    msg: String,
}

#[derive(Debug, Deserialize)]
struct DnsMgrDomainItem {
    id: i64,
    name: String,
}

#[derive(Debug, Deserialize)]
struct DnsMgrRecordItem {
    id: Value, // string or int
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    value: String,
}

impl HipmDnsMgrProvider {
    pub fn new(
        endpoint: Option<String>,
        api_token: String,
        http_interface: Option<&str>,
    ) -> Result<Self, DnsProviderError> {
        if api_token.trim().is_empty() {
            return Err(DnsProviderError::MissingCredentials(
                "HiPM DNSMgr 需要配置 API Token (Secret)".to_string(),
            ));
        }

        // Endpoint 必须显式配置 (P1-9)
        //
        // 原实现以 `https://dnsmgr.example.com`（RFC 2606 保留的示例域名）
        // 作为默认值。用户只填 token 不填 endpoint 时，服务商会向一个
        // 必然解析失败的占位域名发起请求，报出的是 DNS 解析错误而非
        // 「endpoint 未配置」，排障方向被完全误导。
        let base = endpoint
            .map(|e| e.trim().to_string())
            .filter(|e| !e.is_empty());
        let Some(base) = base else {
            return Err(DnsProviderError::MissingCredentials(
                "HiPM DNSMgr 必须配置 Endpoint（面板地址，如 https://your-dnsmgr.example.com）"
                    .to_string(),
            ));
        };
        let trimmed_base = base
            .trim_end_matches('/')
            .trim_end_matches("/api")
            .to_string();

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let mut auth_val =
            HeaderValue::from_str(&format!("Bearer {}", api_token.trim())).map_err(|e| {
                DnsProviderError::MissingCredentials(format!("无效的 API Token: {}", e))
            })?;
        auth_val.set_sensitive(true);
        headers.insert(AUTHORIZATION, auth_val);

        // 复用全局连接池缓存，避免每轮同步重复进行 TCP/TLS 握手
        let client = crate::util::http::create_default_dns_client(http_interface);

        Ok(Self {
            client,
            headers,
            endpoint: trimmed_base,
        })
    }

    /// 构造携带鉴权头的请求
    fn build_headers(&self) -> HeaderMap {
        self.headers.clone()
    }

    /// 发送请求并校验 code == 0
    async fn request_api(
        &self,
        method: reqwest::Method,
        path: &str,
        query: &[(&str, &str)],
        body: Option<Value>,
    ) -> Result<Value, DnsProviderError> {
        let clean_path = if path.starts_with('/') {
            path
        } else {
            &format!("/{}", path)
        };
        let url = format!("{}/api{}", self.endpoint, clean_path);

        let mut req = self
            .client
            .request(method, &url)
            .headers(self.build_headers());
        if !query.is_empty() {
            req = req.query(query);
        }
        if let Some(b) = body {
            req = req.json(&b);
        }

        let resp = req.send().await?;
        let status = resp.status();
        let body_text = resp.text().await?;

        if !status.is_success() {
            return Err(DnsProviderError::ApiError {
                code: status.to_string(),
                message: format!("HiPM DNSMgr HTTP 错误: {}", body_text),
            });
        }

        let api_resp: DnsMgrApiResponse = serde_json::from_str(&body_text)?;
        if api_resp.code != 0 {
            return Err(DnsProviderError::ApiError {
                code: api_resp.code.to_string(),
                message: format!("HiPM DNSMgr API 错误: {}", api_resp.msg),
            });
        }

        Ok(api_resp.data.unwrap_or(Value::Null))
    }

    /// 获取 Domain ID（带 TTL 缓存）
    ///
    /// # 性能说明 (P1-9)
    /// 原实现每次调用都重新发起 1 次关键字查询 + 最多 5 次分页查询。配合上层
    /// 「每域名 × 每协议一次调度」的编排，单轮 HTTP 请求放大可达 12~36 倍。
    /// Domain ID 在 TTL 窗口内稳定，缓存后可将该放大降至每轮一次。
    async fn get_domain_id(&self, root_domain: &str) -> Result<i64, DnsProviderError> {
        let cache_key = HipmDomainCacheKey {
            endpoint: self.endpoint.clone(),
            root_domain: root_domain.to_ascii_lowercase(),
        };
        if let Some(cached) = HIPM_DOMAIN_CACHE.get(&cache_key) {
            return Ok(cached);
        }

        // 尝试关键字查询
        let query = [("page", "1"), ("pageSize", "1"), ("keyword", root_domain)];
        let data = self
            .request_api(reqwest::Method::GET, "/domains", &query, None)
            .await?;

        let domains: Vec<DnsMgrDomainItem> = extract_json_list(&data);
        if let Some(matched) = domains
            .into_iter()
            .find(|d| d.name.eq_ignore_ascii_case(root_domain))
        {
            HIPM_DOMAIN_CACHE.insert(cache_key, matched.id);
            return Ok(matched.id);
        }

        // 分页兜底查询
        for page in 1..=5 {
            let p_str = page.to_string();
            let p_query = [("page", p_str.as_str()), ("pageSize", "50")];
            let p_data = self
                .request_api(reqwest::Method::GET, "/domains", &p_query, None)
                .await?;
            let p_domains: Vec<DnsMgrDomainItem> = extract_json_list(&p_data);
            if p_domains.is_empty() {
                break;
            }
            if let Some(matched) = p_domains
                .into_iter()
                .find(|d| d.name.eq_ignore_ascii_case(root_domain))
            {
                HIPM_DOMAIN_CACHE.insert(cache_key, matched.id);
                return Ok(matched.id);
            }
        }

        // 分页达到上限时显式报错 (P1-6)：静默返回 ZoneNotFound 会使上层
        // 误判为域名不存在，从而创建重复记录
        Err(DnsProviderError::ZoneNotFound(root_domain.to_string()))
    }

    /// 查询指定子域名记录
    async fn get_record(
        &self,
        domain_id: i64,
        sub: &str,
        record_type: &str,
    ) -> Result<Option<DnsMgrRecordItem>, DnsProviderError> {
        let path = format!("/domains/{}/records", domain_id);
        let query = [
            ("page", "1"),
            ("pageSize", "100"),
            ("subdomain", sub),
            ("type", record_type),
        ];
        let data = self
            .request_api(reqwest::Method::GET, &path, &query, None)
            .await?;
        let records: Vec<DnsMgrRecordItem> = extract_json_list(&data);

        let matched = records.into_iter().find(|r| {
            r.name.eq_ignore_ascii_case(sub) && r.record_type.eq_ignore_ascii_case(record_type)
        });

        Ok(matched)
    }
}

#[async_trait]
impl RecordOps for HipmDnsMgrProvider {
    fn provider_name(&self) -> &'static str {
        "HiPM DNSMgr"
    }

    async fn resolve_zone(&self, root_domain: &str) -> Result<String, DnsProviderError> {
        let domain_id = self.get_domain_id(root_domain).await?;
        Ok(domain_id.to_string())
    }

    async fn list_records(
        &self,
        zone: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
    ) -> Result<Vec<RemoteRecord>, DnsProviderError> {
        let domain_id: i64 = zone
            .parse()
            .map_err(|e| DnsProviderError::Other(format!("无效的 domain_id: {}", e)))?;
        let sub = domain.sub_domain_or_at();
        let existing = self
            .get_record(domain_id, sub, &record_type.to_string())
            .await?;

        Ok(existing
            .into_iter()
            .map(|record| {
                let record_id_str = match &record.id {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    _ => record.id.to_string(),
                };
                RemoteRecord::new(record_id_str, record.value)
            })
            .collect())
    }

    async fn create_record(
        &self,
        zone: &str,
        params: &RecordParams<'_>,
    ) -> Result<(), DnsProviderError> {
        let domain_id: i64 = zone
            .parse()
            .map_err(|e| DnsProviderError::Other(format!("无效的 domain_id: {}", e)))?;
        let sub = params.domain.sub_domain_or_at();
        let target_ip_str = params.ip.to_string();
        let ttl_val = default_ttl(params.ttl);

        let create_payload = json!({
            "name": sub,
            "type": params.record_type.to_string(),
            "value": target_ip_str,
            "ttl": ttl_val,
            "line": "0"
        });

        let path = format!("/domains/{}/records", domain_id);
        self.request_api(reqwest::Method::POST, &path, &[], Some(create_payload))
            .await?;

        Ok(())
    }

    async fn update_record(
        &self,
        zone: &str,
        record_id: &str,
        params: &RecordParams<'_>,
    ) -> Result<(), DnsProviderError> {
        let domain_id: i64 = zone
            .parse()
            .map_err(|e| DnsProviderError::Other(format!("无效的 domain_id: {}", e)))?;
        let sub = params.domain.sub_domain_or_at();
        let target_ip_str = params.ip.to_string();
        let ttl_val = default_ttl(params.ttl);

        let update_payload = json!({
            "name": sub,
            "type": params.record_type.to_string(),
            "value": target_ip_str,
            "ttl": ttl_val,
            "line": "0"
        });

        let path = format!("/domains/{}/records/{}", domain_id, record_id);
        self.request_api(reqwest::Method::PUT, &path, &[], Some(update_payload))
            .await?;

        Ok(())
    }

    async fn delete_record(
        &self,
        zone: &str,
        record: &RemoteRecord,
        _params: &RecordParams<'_>,
    ) -> Result<(), DnsProviderError> {
        let domain_id: i64 = zone
            .parse()
            .map_err(|e| DnsProviderError::Other(format!("无效的 domain_id: {}", e)))?;
        let path = format!("/domains/{}/records/{}", domain_id, record.id);
        self.request_api(reqwest::Method::DELETE, &path, &[], None)
            .await?;
        Ok(())
    }
}

/// 从 JSON 中提取泛型实体列表 (兼容顶层数组与包裹在 list 字段中的分页对象)
fn extract_json_list<T: serde::de::DeserializeOwned>(val: &Value) -> Vec<T> {
    if let Some(arr) = val.as_array() {
        serde_json::from_value(Value::Array(arr.clone())).unwrap_or_default()
    } else if let Some(obj) = val.as_object() {
        if let Some(list) = obj.get("list").and_then(|l| l.as_array()) {
            serde_json::from_value(Value::Array(list.clone())).unwrap_or_default()
        } else {
            vec![]
        }
    } else {
        vec![]
    }
}
