use crate::core::domain::ParsedDomain;
use crate::dns::trait_def::{
    DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult, SyncStatus,
};
use async_trait::async_trait;
use log::info;
use reqwest::Client;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::Deserialize;
use serde_json::{Value, json};
use std::net::IpAddr;
use std::time::Duration;

pub const DEFAULT_HIPM_ENDPOINT: &str = "https://dnsmgr.example.com";

/// HiPM DNSMgr 驱动提供商
pub struct HipmDnsMgrProvider {
    client: Client,
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

        let base = endpoint
            .filter(|e| !e.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_HIPM_ENDPOINT.to_string());
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

        let client = crate::util::http::create_task_http_client_builder(http_interface)
            .timeout(Duration::from_secs(15))
            .default_headers(headers)
            .build()?;

        Ok(Self {
            client,
            endpoint: trimmed_base,
        })
    }

    /// 发送请求并校验 code == 0
    async fn request_api(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, DnsProviderError> {
        let clean_path = if path.starts_with('/') {
            path
        } else {
            &format!("/{}", path)
        };
        let url = format!("{}/api{}", self.endpoint, clean_path);

        let mut req = self.client.request(method, &url);
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

    /// 获取 Domain ID
    async fn get_domain_id(&self, root_domain: &str) -> Result<i64, DnsProviderError> {
        // 尝试关键字查询
        let path = format!("/domains?page=1&pageSize=1&keyword={}", root_domain);
        let data = self.request_api(reqwest::Method::GET, &path, None).await?;

        let domains: Vec<DnsMgrDomainItem> = extract_json_list(&data);
        if let Some(matched) = domains
            .into_iter()
            .find(|d| d.name.eq_ignore_ascii_case(root_domain))
        {
            return Ok(matched.id);
        }

        // 分页兜底查询
        for page in 1..=5 {
            let p_path = format!("/domains?page={}&pageSize=50", page);
            let p_data = self
                .request_api(reqwest::Method::GET, &p_path, None)
                .await?;
            let p_domains: Vec<DnsMgrDomainItem> = extract_json_list(&p_data);
            if p_domains.is_empty() {
                break;
            }
            if let Some(matched) = p_domains
                .into_iter()
                .find(|d| d.name.eq_ignore_ascii_case(root_domain))
            {
                return Ok(matched.id);
            }
        }

        Err(DnsProviderError::ZoneNotFound(format!(
            "在 HiPM DNSMgr 中未找到根域名 [{}] 对应的域名 ID",
            root_domain
        )))
    }

    /// 查询指定子域名记录
    async fn get_record(
        &self,
        domain_id: i64,
        sub: &str,
        record_type: &str,
    ) -> Result<Option<DnsMgrRecordItem>, DnsProviderError> {
        let path = format!(
            "/domains/{}/records?page=1&pageSize=100&subdomain={}&type={}",
            domain_id, sub, record_type
        );
        let data = self.request_api(reqwest::Method::GET, &path, None).await?;
        let records: Vec<DnsMgrRecordItem> = extract_json_list(&data);

        let matched = records.into_iter().find(|r| {
            r.name.eq_ignore_ascii_case(sub) && r.record_type.eq_ignore_ascii_case(record_type)
        });

        Ok(matched)
    }
}

#[async_trait]
impl DnsProvider for HipmDnsMgrProvider {
    fn provider_name(&self) -> &'static str {
        "HiPM DNSMgr"
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
        let ttl_val = ttl.unwrap_or(600).max(1);
        let sub = domain.sub_domain_or_at();

        // 1. 获取 Domain ID
        let domain_id = self.get_domain_id(&domain.root_domain).await?;

        // 2. 查询已有记录
        let existing = self
            .get_record(domain_id, sub, &record_type.to_string())
            .await?;

        if let Some(record) = existing {
            if record.value == target_ip_str {
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

            let record_id_str = match &record.id {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                _ => record.id.to_string(),
            };

            // 更新记录 (PUT)
            let update_payload = json!({
                "name": sub,
                "type": record_type.to_string(),
                "value": target_ip_str,
                "ttl": ttl_val,
                "line": "0"
            });

            let path = format!("/domains/{}/records/{}", domain_id, record_id_str);
            self.request_api(reqwest::Method::PUT, &path, Some(update_payload))
                .await?;

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
            // 创建记录 (POST)
            let create_payload = json!({
                "name": sub,
                "type": record_type.to_string(),
                "value": target_ip_str,
                "ttl": ttl_val,
                "line": "0"
            });

            let path = format!("/domains/{}/records", domain_id);
            self.request_api(reqwest::Method::POST, &path, Some(create_payload))
                .await?;

            info!(
                "[{}] 成功创建域名解析 {} -> {}",
                self.provider_name(),
                full_domain,
                target_ip_str
            );
            Ok(SyncRecordResult {
                domain: full_domain,
                record_type,
                target_ip: target_ip_str,
                status: SyncStatus::Created,
                message: "解析记录创建成功".to_string(),
            })
        }
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
