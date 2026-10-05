use crate::core::domain::ParsedDomain;
use crate::dns::ops::{RecordOps, RemoteRecord, sync_record_via};
use crate::dns::trait_def::{DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult};
use crate::util::http::url_encode;
use async_trait::async_trait;
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

const NSONE_API_ENDPOINT: &str = "https://api.nsone.net/v1/zones";

/// IBM NS1 Connect DNS 提供商
pub struct NsOneProvider {
    client: Client,
    /// 逐请求携带的鉴权头（含敏感凭据，禁止写入日志）
    headers: HeaderMap,
}

#[derive(Debug, Deserialize)]
struct NsOneZone {
    #[serde(rename = "name")]
    _name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct NsOneAnswer {
    answer: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct NsOneRecordResp {
    answers: Option<Vec<NsOneAnswer>>,
}

#[derive(Debug, Deserialize)]
struct NsOneErrorResp {
    message: Option<String>,
}

fn check_nsone_error(
    body_text: &str,
    status: StatusCode,
    action: &str,
) -> Result<(), DnsProviderError> {
    if let Ok(err) = serde_json::from_str::<NsOneErrorResp>(body_text)
        && let Some(msg) = err.message
    {
        return Err(DnsProviderError::ApiError {
            code: status.to_string(),
            message: format!("NS1 {}业务失败: {}", action, msg),
        });
    }

    if !status.is_success() {
        return Err(DnsProviderError::ApiError {
            code: status.to_string(),
            message: format!("NS1 {}: {}", action, body_text),
        });
    }

    Ok(())
}

#[derive(Debug, Serialize)]
struct NsOneRecordReq<'a> {
    zone: &'a str,
    domain: &'a str,
    #[serde(rename = "type")]
    record_type: &'a str,
    ttl: u32,
    answers: Vec<NsOneAnswer>,
}

impl NsOneProvider {
    pub fn new(api_key: String, http_interface: Option<&str>) -> Result<Self, DnsProviderError> {
        if api_key.trim().is_empty() {
            return Err(DnsProviderError::MissingCredentials(
                "IBM NS1 Connect 需要配置 API Key (Secret)".to_string(),
            ));
        }

        // 凭据不固化进 Client，而是逐请求通过请求头携带，
        // 以便 HTTP Client 可安全地放入全局连接池缓存跨任务复用
        let mut auth_val = HeaderValue::from_str(api_key.trim()).map_err(|e| {
            DnsProviderError::MissingCredentials(format!("无效的 NS1 API Key: {}", e))
        })?;
        auth_val.set_sensitive(true);

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert("X-NSONE-Key", auth_val);

        // 复用全局连接池缓存，避免每轮同步重复进行 TCP/TLS 握手
        let client = crate::util::http::create_default_dns_client(http_interface);

        Ok(Self { client, headers })
    }

    /// 构造携带鉴权头的请求
    fn build_headers(&self) -> HeaderMap {
        self.headers.clone()
    }

    /// 检查 Zone 是否存在
    async fn check_zone(&self, root_domain: &str) -> Result<(), DnsProviderError> {
        let url = format!("{}/{}?records=false", NSONE_API_ENDPOINT, root_domain);
        let resp = self
            .client
            .get(&url)
            .headers(self.build_headers())
            .send()
            .await?;

        let status = resp.status();
        if status == StatusCode::NOT_FOUND {
            return Err(DnsProviderError::ZoneNotFound(format!(
                "在 IBM NS1 Connect 中未找到根域名 [{}]",
                root_domain
            )));
        }

        let body = resp.text().await?;
        check_nsone_error(&body, status, "查询 Zone 失败")?;

        let _zone: NsOneZone = serde_json::from_str(&body)?;
        Ok(())
    }

    /// 获取已有记录
    async fn get_record(
        &self,
        root_domain: &str,
        full_domain: &str,
        record_type: &str,
    ) -> Result<Option<NsOneRecordResp>, DnsProviderError> {
        let url = format!(
            "{}/{}/{}/{}?records=false",
            NSONE_API_ENDPOINT, root_domain, full_domain, record_type
        );
        let resp = self
            .client
            .get(&url)
            .headers(self.build_headers())
            .send()
            .await?;

        let status = resp.status();
        if status == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        let body = resp.text().await?;
        check_nsone_error(&body, status, "查询记录失败")?;

        let parsed: NsOneRecordResp = serde_json::from_str(&body)?;
        Ok(Some(parsed))
    }
}

#[async_trait]
impl RecordOps for NsOneProvider {
    fn provider_name(&self) -> &'static str {
        "IBM NS1 Connect"
    }

    async fn resolve_zone(&self, root_domain: &str) -> Result<String, DnsProviderError> {
        self.check_zone(root_domain).await?;
        Ok(root_domain.to_string())
    }

    async fn list_records(
        &self,
        zone: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
    ) -> Result<Vec<RemoteRecord>, DnsProviderError> {
        let full_domain = domain.full_domain();
        let existing = self
            .get_record(zone, &full_domain, &record_type.to_string())
            .await?;

        let mut remotes = Vec::new();
        if let Some(record) = existing {
            let current_ip = record
                .answers
                .as_ref()
                .and_then(|ans| ans.first())
                .and_then(|a| a.answer.first());
            if let Some(ip_str) = current_ip {
                // NS1 API 以完整的 FQDN (/{zone}/{domain}/{type}) 作为记录唯一主键，
                // 不存在独立分配的数字 record_id，因此传递 full_domain 作为定位标识 (P2-19)。
                remotes.push(RemoteRecord::new(full_domain, ip_str));
            }
        }
        Ok(remotes)
    }

    async fn create_record(
        &self,
        zone: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
        ip: &IpAddr,
        ttl: Option<u32>,
    ) -> Result<(), DnsProviderError> {
        let full_domain = domain.full_domain();
        let ttl_val = ttl.unwrap_or(60).max(1);
        let answers = vec![NsOneAnswer {
            answer: vec![ip.to_string()],
        }];

        let req_payload = NsOneRecordReq {
            zone,
            domain: &full_domain,
            record_type: &record_type.to_string(),
            ttl: ttl_val,
            answers,
        };

        let url = format!(
            "{}/{}/{}/{}",
            NSONE_API_ENDPOINT,
            url_encode(zone),
            url_encode(&full_domain),
            record_type
        );

        let resp = self
            .client
            .put(&url)
            .headers(self.build_headers())
            .json(&req_payload)
            .send()
            .await?;
        let status = resp.status();
        let body = resp.text().await?;
        check_nsone_error(&body, status, "创建记录失败")?;
        Ok(())
    }

    async fn update_record(
        &self,
        zone: &str,
        _record_id: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
        ip: &IpAddr,
        ttl: Option<u32>,
    ) -> Result<(), DnsProviderError> {
        let full_domain = domain.full_domain();
        let ttl_val = ttl.unwrap_or(60).max(1);
        let answers = vec![NsOneAnswer {
            answer: vec![ip.to_string()],
        }];

        let req_payload = NsOneRecordReq {
            zone,
            domain: &full_domain,
            record_type: &record_type.to_string(),
            ttl: ttl_val,
            answers,
        };

        let url = format!(
            "{}/{}/{}/{}",
            NSONE_API_ENDPOINT, zone, full_domain, record_type
        );

        let resp = self
            .client
            .post(&url)
            .headers(self.build_headers())
            .json(&req_payload)
            .send()
            .await?;
        let status = resp.status();
        let body = resp.text().await?;

        check_nsone_error(&body, status, "更新记录失败")?;
        Ok(())
    }
}

#[async_trait]
impl DnsProvider for NsOneProvider {
    fn provider_name(&self) -> &'static str {
        <Self as RecordOps>::provider_name(self)
    }

    async fn sync_record(
        &self,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
        ip: &IpAddr,
        ttl: Option<u32>,
    ) -> Result<SyncRecordResult, DnsProviderError> {
        sync_record_via(self, domain, record_type, ip, ttl).await
    }
}
