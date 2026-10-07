use crate::core::domain::ParsedDomain;
use crate::dns::ops::{RecordOps, RecordParams, RemoteRecord};
use crate::dns::trait_def::{DEFAULT_DNS_TTL, DnsProviderError, DnsRecordType};
use crate::util::http::url_encode;
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;

const PORKBUN_ENDPOINT: &str = "https://api.porkbun.com/api/json/v3/dns";

/// Porkbun DNS 提供商
pub struct PorkbunProvider {
    api_key: String,
    secret_key: String,
    client: Client,
}

#[derive(Debug, Deserialize)]
struct PorkbunRecord {
    id: Option<String>,
    content: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PorkbunQueryResponse {
    status: String,
    message: Option<String>,
    records: Option<Vec<PorkbunRecord>>,
}

#[derive(Debug, Deserialize)]
struct PorkbunBaseResponse {
    status: String,
    message: Option<String>,
}

impl PorkbunProvider {
    pub fn new(api_key: String, secret_key: String, http_interface: Option<&str>) -> Self {
        Self {
            api_key,
            secret_key,
            client: crate::util::http::create_default_dns_client(http_interface),
        }
    }

    fn auth_payload(&self) -> serde_json::Value {
        json!({
            "apikey": self.api_key,
            "secretapikey": self.secret_key,
        })
    }

    /// 计算并规范化 TTL（Porkbun 官方限制最低 TTL 为 600 秒）
    ///
    /// # 设计原理
    /// - **实现初衷**: Porkbun API 强制要求 DNS 记录 TTL 必须 >= 600 秒，否则直接报错拒绝。
    /// - **核心优势**: 当用户配置的 TTL 低于 600 秒时，输出清晰提示日志并自动平滑调整，杜绝静默改动导致用户疑惑 (P2-18)。
    fn resolve_ttl(ttl: Option<u32>) -> String {
        const PORKBUN_MIN_TTL: u32 = DEFAULT_DNS_TTL;
        let configured = ttl.unwrap_or(PORKBUN_MIN_TTL);
        if configured < PORKBUN_MIN_TTL {
            log::debug!(
                "[Porkbun] 用户配置的 TTL ({} 秒) 低于服务商官方最低限制 (600 秒)，已自动修正为 600 秒",
                configured
            );
            PORKBUN_MIN_TTL.to_string()
        } else {
            configured.to_string()
        }
    }
}

#[async_trait]
impl RecordOps for PorkbunProvider {
    fn provider_name(&self) -> &'static str {
        "Porkbun"
    }

    async fn list_records(
        &self,
        _zone: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
    ) -> Result<Vec<RemoteRecord>, DnsProviderError> {
        let is_root = domain.sub_domain.is_empty() || domain.sub_domain == "@";
        let sub_domain_param = if is_root { "" } else { &domain.sub_domain };

        let query_url = if sub_domain_param.is_empty() {
            format!(
                "{}/retrieveByNameType/{}/{}",
                PORKBUN_ENDPOINT,
                url_encode(&domain.root_domain),
                record_type
            )
        } else {
            format!(
                "{}/retrieveByNameType/{}/{}/{}",
                PORKBUN_ENDPOINT,
                url_encode(&domain.root_domain),
                record_type,
                url_encode(sub_domain_param)
            )
        };

        let query_resp = self
            .client
            .post(&query_url)
            .json(&self.auth_payload())
            .send()
            .await?;

        let query_status = query_resp.status();
        let query_text = query_resp.text().await?;
        if !query_status.is_success() {
            return Err(DnsProviderError::http_status(query_status, &query_text));
        }

        let query_result: PorkbunQueryResponse = serde_json::from_str(&query_text)?;
        if !query_result.status.eq_ignore_ascii_case("SUCCESS") {
            let msg = query_result
                .message
                .unwrap_or_else(|| "查询 Porkbun 解析记录失败".to_string());
            return Err(DnsProviderError::ApiError {
                code: query_result.status,
                message: msg,
            });
        }

        let existing_records = query_result.records.unwrap_or_default();
        let mut remotes = Vec::with_capacity(existing_records.len());
        for rec in existing_records {
            if let Some(content) = rec.content {
                let rec_id = rec.id.as_deref().unwrap_or("porkbun_record");
                remotes.push(RemoteRecord::new(rec_id, content));
            }
        }
        Ok(remotes)
    }

    async fn create_record(
        &self,
        _zone: &str,
        params: &RecordParams<'_>,
    ) -> Result<(), DnsProviderError> {
        let ttl_val = Self::resolve_ttl(params.ttl);
        let is_root = params.domain.sub_domain.is_empty() || params.domain.sub_domain == "@";
        let sub_domain_param = if is_root {
            ""
        } else {
            &params.domain.sub_domain
        };

        let create_url = format!(
            "{}/create/{}",
            PORKBUN_ENDPOINT,
            url_encode(&params.domain.root_domain)
        );
        let mut create_payload = self.auth_payload();
        create_payload["name"] = json!(sub_domain_param);
        create_payload["type"] = json!(params.record_type.to_string());
        create_payload["content"] = json!(params.ip.to_string());
        create_payload["ttl"] = json!(ttl_val);

        let create_resp = self
            .client
            .post(&create_url)
            .json(&create_payload)
            .send()
            .await?;

        let create_status = create_resp.status();
        let create_text = create_resp.text().await?;
        if !create_status.is_success() {
            return Err(DnsProviderError::http_status(create_status, &create_text));
        }

        let create_result: PorkbunBaseResponse = serde_json::from_str(&create_text)?;
        if create_result.status.eq_ignore_ascii_case("SUCCESS") {
            Ok(())
        } else {
            Err(DnsProviderError::ApiError {
                code: create_result.status,
                message: create_result
                    .message
                    .unwrap_or_else(|| "新增 Porkbun 记录失败".to_string()),
            })
        }
    }

    async fn update_record(
        &self,
        _zone: &str,
        _record_id: &str,
        params: &RecordParams<'_>,
    ) -> Result<(), DnsProviderError> {
        let ttl_val = Self::resolve_ttl(params.ttl);
        let is_root = params.domain.sub_domain.is_empty() || params.domain.sub_domain == "@";
        let sub_domain_param = if is_root {
            ""
        } else {
            &params.domain.sub_domain
        };

        let edit_url = if sub_domain_param.is_empty() {
            format!(
                "{}/editByNameType/{}/{}",
                PORKBUN_ENDPOINT,
                url_encode(&params.domain.root_domain),
                params.record_type
            )
        } else {
            format!(
                "{}/editByNameType/{}/{}/{}",
                PORKBUN_ENDPOINT,
                url_encode(&params.domain.root_domain),
                params.record_type,
                url_encode(sub_domain_param)
            )
        };

        let mut edit_payload = self.auth_payload();
        edit_payload["content"] = json!(params.ip.to_string());
        edit_payload["ttl"] = json!(ttl_val);

        let edit_resp = self
            .client
            .post(&edit_url)
            .json(&edit_payload)
            .send()
            .await?;

        let edit_status = edit_resp.status();
        let edit_text = edit_resp.text().await?;
        if !edit_status.is_success() {
            return Err(DnsProviderError::http_status(edit_status, &edit_text));
        }

        let edit_result: PorkbunBaseResponse = serde_json::from_str(&edit_text)?;
        if edit_result.status.eq_ignore_ascii_case("SUCCESS") {
            Ok(())
        } else {
            Err(DnsProviderError::ApiError {
                code: edit_result.status,
                message: edit_result
                    .message
                    .unwrap_or_else(|| "更新 Porkbun 记录失败".to_string()),
            })
        }
    }
}
