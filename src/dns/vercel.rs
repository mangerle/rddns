use crate::core::domain::ParsedDomain;
use crate::dns::ops::{RecordOps, RecordParams, RemoteRecord};
use crate::dns::trait_def::{DnsProviderError, DnsRecordType, MIN_DNS_TTL, clamp_ttl};
use crate::util::http::{create_default_dns_client, url_encode};
use async_trait::async_trait;
use reqwest::Client;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::Deserialize;
use serde_json::json;

/// Vercel API 基础服务地址
const VERCEL_API_BASE: &str = "https://api.vercel.com";

/// Vercel DNS 提供商
pub struct VercelProvider {
    token: String,
    team_id: Option<String>,
    client: Client,
}

#[derive(Debug, Deserialize)]
struct VercelRecord {
    id: String,
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct VercelPagination {
    next: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct VercelRecordsResp {
    records: Option<Vec<VercelRecord>>,
    pagination: Option<VercelPagination>,
}

#[derive(Debug, Deserialize)]
struct VercelApiErrorDetail {
    code: Option<String>,
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VercelErrorEnvelope {
    error: Option<VercelApiErrorDetail>,
}

/// 统一校验 Vercel API 响应，杜绝 HTTP 200 + {"error": ...} 静默误判成功
fn check_vercel_error(
    body_text: &str,
    status: reqwest::StatusCode,
) -> Result<(), DnsProviderError> {
    if let Ok(env) = serde_json::from_str::<VercelErrorEnvelope>(body_text)
        && let Some(err) = env.error
    {
        return Err(DnsProviderError::ApiError {
            code: err.code.unwrap_or_else(|| status.to_string()),
            message: format!(
                "Vercel API 业务失败: {}",
                err.message.unwrap_or_else(|| body_text.to_string())
            ),
        });
    }

    if !status.is_success() {
        return Err(DnsProviderError::ApiError {
            code: status.to_string(),
            message: format!("Vercel API 请求失败: {}", body_text),
        });
    }

    Ok(())
}

/// 根据当前页响应推进或清空分页游标
fn resolve_next_cursor(
    pagination: Option<&VercelPagination>,
    page_len: usize,
    page_size: usize,
) -> Option<u64> {
    if page_len >= page_size
        && let Some(pag) = pagination
    {
        pag.next
    } else {
        None
    }
}

impl VercelProvider {
    pub fn new(token: String, team_id: Option<String>, http_interface: Option<&str>) -> Self {
        Self {
            token,
            team_id: team_id.filter(|t| !t.trim().is_empty()),
            client: create_default_dns_client(http_interface),
        }
    }

    fn build_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::with_capacity(2);
        if let Ok(mut hv) = HeaderValue::from_str(&format!("Bearer {}", self.token)) {
            hv.set_sensitive(true);
            headers.insert(AUTHORIZATION, hv);
        }
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers
    }

    fn append_team_id(&self, base_url: &str) -> String {
        if let Some(ref tid) = self.team_id {
            let encoded_tid = url_encode(tid);
            if base_url.contains('?') {
                format!("{}&teamId={}", base_url, encoded_tid)
            } else {
                format!("{}?teamId={}", base_url, encoded_tid)
            }
        } else {
            base_url.to_string()
        }
    }
}

#[async_trait]
impl RecordOps for VercelProvider {
    fn provider_name(&self) -> &'static str {
        "Vercel DNS"
    }

    async fn list_records(
        &self,
        _zone: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
    ) -> Result<Vec<RemoteRecord>, DnsProviderError> {
        // 单页条数与最大翻页数：Vercel records API 的 limit 上限为 100
        const PAGE_SIZE: usize = 100;
        const MAX_PAGES: usize = 10;

        let mut all_records = Vec::with_capacity(PAGE_SIZE);
        let mut next_cursor: Option<u64> = None;

        for _ in 0..MAX_PAGES {
            let base_url = format!(
                "{}/v4/domains/{}/records?limit={}{}",
                VERCEL_API_BASE,
                url_encode(&domain.root_domain),
                PAGE_SIZE,
                next_cursor
                    .map(|c| format!("&until={}", c))
                    .unwrap_or_default()
            );
            let list_url = self.append_team_id(&base_url);

            let list_resp = self
                .client
                .get(&list_url)
                .headers(self.build_headers())
                .send()
                .await?;

            let status = list_resp.status();
            let body_text = list_resp.text().await?;
            check_vercel_error(&body_text, status)?;

            let parsed: VercelRecordsResp = serde_json::from_str(&body_text)?;
            let records = parsed.records.unwrap_or_default();
            let page_len = records.len();
            all_records.extend(records);

            next_cursor = resolve_next_cursor(parsed.pagination.as_ref(), page_len, PAGE_SIZE);
            if next_cursor.is_none() {
                // 已拉取到最后一页，正常结束
                break;
            }
        }

        // 达到翻页上限仍有后续数据时必须显式报错 (P1-6)：
        // 静默返回不完整列表会使目标域名记录「查不到」，进而被模板
        // 误判为记录不存在并创建重复记录，破坏 DNS 解析。
        if next_cursor.is_some() {
            return Err(DnsProviderError::Other(format!(
                "Vercel 记录查询翻页达到 {} 页上限后仍有剩余数据，为避免误创建重复记录已中止本次同步，请减少单域名记录数或改用支持名称过滤的服务商接口",
                MAX_PAGES
            )));
        }

        let matched = all_records
            .into_iter()
            .filter(|r| {
                r.record_type.eq_ignore_ascii_case(&record_type.to_string())
                    && domain.matches_record_name(&r.name)
            })
            .map(|r| RemoteRecord::new(r.id, r.value))
            .collect();

        Ok(matched)
    }

    async fn create_record(
        &self,
        _zone: &str,
        params: &RecordParams<'_>,
    ) -> Result<(), DnsProviderError> {
        let ttl_val = clamp_ttl(params.ttl, MIN_DNS_TTL, MIN_DNS_TTL);
        let sub_name = if params.domain.sub_domain.is_empty() || params.domain.sub_domain == "@" {
            ""
        } else {
            &params.domain.sub_domain
        };

        let create_url = self.append_team_id(&format!(
            "{}/v2/domains/{}/records",
            VERCEL_API_BASE,
            url_encode(&params.domain.root_domain)
        ));

        let create_payload = json!({
            "name": sub_name,
            "type": params.record_type.to_string(),
            "value": params.ip.to_string(),
            "ttl": ttl_val,
            "comment": "Created by rddns"
        });

        let post_resp = self
            .client
            .post(&create_url)
            .headers(self.build_headers())
            .json(&create_payload)
            .send()
            .await?;

        let post_status = post_resp.status();
        let body_text = post_resp.text().await?;
        check_vercel_error(&body_text, post_status)?;
        Ok(())
    }

    async fn update_record(
        &self,
        _zone: &str,
        record_id: &str,
        params: &RecordParams<'_>,
    ) -> Result<(), DnsProviderError> {
        let ttl_val = clamp_ttl(params.ttl, MIN_DNS_TTL, MIN_DNS_TTL);
        let update_url = self.append_team_id(&format!(
            "{}/v1/domains/records/{}",
            VERCEL_API_BASE,
            url_encode(record_id)
        ));

        let update_payload = json!({
            "type": params.record_type.to_string(),
            "value": params.ip.to_string(),
            "ttl": ttl_val
        });

        let patch_resp = self
            .client
            .patch(&update_url)
            .headers(self.build_headers())
            .json(&update_payload)
            .send()
            .await?;

        let patch_status = patch_resp.status();
        let body_text = patch_resp.text().await?;
        check_vercel_error(&body_text, patch_status)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_next_cursor_clears_on_final_partial_page() {
        // 第 1 页满 100 条且带有 next 游标：应返回 Some(next)
        let page1_pag = VercelPagination { next: Some(123456) };
        let mut cursor = resolve_next_cursor(Some(&page1_pag), 100, 100);
        assert_eq!(cursor, Some(123456));

        // 第 2 页仅 20 条（最后一页），即使服务端或旧状态带有 next，游标也必须清零为 None，
        // 避免循环退出后误判“翻页达到 10 页上限”
        let page2_pag = VercelPagination { next: Some(789012) };
        cursor = resolve_next_cursor(Some(&page2_pag), 20, 100);
        assert!(
            cursor.is_none(),
            "最后一页不满 PAGE_SIZE 时必须将游标置为 None"
        );
    }
}
