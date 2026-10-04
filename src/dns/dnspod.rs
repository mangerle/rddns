use crate::core::domain::ParsedDomain;
use crate::dns::ops::{RecordOps, RemoteRecord, sync_record_via};
use crate::dns::tencentcloud::{Tc3ApiEndpoint, Tc3Client};
use crate::dns::trait_def::{DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;
use std::net::IpAddr;

const DNSPOD_ENDPOINT: Tc3ApiEndpoint = Tc3ApiEndpoint {
    host: "dnspod.tencentcloudapi.com",
    service: "dnspod",
    version: "2021-03-23",
};

pub struct TencentCloudProvider {
    tc3: Tc3Client,
}

impl TencentCloudProvider {
    pub fn new(
        secret_id: String,
        secret_key: String,
        http_interface: Option<&str>,
    ) -> Result<Self, DnsProviderError> {
        if secret_id.trim().is_empty() || secret_key.trim().is_empty() {
            return Err(DnsProviderError::MissingCredentials(
                "腾讯云 DNSPod 需要配置 SecretId 与 SecretKey".to_string(),
            ));
        }

        // 复用全局连接池缓存，避免每轮同步重复进行 TCP/TLS 握手
        let client = crate::util::http::create_default_dns_client(http_interface);

        Ok(Self {
            tc3: Tc3Client::new(client, secret_id, secret_key, DNSPOD_ENDPOINT),
        })
    }

    /// 获取域名自定义参数中指定的解析线路
    fn resolve_line(domain: &ParsedDomain) -> &str {
        domain
            .custom_params
            .get("line")
            .or_else(|| domain.custom_params.get("Line"))
            .map(|s| s.as_str())
            .unwrap_or("默认")
    }
}

#[async_trait]
impl RecordOps for TencentCloudProvider {
    fn provider_name(&self) -> &'static str {
        "腾讯云 (DNSPod)"
    }

    /// 查询现有解析记录列表 (单页最大 100 条)
    async fn list_records(
        &self,
        zone: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
    ) -> Result<Vec<RemoteRecord>, DnsProviderError> {
        let sub_domain = domain.sub_domain_or_at();
        let record_line = Self::resolve_line(domain);

        let list_payload = json!({
            "Domain": zone,
            "Subdomain": sub_domain,
            "RecordType": record_type.to_string(),
            "Limit": 100,
        });

        let list_res: Result<TcRecordListResponse, DnsProviderError> = self
            .tc3
            .request_api("DescribeRecordList", list_payload)
            .await;

        let records = match list_res {
            Ok(data) => data.record_list.unwrap_or_default(),
            Err(DnsProviderError::ApiError { ref code, .. })
                if code == "ResourceNotFound.NoDataOfRecord"
                    || code == "ResourceNotFound.NoDataOfDomain" =>
            {
                // 腾讯云 DNSPod 在没有查到记录时会返回 ResourceNotFound 错误码，此处应视为空记录列表
                Vec::new()
            }
            Err(e) => return Err(e),
        };

        let matched = records
            .into_iter()
            .filter(|r| {
                let name_match = r.name.eq_ignore_ascii_case(sub_domain);
                let type_match = r.record_type.eq_ignore_ascii_case(&record_type.to_string());
                let line_match = if let Some(ref l) = r.line {
                    l.eq_ignore_ascii_case(record_line)
                } else {
                    true
                };
                name_match && type_match && line_match
            })
            .map(|r| RemoteRecord::new(r.record_id.to_string(), r.value))
            .collect();

        Ok(matched)
    }

    /// 新增解析记录
    async fn create_record(
        &self,
        zone: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
        ip: &IpAddr,
        ttl: Option<u32>,
    ) -> Result<(), DnsProviderError> {
        let sub_domain = domain.sub_domain_or_at();
        let record_line = Self::resolve_line(domain);
        let ttl_val = ttl.unwrap_or(600).max(1);

        let create_payload = json!({
            "Domain": zone,
            "SubDomain": sub_domain,
            "RecordType": record_type.to_string(),
            "RecordLine": record_line,
            "Value": ip.to_string(),
            "TTL": ttl_val,
        });

        let _: serde_json::Value = self.tc3.request_api("CreateRecord", create_payload).await?;
        Ok(())
    }

    /// 更新既有解析记录
    async fn update_record(
        &self,
        zone: &str,
        record_id: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
        ip: &IpAddr,
        ttl: Option<u32>,
    ) -> Result<(), DnsProviderError> {
        let sub_domain = domain.sub_domain_or_at();
        let record_line = Self::resolve_line(domain);
        let ttl_val = ttl.unwrap_or(600).max(1);
        let record_id_num = record_id.parse::<u64>().map_err(|e| {
            DnsProviderError::api(
                "InvalidRecordId",
                format!("无效的记录 ID: {record_id}, 错误: {e}"),
            )
        })?;

        let modify_payload = json!({
            "Domain": zone,
            "RecordId": record_id_num,
            "SubDomain": sub_domain,
            "RecordType": record_type.to_string(),
            "RecordLine": record_line,
            "Value": ip.to_string(),
            "TTL": ttl_val,
        });

        let _: serde_json::Value = self.tc3.request_api("ModifyRecord", modify_payload).await?;
        Ok(())
    }
}

#[async_trait]
impl DnsProvider for TencentCloudProvider {
    fn provider_name(&self) -> &'static str {
        "腾讯云 (DNSPod)"
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

#[derive(Debug, Deserialize)]
struct TcRecordListResponse {
    #[serde(rename = "RecordList")]
    record_list: Option<Vec<TcRecordItem>>,
}

#[derive(Debug, Deserialize)]
struct TcRecordItem {
    #[serde(rename = "RecordId")]
    record_id: u64,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Type")]
    record_type: String,
    #[serde(rename = "Value")]
    value: String,
    #[serde(rename = "Line")]
    line: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_dnspod_record_list_deserialization() {
        let sample_json = r#"{
            "RecordList": [
                {
                    "RecordId": 123456789,
                    "Name": "www",
                    "Type": "A",
                    "Value": "1.2.3.4",
                    "Line": "默认"
                }
            ]
        }"#;

        let parsed: TcRecordListResponse =
            serde_json::from_str(sample_json).expect("解析腾讯云 DNSPod 记录响应失败");
        let list = parsed.record_list.expect("缺失 RecordList");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].record_id, 123456789);
        assert_eq!(list[0].name, "www");
        assert_eq!(list[0].record_type, "A");
        assert_eq!(list[0].value, "1.2.3.4");
        assert_eq!(list[0].line.as_deref(), Some("默认"));
    }

    #[test]
    fn test_resolve_line_custom_params() {
        let mut domain = ParsedDomain {
            raw: "home.example.com".to_string(),
            root_domain: "example.com".to_string(),
            sub_domain: "home".to_string(),
            custom_params: HashMap::new(),
        };

        // 默认情况回退为 默认
        assert_eq!(TencentCloudProvider::resolve_line(&domain), "默认");

        // 小写 line 参数
        domain
            .custom_params
            .insert("line".to_string(), "电信".to_string());
        assert_eq!(TencentCloudProvider::resolve_line(&domain), "电信");

        // 大写 Line 参数
        domain.custom_params.remove("line");
        domain
            .custom_params
            .insert("Line".to_string(), "联通".to_string());
        assert_eq!(TencentCloudProvider::resolve_line(&domain), "联通");
    }
}
