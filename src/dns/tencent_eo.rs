use crate::core::domain::ParsedDomain;
use crate::dns::trait_def::{
    DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult, SyncStatus,
};
use crate::util::crypto::{hmac_sha256, sha256_hex};
use async_trait::async_trait;
use chrono::Utc;
use log::info;
use reqwest::Client;
use reqwest::header::{CONTENT_TYPE, HOST, HeaderMap, HeaderValue};
use serde::Deserialize;
use serde_json::json;
use std::net::IpAddr;
use std::time::Duration;

const TEO_ENDPOINT: &str = "https://teo.tencentcloudapi.com";
const TEO_HOST: &str = "teo.tencentcloudapi.com";
const TEO_SERVICE: &str = "teo";
const TEO_VERSION: &str = "2022-09-01";

/// 腾讯云 EdgeOne (TEO) 提供商
pub struct TencentEoProvider {
    client: Client,
    secret_id: String,
    secret_key: String,
}

#[derive(Debug, Deserialize)]
struct TeoError {
    #[serde(rename = "Code")]
    code: String,
    #[serde(rename = "Message")]
    message: String,
}

#[derive(Debug, Deserialize)]
struct TeoZoneItem {
    #[serde(rename = "ZoneId")]
    zone_id: String,
    #[serde(rename = "ZoneName")]
    zone_name: String,
}

#[derive(Debug, Deserialize)]
struct TeoZoneRespData {
    #[serde(rename = "Zones")]
    zones: Option<Vec<TeoZoneItem>>,
    #[serde(rename = "Error")]
    error: Option<TeoError>,
}

#[derive(Debug, Deserialize)]
struct TeoZoneResp {
    #[serde(rename = "Response")]
    response: TeoZoneRespData,
}

#[derive(Debug, Deserialize)]
struct TeoRecordItem {
    #[serde(rename = "RecordId")]
    record_id: Option<String>,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Type")]
    record_type: String,
    #[serde(rename = "Content")]
    content: String,
}

#[derive(Debug, Deserialize)]
struct TeoRecordRespData {
    #[serde(rename = "DnsRecords")]
    dns_records: Option<Vec<TeoRecordItem>>,
    #[serde(rename = "Error")]
    error: Option<TeoError>,
}

#[derive(Debug, Deserialize)]
struct TeoRecordResp {
    #[serde(rename = "Response")]
    response: TeoRecordRespData,
}

#[derive(Debug, Deserialize)]
struct TeoActionRespData {
    #[serde(rename = "Error")]
    error: Option<TeoError>,
}

#[derive(Debug, Deserialize)]
struct TeoActionResp {
    #[serde(rename = "Response")]
    response: TeoActionRespData,
}

#[derive(Debug, Deserialize)]
struct TeoOriginRecord {
    #[serde(rename = "Record")]
    record: String,
    #[serde(rename = "Type")]
    #[allow(dead_code)]
    record_type: String,
    #[serde(rename = "Weight")]
    weight: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct TeoOriginGroup {
    #[serde(rename = "GroupId")]
    group_id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Records")]
    records: Option<Vec<TeoOriginRecord>>,
}

#[derive(Debug, Deserialize)]
struct TeoOriginGroupRespData {
    #[serde(rename = "OriginGroups")]
    origin_groups: Option<Vec<TeoOriginGroup>>,
    #[serde(rename = "Error")]
    error: Option<TeoError>,
}

#[derive(Debug, Deserialize)]
struct TeoOriginGroupResp {
    #[serde(rename = "Response")]
    response: TeoOriginGroupRespData,
}

impl TencentEoProvider {
    pub fn new(
        secret_id: String,
        secret_key: String,
        http_interface: Option<&str>,
    ) -> Result<Self, DnsProviderError> {
        if secret_id.trim().is_empty() || secret_key.trim().is_empty() {
            return Err(DnsProviderError::MissingCredentials(
                "腾讯云 EdgeOne 需要配置 SecretId 与 SecretKey".to_string(),
            ));
        }

        let client = crate::util::http::create_task_http_client_builder(http_interface)
            .timeout(Duration::from_secs(15))
            .build()?;

        Ok(Self {
            client,
            secret_id,
            secret_key,
        })
    }

    /// 发起腾讯云 TC3-HMAC-SHA256 签名请求
    async fn request_tc3_api<T: for<'de> Deserialize<'de>>(
        &self,
        action: &str,
        payload_json: serde_json::Value,
    ) -> Result<T, DnsProviderError> {
        let payload_str = payload_json.to_string();
        let timestamp = Utc::now().timestamp();
        let date = Utc::now().format("%Y-%m-%d").to_string();

        // 1. 构造规范请求串 CanonicalRequest
        let canonical_headers = format!(
            "content-type:application/json; charset=utf-8\nhost:{}\nx-tc-action:{}\nx-tc-timestamp:{}\n",
            TEO_HOST,
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
        let credential_scope = format!("{}/{}/tc3_request", date, TEO_SERVICE);
        let hashed_canonical_request = sha256_hex(canonical_request.as_bytes());
        let string_to_sign = format!(
            "TC3-HMAC-SHA256\n{}\n{}\n{}",
            timestamp, credential_scope, hashed_canonical_request
        );

        // 3. 计算签名 Signature
        let secret_date = hmac_sha256(
            format!("TC3{}", self.secret_key).as_bytes(),
            date.as_bytes(),
        );
        let secret_service = hmac_sha256(&secret_date, TEO_SERVICE.as_bytes());
        let secret_signing = hmac_sha256(&secret_service, b"tc3_request");
        let signature = hex::encode(hmac_sha256(&secret_signing, string_to_sign.as_bytes()));

        // 4. 构造 Authorization
        let authorization = format!(
            "TC3-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            self.secret_id, credential_scope, signed_headers, signature
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        );
        headers.insert(HOST, HeaderValue::from_static(TEO_HOST));
        if let Ok(act_val) = HeaderValue::from_str(action) {
            headers.insert("X-TC-Action", act_val);
        }
        headers.insert("X-TC-Version", HeaderValue::from_static(TEO_VERSION));
        if let Ok(ts_val) = HeaderValue::from_str(&timestamp.to_string()) {
            headers.insert("X-TC-Timestamp", ts_val);
        }
        if let Ok(auth_val) = HeaderValue::from_str(&authorization) {
            headers.insert("Authorization", auth_val);
        }

        let resp = self
            .client
            .post(TEO_ENDPOINT)
            .headers(headers)
            .body(payload_str)
            .send()
            .await?;

        let status = resp.status();
        let body_text = resp.text().await?;

        if !status.is_success() {
            return Err(DnsProviderError::ApiError {
                code: status.to_string(),
                message: body_text,
            });
        }

        let parsed = serde_json::from_str::<T>(&body_text)?;
        Ok(parsed)
    }

    /// 获取 Zone ID
    async fn get_zone_id(&self, root_domain: &str) -> Result<String, DnsProviderError> {
        let payload = json!({
            "Filters": [
                {
                    "Name": "zone-name",
                    "Values": [root_domain]
                }
            ]
        });

        let resp: TeoZoneResp = self.request_tc3_api("DescribeZones", payload).await?;

        if let Some(err) = resp.response.error {
            return Err(DnsProviderError::ApiError {
                code: err.code,
                message: err.message,
            });
        }

        let zones = resp.response.zones.unwrap_or_default();
        let matched = zones
            .into_iter()
            .find(|z| z.zone_name.eq_ignore_ascii_case(root_domain))
            .ok_or_else(|| {
                DnsProviderError::ZoneNotFound(format!(
                    "在腾讯云 EdgeOne 中未找到根域名 [{}] 对应的 Zone",
                    root_domain
                ))
            })?;

        Ok(matched.zone_id)
    }
}

#[async_trait]
impl DnsProvider for TencentEoProvider {
    fn provider_name(&self) -> &'static str {
        "腾讯云 EdgeOne (EO)"
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

        // 1. 获取 Zone ID
        let zone_id = self.get_zone_id(&domain.root_domain).await?;

        // 2. 判断是否为源站组 (OriginGroup) 更新模式 (通过域名后缀参数 ?GroupId=og-xxx 或 ?OriginGroupName=xxx)
        let is_origin_group = domain.custom_params.contains_key("GroupId")
            || domain.custom_params.contains_key("group_id")
            || domain.custom_params.contains_key("OriginGroupName")
            || domain.custom_params.contains_key("origin_group_name");

        if is_origin_group {
            let group_id_opt = domain
                .custom_params
                .get("GroupId")
                .or_else(|| domain.custom_params.get("group_id"))
                .cloned();
            let group_name_opt = domain
                .custom_params
                .get("OriginGroupName")
                .or_else(|| domain.custom_params.get("origin_group_name"))
                .cloned();

            let weight_val = domain
                .custom_params
                .get("Weight")
                .or_else(|| domain.custom_params.get("weight"))
                .and_then(|w| w.parse::<u32>().ok())
                .unwrap_or(100);

            // 查询源站组列表
            let mut og_filters = Vec::new();
            if let Some(ref gid) = group_id_opt {
                og_filters.push(json!({"Name": "origin-group-id", "Values": [gid]}));
            } else if let Some(ref gname) = group_name_opt {
                og_filters.push(json!({"Name": "origin-group-name", "Values": [gname]}));
            }

            let og_describe_payload = json!({
                "ZoneId": zone_id,
                "Filters": og_filters
            });

            let og_resp: TeoOriginGroupResp = self
                .request_tc3_api("DescribeOriginGroup", og_describe_payload)
                .await?;

            if let Some(err) = og_resp.response.error {
                return Err(DnsProviderError::ApiError {
                    code: err.code,
                    message: format!("查询 EdgeOne 源站组失败: {}", err.message),
                });
            }

            let groups = og_resp.response.origin_groups.unwrap_or_default();
            let matched_group = groups
                .into_iter()
                .find(|g| {
                    if let Some(ref gid) = group_id_opt {
                        g.group_id.eq_ignore_ascii_case(gid)
                    } else if let Some(ref gname) = group_name_opt {
                        g.name.eq_ignore_ascii_case(gname)
                    } else {
                        true
                    }
                })
                .ok_or_else(|| DnsProviderError::ApiError {
                    code: "OriginGroupNotFound".to_string(),
                    message: format!(
                        "未找到指定的 EdgeOne 源站组 (ZoneId: {}, GroupId: {:?}, GroupName: {:?})",
                        zone_id, group_id_opt, group_name_opt
                    ),
                })?;

            // 检查源站记录并安全合并（避免覆盖清空组内其它已有源站）
            let current_records = matched_group.records.unwrap_or_default();
            let mut updated_records = Vec::new();
            let mut matched_existing = false;

            for r in &current_records {
                if r.record == target_ip_str {
                    matched_existing = true;
                    updated_records.push(json!({
                        "Record": target_ip_str,
                        "Type": r.record_type,
                        "Weight": weight_val
                    }));
                } else {
                    // 保留组内其它源站记录
                    updated_records.push(json!({
                        "Record": r.record,
                        "Type": r.record_type,
                        "Weight": r.weight.unwrap_or(100)
                    }));
                }
            }

            if !matched_existing {
                if current_records.len() <= 1 {
                    updated_records = vec![json!({
                        "Record": target_ip_str,
                        "Type": "IP_DOMAIN",
                        "Weight": weight_val
                    })];
                } else {
                    updated_records.push(json!({
                        "Record": target_ip_str,
                        "Type": "IP_DOMAIN",
                        "Weight": weight_val
                    }));
                }
            }

            let is_unchanged = matched_existing
                && current_records.len() == updated_records.len()
                && current_records
                    .iter()
                    .any(|r| r.record == target_ip_str && r.weight.unwrap_or(100) == weight_val);

            if is_unchanged {
                info!(
                    "[{}] EdgeOne 源站组 [{}] 记录未变化 ({}), 跳过更新",
                    self.provider_name(),
                    matched_group.name,
                    target_ip_str
                );
                return Ok(SyncRecordResult {
                    domain: full_domain,
                    record_type,
                    target_ip: target_ip_str,
                    status: SyncStatus::Unchanged,
                    message: "EdgeOne 源站组记录一致，无需更新".to_string(),
                });
            }

            // 执行修改源站组 (ModifyOriginGroup)
            let modify_og_payload = json!({
                "ZoneId": zone_id,
                "GroupId": matched_group.group_id,
                "Name": matched_group.name,
                "Type": "GENERAL",
                "Records": updated_records
            });

            let act_resp: TeoActionResp = self
                .request_tc3_api("ModifyOriginGroup", modify_og_payload)
                .await?;

            if let Some(err) = act_resp.response.error {
                return Err(DnsProviderError::ApiError {
                    code: err.code,
                    message: format!("修改 EdgeOne 源站组失败: {}", err.message),
                });
            }

            info!(
                "[{}] 成功同步 EdgeOne 源站组 [{}] -> IP: {}",
                self.provider_name(),
                matched_group.name,
                target_ip_str
            );

            return Ok(SyncRecordResult {
                domain: full_domain,
                record_type,
                target_ip: target_ip_str,
                status: SyncStatus::Updated,
                message: format!("成功更新 EdgeOne 源站组 [{}]", matched_group.name),
            });
        }

        // 3. 常规 DNS 解析记录查询与同步
        let describe_payload = json!({
            "ZoneId": zone_id,
            "Filters": [
                {
                    "Name": "name",
                    "Values": [full_domain]
                },
                {
                    "Name": "type",
                    "Values": [record_type.to_string()]
                }
            ]
        });

        let rec_resp: TeoRecordResp = self
            .request_tc3_api("DescribeDnsRecords", describe_payload)
            .await?;

        if let Some(err) = rec_resp.response.error {
            return Err(DnsProviderError::ApiError {
                code: err.code,
                message: err.message,
            });
        }

        let records = rec_resp.response.dns_records.unwrap_or_default();
        let matched = records.into_iter().find(|r| {
            r.name
                .trim_end_matches('.')
                .eq_ignore_ascii_case(full_domain.trim_end_matches('.'))
                && r.record_type.eq_ignore_ascii_case(&record_type.to_string())
        });

        if let Some(existing) = matched {
            if existing.content == target_ip_str {
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

            let record_id = existing.record_id.unwrap_or_default();

            // 更新记录 (ModifyDnsRecords)
            let modify_payload = json!({
                "ZoneId": zone_id,
                "DnsRecords": [
                    {
                        "RecordId": record_id,
                        "ZoneId": zone_id,
                        "Name": full_domain,
                        "Type": record_type.to_string(),
                        "Content": target_ip_str,
                        "Location": "Default",
                        "TTL": ttl_val
                    }
                ]
            });

            let act_resp: TeoActionResp = self
                .request_tc3_api("ModifyDnsRecords", modify_payload)
                .await?;

            if let Some(err) = act_resp.response.error {
                return Err(DnsProviderError::ApiError {
                    code: err.code,
                    message: format!("EdgeOne 更新记录失败: {}", err.message),
                });
            }

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
            // 创建记录 (CreateDnsRecord)
            let create_payload = json!({
                "ZoneId": zone_id,
                "Name": full_domain,
                "Type": record_type.to_string(),
                "Content": target_ip_str,
                "Location": "Default",
                "TTL": ttl_val
            });

            let act_resp: TeoActionResp = self
                .request_tc3_api("CreateDnsRecord", create_payload)
                .await?;

            if let Some(err) = act_resp.response.error {
                return Err(DnsProviderError::ApiError {
                    code: err.code,
                    message: format!("EdgeOne 创建记录失败: {}", err.message),
                });
            }

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
