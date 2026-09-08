use crate::core::domain::ParsedDomain;
use crate::dns::tencentcloud::{Tc3ApiEndpoint, Tc3Client};
use crate::dns::trait_def::{DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult};
use crate::util::http::create_task_http_client;
use async_trait::async_trait;
use log::info;
use serde::Deserialize;
use serde_json::json;
use std::net::IpAddr;
use std::time::Duration;

const TEO_ENDPOINT: Tc3ApiEndpoint = Tc3ApiEndpoint {
    host: "teo.tencentcloudapi.com",
    service: "teo",
    version: "2022-09-01",
};

/// 腾讯云 EdgeOne (TEO) 全球边缘加速与 DNS 同步驱动
pub struct TencentEoProvider {
    tc3: Tc3Client,
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
    /// 创建腾讯云 EdgeOne (TEO) 同步驱动实例
    ///
    /// # 设计原理
    /// - **实现初衷**: 适配腾讯云全球边缘安全加速平台 EdgeOne，支持同时管理原生权威 DNS 解析记录以及 CDN/全站加速源站组 (OriginGroup) 中的后端源站 IP。
    /// - **核心优势**: 支持无缝集成 EdgeOne TC3-HMAC-SHA256 签名机制与原生出站网卡绑定；支持源站组增量更新算法，安全保留组内其他源站。
    /// - **代价与局限**: 相比传统轻量 DNS，EdgeOne API 接口交互结构较深，且修改源站组生效存在轻微的边缘节点异步收敛延迟。
    ///
    /// # Errors
    ///
    /// 当 SecretId 或 SecretKey 为空，或构建底层 HTTP 客户端失败时返回 [`DnsProviderError`]。
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

        let client = create_task_http_client(http_interface, Duration::from_secs(15))?;

        Ok(Self {
            tc3: Tc3Client::new(client, secret_id, secret_key, TEO_ENDPOINT),
        })
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

        let resp: TeoZoneResp = self.tc3.request_api("DescribeZones", payload).await?;

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

    /// 计算合并后的源站组记录并检测是否产生实际变动
    fn compute_updated_origin_records(
        current_records: &[TeoOriginRecord],
        target_ip: &str,
        weight_val: u32,
    ) -> (Vec<serde_json::Value>, bool) {
        let mut updated_records = Vec::with_capacity(current_records.len() + 1);
        let mut matched_existing = false;

        for r in current_records {
            if r.record == target_ip {
                matched_existing = true;
                updated_records.push(json!({
                    "Record": target_ip,
                    "Type": r.record_type,
                    "Weight": weight_val
                }));
            } else {
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
                    "Record": target_ip,
                    "Type": "IP_DOMAIN",
                    "Weight": weight_val
                })];
            } else {
                updated_records.push(json!({
                    "Record": target_ip,
                    "Type": "IP_DOMAIN",
                    "Weight": weight_val
                }));
            }
        }

        let is_unchanged = matched_existing
            && current_records.len() == updated_records.len()
            && current_records
                .iter()
                .any(|r| r.record == target_ip && r.weight.unwrap_or(100) == weight_val);

        (updated_records, is_unchanged)
    }

    /// 同步 EdgeOne 源站组 (OriginGroup) 中的后端源站 IP
    async fn sync_origin_group(
        &self,
        zone_id: &str,
        domain: &ParsedDomain,
        target_ip_str: &str,
        record_type: DnsRecordType,
    ) -> Result<SyncRecordResult, DnsProviderError> {
        let full_domain = domain.full_domain();
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

        let mut og_filters = Vec::new();
        if let Some(ref gid) = group_id_opt {
            og_filters.push(json!({"Name": "origin-group-id", "Values": [gid]}));
        } else if let Some(ref gname) = group_name_opt {
            og_filters.push(json!({"Name": "origin-group-name", "Values": [gname]}));
        }

        let og_describe_payload = json!({ "ZoneId": zone_id, "Filters": og_filters });
        let og_resp: TeoOriginGroupResp = self
            .tc3
            .request_api("DescribeOriginGroup", og_describe_payload)
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

        let current_records = matched_group.records.unwrap_or_default();
        let (updated_records, is_unchanged) =
            Self::compute_updated_origin_records(&current_records, target_ip_str, weight_val);

        if is_unchanged {
            info!(
                "[{}] EdgeOne 源站组 [{}] 记录未变化 ({}), 跳过更新",
                self.provider_name(),
                matched_group.name,
                target_ip_str
            );
            return Ok(SyncRecordResult::unchanged(
                full_domain,
                record_type,
                target_ip_str,
            ));
        }

        let modify_og_payload = json!({
            "ZoneId": zone_id,
            "GroupId": matched_group.group_id,
            "Name": matched_group.name,
            "Type": "GENERAL",
            "Records": updated_records
        });

        let act_resp: TeoActionResp = self
            .tc3
            .request_api("ModifyOriginGroup", modify_og_payload)
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

        Ok(SyncRecordResult::updated(
            full_domain,
            record_type,
            target_ip_str,
        ))
    }

    /// 同步 EdgeOne 普通权威 DNS 解析记录
    async fn sync_standard_dns_record(
        &self,
        zone_id: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
        target_ip_str: &str,
        ttl_val: u32,
    ) -> Result<SyncRecordResult, DnsProviderError> {
        let full_domain = domain.full_domain();
        let describe_payload = json!({
            "ZoneId": zone_id,
            "Filters": [
                { "Name": "name", "Values": [full_domain] },
                { "Name": "type", "Values": [record_type.to_string()] }
            ]
        });

        let rec_resp: TeoRecordResp = self
            .tc3
            .request_api("DescribeDnsRecords", describe_payload)
            .await?;

        if let Some(err) = rec_resp.response.error {
            return Err(DnsProviderError::ApiError {
                code: err.code,
                message: err.message,
            });
        }

        let records = rec_resp.response.dns_records.unwrap_or_default();
        let matched = records.into_iter().find(|r| {
            domain.matches_record_name(&r.name)
                && r.record_type.eq_ignore_ascii_case(&record_type.to_string())
        });

        if let Some(existing) = matched {
            if existing.content == target_ip_str {
                return Ok(SyncRecordResult::unchanged_log(
                    self.provider_name(),
                    full_domain,
                    record_type,
                    target_ip_str,
                ));
            }

            let record_id = existing.record_id.unwrap_or_default();
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
                .tc3
                .request_api("ModifyDnsRecords", modify_payload)
                .await?;

            if let Some(err) = act_resp.response.error {
                return Err(DnsProviderError::ApiError {
                    code: err.code,
                    message: format!("EdgeOne 更新记录失败: {}", err.message),
                });
            }

            Ok(SyncRecordResult::updated_log(
                self.provider_name(),
                full_domain,
                record_type,
                target_ip_str,
            ))
        } else {
            let create_payload = json!({
                "ZoneId": zone_id,
                "Name": full_domain,
                "Type": record_type.to_string(),
                "Content": target_ip_str,
                "Location": "Default",
                "TTL": ttl_val
            });

            let act_resp: TeoActionResp = self
                .tc3
                .request_api("CreateDnsRecord", create_payload)
                .await?;

            if let Some(err) = act_resp.response.error {
                return Err(DnsProviderError::ApiError {
                    code: err.code,
                    message: format!("EdgeOne 创建记录失败: {}", err.message),
                });
            }

            Ok(SyncRecordResult::created_log(
                self.provider_name(),
                full_domain,
                record_type,
                target_ip_str,
            ))
        }
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
        let zone_id = self.get_zone_id(&domain.root_domain).await?;
        let target_ip_str = ip.to_string();
        let ttl_val = ttl.unwrap_or(600).max(1);

        let is_origin_group = domain.custom_params.contains_key("GroupId")
            || domain.custom_params.contains_key("group_id")
            || domain.custom_params.contains_key("OriginGroupName")
            || domain.custom_params.contains_key("origin_group_name");

        if is_origin_group {
            self.sync_origin_group(&zone_id, domain, &target_ip_str, record_type)
                .await
        } else {
            self.sync_standard_dns_record(&zone_id, domain, record_type, &target_ip_str, ttl_val)
                .await
        }
    }
}
