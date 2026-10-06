use crate::core::domain::ParsedDomain;
use crate::dns::ops::{RecordOps, RecordParams, RemoteRecord};
use crate::dns::tencent_eo_types::*;
use crate::dns::tencentcloud::{Tc3ApiEndpoint, Tc3Client};
use crate::dns::trait_def::{DnsProviderError, DnsRecordType, default_ttl};
use crate::util::http::create_default_dns_client;
use async_trait::async_trait;
use serde_json::json;

const TEO_ENDPOINT: Tc3ApiEndpoint = Tc3ApiEndpoint {
    host: "teo.tencentcloudapi.com",
    service: "teo",
    version: "2022-09-01",
};

/// 腾讯云 EdgeOne (TEO) 全球边缘加速与 DNS 同步驱动
pub struct TencentEoProvider {
    tc3: Tc3Client,
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
    /// 当 SecretId 或 SecretKey 为空时返回 [`DnsProviderError::MissingCredentials`]。
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

        // 复用全局连接池缓存，避免每轮同步重复进行 TCP/TLS 握手
        let client = create_default_dns_client(http_interface);
        let tc3 = Tc3Client::new(client, secret_id, secret_key, TEO_ENDPOINT);

        Ok(Self { tc3 })
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

        let zones = resp.response.zones.unwrap_or_default();
        let matched = zones
            .into_iter()
            .find(|z| z.zone_name.eq_ignore_ascii_case(root_domain))
            .ok_or_else(|| DnsProviderError::ZoneNotFound(root_domain.to_string()))?;

        Ok(matched.zone_id)
    }

    fn is_origin_group(domain: &ParsedDomain) -> bool {
        domain.custom_params.contains_key("GroupId")
            || domain.custom_params.contains_key("group_id")
            || domain.custom_params.contains_key("OriginGroupName")
            || domain.custom_params.contains_key("origin_group_name")
    }

    /// 计算合并后的源站组记录
    ///
    /// # 设计原理
    /// - **单源站场景** (`len <= 1`)：直接用当前目标 IP 覆盖源站记录，彻底避免动态公网 IP 变动时历史 IP 无限累积堆叠；
    /// - **多源站场景**：若匹配到目标 IP 则更新权重；若指定了旧 IP 则将其替换为新目标 IP；否则追加新节点并保留组内其他合法源站。
    fn compute_updated_origin_records(
        current_records: &[TeoOriginRecord],
        target_ip: &str,
        old_ip: Option<&str>,
        weight_val: u32,
    ) -> Vec<serde_json::Value> {
        if current_records.len() <= 1 {
            return vec![json!({
                "Record": target_ip,
                "Type": "IP_DOMAIN",
                "Weight": weight_val
            })];
        }

        let mut updated_records = Vec::with_capacity(current_records.len() + 1);
        let mut replaced = false;

        for r in current_records {
            if r.record == target_ip || old_ip.is_some_and(|old| r.record == old) {
                replaced = true;
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

        if !replaced {
            updated_records.push(json!({
                "Record": target_ip,
                "Type": "IP_DOMAIN",
                "Weight": weight_val
            }));
        }

        updated_records
    }

    async fn get_origin_group(
        &self,
        zone_id: &str,
        domain: &ParsedDomain,
    ) -> Result<TeoOriginGroup, DnsProviderError> {
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

        let groups = og_resp.response.origin_groups.unwrap_or_default();
        groups
            .into_iter()
            .find(|g| {
                if let Some(ref gid) = group_id_opt {
                    g.group_id.eq_ignore_ascii_case(gid)
                } else if let Some(ref gname) = group_name_opt {
                    g.name.eq_ignore_ascii_case(gname)
                } else {
                    false
                }
            })
            .ok_or_else(|| DnsProviderError::ApiError {
                code: "OriginGroupNotFound".to_string(),
                message: format!(
                    "未找到指定的 EdgeOne 源站组 (ZoneId: {}, GroupId: {:?}, GroupName: {:?})",
                    zone_id, group_id_opt, group_name_opt
                ),
            })
    }
}

#[async_trait]
impl RecordOps for TencentEoProvider {
    fn provider_name(&self) -> &'static str {
        "腾讯云 EdgeOne (EO)"
    }

    async fn resolve_zone(&self, root_domain: &str) -> Result<String, DnsProviderError> {
        self.get_zone_id(root_domain).await
    }

    async fn list_records(
        &self,
        zone: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
    ) -> Result<Vec<RemoteRecord>, DnsProviderError> {
        if Self::is_origin_group(domain) {
            let matched_group = self.get_origin_group(zone, domain).await?;
            let current_records = matched_group.records.unwrap_or_default();
            let remotes = current_records
                .into_iter()
                .map(|r| RemoteRecord::new(r.record.clone(), r.record))
                .collect();
            Ok(remotes)
        } else {
            let full_domain = domain.full_domain();
            let describe_payload = json!({
                "ZoneId": zone,
                "Filters": [
                    { "Name": "name", "Values": [full_domain] },
                    { "Name": "type", "Values": [record_type.to_string()] }
                ]
            });

            let rec_resp: TeoRecordResp = self
                .tc3
                .request_api("DescribeDnsRecords", describe_payload)
                .await?;

            let records = rec_resp.response.dns_records.unwrap_or_default();
            let matched = records
                .into_iter()
                .filter(|r| {
                    domain.matches_record_name(&r.name)
                        && r.record_type.eq_ignore_ascii_case(&record_type.to_string())
                })
                .map(|r| RemoteRecord::new(r.record_id.unwrap_or_default(), r.content))
                .collect();

            Ok(matched)
        }
    }

    async fn create_record(
        &self,
        zone: &str,
        params: &RecordParams<'_>,
    ) -> Result<(), DnsProviderError> {
        let target_ip_str = params.ip.to_string();
        if Self::is_origin_group(params.domain) {
            self.update_record(zone, "", params).await
        } else {
            let full_domain = params.domain.full_domain();
            let ttl_val = default_ttl(params.ttl);
            let create_payload = json!({
                "ZoneId": zone,
                "Name": full_domain,
                "Type": params.record_type.to_string(),
                "Content": target_ip_str,
                "Location": "Default",
                "TTL": ttl_val
            });

            let _act: TeoActionResp = self
                .tc3
                .request_api("CreateDnsRecord", create_payload)
                .await?;

            Ok(())
        }
    }

    async fn update_record(
        &self,
        zone: &str,
        record_id: &str,
        params: &RecordParams<'_>,
    ) -> Result<(), DnsProviderError> {
        let target_ip_str = params.ip.to_string();
        if Self::is_origin_group(params.domain) {
            let matched_group = self.get_origin_group(zone, params.domain).await?;
            let weight_val = params
                .domain
                .custom_params
                .get("Weight")
                .or_else(|| params.domain.custom_params.get("weight"))
                .and_then(|w| w.parse::<u32>().ok())
                .unwrap_or(100);

            let current_records = matched_group.records.unwrap_or_default();
            let old_ip = if record_id.is_empty() {
                None
            } else {
                Some(record_id)
            };
            let updated_records = Self::compute_updated_origin_records(
                &current_records,
                &target_ip_str,
                old_ip,
                weight_val,
            );

            let modify_og_payload = json!({
                "ZoneId": zone,
                "GroupId": matched_group.group_id,
                "Name": matched_group.name,
                "Type": "GENERAL",
                "Records": updated_records
            });

            let _act: TeoActionResp = self
                .tc3
                .request_api("ModifyOriginGroup", modify_og_payload)
                .await?;

            Ok(())
        } else {
            let full_domain = params.domain.full_domain();
            let ttl_val = default_ttl(params.ttl);
            let modify_payload = json!({
                "ZoneId": zone,
                "DnsRecords": [
                    {
                        "RecordId": record_id,
                        "ZoneId": zone,
                        "Name": full_domain,
                        "Type": params.record_type.to_string(),
                        "Content": target_ip_str,
                        "Location": "Default",
                        "TTL": ttl_val
                    }
                ]
            });

            let _act: TeoActionResp = self
                .tc3
                .request_api("ModifyDnsRecords", modify_payload)
                .await?;

            Ok(())
        }
    }

    async fn delete_record(
        &self,
        zone: &str,
        record: &RemoteRecord,
        _params: &RecordParams<'_>,
    ) -> Result<(), DnsProviderError> {
        let delete_payload = json!({
            "ZoneId": zone,
            "RecordIds": [&record.id]
        });

        let _act: TeoActionResp = self
            .tc3
            .request_api("DeleteDnsRecords", delete_payload)
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_teo_zone_resp_deserialization() {
        let json_str = r#"{
            "Response": {
                "Zones": [
                    {
                        "ZoneId": "zone-2a3b4c5d",
                        "ZoneName": "example.com"
                    }
                ],
                "Error": null
            }
        }"#;

        let resp: TeoZoneResp = serde_json::from_str(json_str).unwrap();
        let zones = resp.response.zones.expect("应包含 zones 列表");
        assert_eq!(zones.len(), 1);
        assert_eq!(zones[0].zone_id, "zone-2a3b4c5d");
        assert_eq!(zones[0].zone_name, "example.com");
    }

    #[test]
    fn test_teo_record_resp_deserialization() {
        let json_str = r#"{
            "Response": {
                "DnsRecords": [
                    {
                        "RecordId": "rec-123456",
                        "Name": "sub.example.com",
                        "Type": "A",
                        "Content": "1.2.3.4"
                    }
                ],
                "Error": null
            }
        }"#;

        let resp: TeoRecordResp = serde_json::from_str(json_str).unwrap();
        let records = resp.response.dns_records.expect("应包含 dns_records 列表");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].record_id.as_deref(), Some("rec-123456"));
        assert_eq!(records[0].content, "1.2.3.4");
    }

    #[test]
    fn test_origin_group_param_detection() {
        let mut domain = ParsedDomain {
            raw: "cdn.example.com".to_string(),
            sub_domain: "cdn".to_string(),
            root_domain: "example.com".to_string(),
            custom_params: std::collections::HashMap::new(),
        };

        // 未配置源站组参数时为标准 DNS
        let is_og = domain.custom_params.contains_key("GroupId")
            || domain.custom_params.contains_key("group_id");
        assert!(!is_og);

        // 配置 group_id 后识别为源站组
        domain
            .custom_params
            .insert("group_id".to_string(), "og-123".to_string());
        let is_og = domain.custom_params.contains_key("GroupId")
            || domain.custom_params.contains_key("group_id");
        assert!(is_og);
    }

    #[test]
    fn test_compute_updated_origin_records_single_and_multi() {
        // 单源站场景：原有一个旧 IP，更新为新 IP 时应直接覆盖，不产生残留 (P3-21)
        let single_origin = vec![TeoOriginRecord {
            record: "1.1.1.1".to_string(),
            record_type: "IP_DOMAIN".to_string(),
            weight: Some(100),
        }];
        let updated = TencentEoProvider::compute_updated_origin_records(
            &single_origin,
            "2.2.2.2",
            Some("1.1.1.1"),
            100,
        );
        assert_eq!(updated.len(), 1, "单源站应覆盖为唯一新 IP");
        assert_eq!(updated[0]["Record"], "2.2.2.2");

        // 多源站场景：保留其他备用源站，仅替换指定旧 IP
        let multi_origin = vec![
            TeoOriginRecord {
                record: "1.1.1.1".to_string(),
                record_type: "IP_DOMAIN".to_string(),
                weight: Some(50),
            },
            TeoOriginRecord {
                record: "8.8.8.8".to_string(),
                record_type: "IP_DOMAIN".to_string(),
                weight: Some(50),
            },
        ];
        let updated_multi = TencentEoProvider::compute_updated_origin_records(
            &multi_origin,
            "2.2.2.2",
            Some("1.1.1.1"),
            50,
        );
        assert_eq!(updated_multi.len(), 2, "多源站应保留其他节点并替换目标节点");
        assert!(
            updated_multi
                .iter()
                .any(|r| r["Record"] == "2.2.2.2" && r["Weight"] == 50)
        );
        assert!(
            updated_multi
                .iter()
                .any(|r| r["Record"] == "8.8.8.8" && r["Weight"] == 50)
        );
    }
}
