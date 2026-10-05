//! 腾讯云 EdgeOne (TEO) API 响应与实体数据契约模型
//!
//! # 设计原理
//! 将 EdgeOne 的 API 实体类型从主体驱动中拆离，降低单文件复杂度并符合模块化设计准则。

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct TeoError {
    #[serde(rename = "Code")]
    pub code: String,
    #[serde(rename = "Message")]
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct TeoZoneItem {
    #[serde(rename = "ZoneId")]
    pub zone_id: String,
    #[serde(rename = "ZoneName")]
    pub zone_name: String,
}

#[derive(Debug, Deserialize)]
pub struct TeoZoneRespData {
    #[serde(rename = "Zones")]
    pub zones: Option<Vec<TeoZoneItem>>,
    #[serde(rename = "Error")]
    pub error: Option<TeoError>,
}

#[derive(Debug, Deserialize)]
pub struct TeoZoneResp {
    #[serde(rename = "Response")]
    pub response: TeoZoneRespData,
}

#[derive(Debug, Deserialize)]
pub struct TeoRecordItem {
    #[serde(rename = "RecordId")]
    pub record_id: Option<String>,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Type")]
    pub record_type: String,
    #[serde(rename = "Content")]
    pub content: String,
}

#[derive(Debug, Deserialize)]
pub struct TeoRecordRespData {
    #[serde(rename = "DnsRecords")]
    pub dns_records: Option<Vec<TeoRecordItem>>,
    #[serde(rename = "Error")]
    pub error: Option<TeoError>,
}

#[derive(Debug, Deserialize)]
pub struct TeoRecordResp {
    #[serde(rename = "Response")]
    pub response: TeoRecordRespData,
}

#[derive(Debug, Deserialize)]
pub struct TeoActionRespData {
    #[serde(rename = "Error")]
    pub error: Option<TeoError>,
}

#[derive(Debug, Deserialize)]
pub struct TeoActionResp {
    #[serde(rename = "Response")]
    pub response: TeoActionRespData,
}

#[derive(Debug, Deserialize)]
pub struct TeoOriginRecord {
    #[serde(rename = "Record")]
    pub record: String,
    #[serde(rename = "Type")]
    pub record_type: String,
    #[serde(rename = "Weight")]
    pub weight: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct TeoOriginGroup {
    #[serde(rename = "GroupId")]
    pub group_id: String,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Records")]
    pub records: Option<Vec<TeoOriginRecord>>,
}

#[derive(Debug, Deserialize)]
pub struct TeoOriginGroupRespData {
    #[serde(rename = "OriginGroups")]
    pub origin_groups: Option<Vec<TeoOriginGroup>>,
    #[serde(rename = "Error")]
    pub error: Option<TeoError>,
}

#[derive(Debug, Deserialize)]
pub struct TeoOriginGroupResp {
    #[serde(rename = "Response")]
    pub response: TeoOriginGroupRespData,
}
