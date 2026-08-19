use super::{ApiResponse, AppState};
use crate::config::model::{IpFetchConfig, IpSourceType, NotificationConfig};
use crate::core::domain::parse_domain;
use crate::dns::trait_def::{DnsRecordType, SyncRecordResult, SyncStatus};
use crate::ip_fetcher::create_ip_fetcher;
use crate::notifier::dispatcher::NotificationDispatcher;
use crate::notifier::trait_def::{NotificationEvent, NotificationOverallStatus};
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use chrono::Local;
use serde::{Deserialize, Serialize};

/// 测试 IP 提取器配置请求体
#[derive(Debug, Deserialize)]
pub struct TestIpRequest {
    pub ip_type: Option<String>,
    pub http_interface: Option<String>,
    #[serde(flatten)]
    pub config: IpFetchConfig,
}

/// 测试 IP 提取器配置响应
#[derive(Debug, Serialize)]
pub struct TestIpResult {
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
}

/// 测试 IP 提取器在线获取
pub async fn test_ip_handler(Json(payload): Json<TestIpRequest>) -> impl IntoResponse {
    let iface = payload.http_interface.as_deref();
    let config = payload.config;

    // 1. 命令型 IP 获取明确禁止在线即时测试（防止 Web API 暴露任意命令执行风险）
    if config.source_type == IpSourceType::Command {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<TestIpResult>::err(
                "命令型 IP 获取不支持在线测试，请保存配置后通过同步日志验证！".to_string(),
            )),
        );
    }

    // 2. URL 型 IP 获取强制校验 Scheme 白名单 (仅允许 http:// 或 https://，防范协议走私与 SSRF 滥用)
    if config.source_type == IpSourceType::Url {
        for url in &config.url_endpoints {
            let trimmed = url.trim();
            if !trimmed.is_empty()
                && !trimmed.starts_with("http://")
                && !trimmed.starts_with("https://")
            {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ApiResponse::<TestIpResult>::err(format!(
                        "URL 端点 [{}] 协议非法，仅允许 http:// 或 https:// 开头的地址！",
                        trimmed
                    ))),
                );
            }
        }
    }

    if let Some(fetcher) = create_ip_fetcher(&config, iface) {
        let is_v4_test = payload.ip_type.as_deref() == Some("ipv4");
        let is_v6_test = payload.ip_type.as_deref() == Some("ipv6");

        let ipv4 = if is_v6_test {
            None
        } else {
            fetcher
                .fetch_ipv4()
                .await
                .ok()
                .flatten()
                .map(|ip| ip.to_string())
        };

        let ipv6 = if is_v4_test {
            None
        } else {
            fetcher
                .fetch_ipv6()
                .await
                .ok()
                .flatten()
                .map(|ip| ip.to_string())
        };

        (
            StatusCode::OK,
            Json(ApiResponse::ok(TestIpResult { ipv4, ipv6 })),
        )
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<TestIpResult>::err(
                "无法创建 IP 提取器，请检查是否填写了网卡名称或有效的 URL".to_string(),
            )),
        )
    }
}

/// 测试通知发送（优先提取当前已配置的真实公网 IP 与真实域名数据）
pub async fn test_notify_handler(
    State(state): State<AppState>,
    Json(config): Json<NotificationConfig>,
) -> impl IntoResponse {
    let app_config = state.config_manager.get_config();
    let dispatcher = NotificationDispatcher::new(config);

    // 尝试从当前任务中探测真实 IP 并生成真实测试数据
    let task = app_config.dns_tasks.first();
    let task_name = task
        .map(|t| t.name.clone())
        .unwrap_or_else(|| "默认任务".to_string());

    let mut ipv4 = None;
    let mut ipv6 = None;
    let mut results = Vec::new();

    if let Some(t) = task {
        // 探测真实 IPv4
        if let Some(fetcher) = if t.ipv4.enabled {
            create_ip_fetcher(&t.ipv4, t.http_interface.as_deref())
        } else {
            None
        } {
            ipv4 = fetcher.fetch_ipv4().await.ok().flatten();
        }
        // 探测真实 IPv6
        if let Some(fetcher) = if t.ipv6.enabled {
            create_ip_fetcher(&t.ipv6, t.http_interface.as_deref())
        } else {
            None
        } {
            ipv6 = fetcher.fetch_ipv6().await.ok().flatten();
        }

        // 构建真实的域名结果列表
        for d in &t.ipv4.domains {
            if let Some(parsed) = parse_domain(d) {
                let ip_str = ipv4
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "127.0.0.1".to_string());
                results.push(SyncRecordResult {
                    domain: parsed.full_domain(),
                    record_type: DnsRecordType::A,
                    target_ip: ip_str,
                    status: SyncStatus::Updated,
                    message: "通知通道测试消息（真实 IPv4 数据）".to_string(),
                });
            }
        }

        for d in &t.ipv6.domains {
            if let Some(parsed) = parse_domain(d) {
                let ip_str = ipv6
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "::1".to_string());
                results.push(SyncRecordResult {
                    domain: parsed.full_domain(),
                    record_type: DnsRecordType::AAAA,
                    target_ip: ip_str,
                    status: SyncStatus::Updated,
                    message: "通知通道测试消息（真实 IPv6 数据）".to_string(),
                });
            }
        }
    }

    // 如果未配置任何域名，使用示例域名
    if results.is_empty() {
        results.push(SyncRecordResult {
            domain: "test.example.com".to_string(),
            record_type: if ipv6.is_some() && ipv4.is_none() {
                DnsRecordType::AAAA
            } else {
                DnsRecordType::A
            },
            target_ip: ipv4
                .map(|ip| ip.to_string())
                .or_else(|| ipv6.map(|ip| ip.to_string()))
                .unwrap_or_else(|| "127.0.0.1".to_string()),
            status: SyncStatus::Updated,
            message: "这是一条测试消息，表明通知渠道工作正常！".to_string(),
        });
    }

    let sample_event = NotificationEvent {
        overall_status: NotificationOverallStatus::Success,
        title: "rddns 通知通道测试".to_string(),
        task_name,
        ipv4,
        ipv6,
        ip_changed: true,
        results,
        timestamp: Local::now(),
    };

    dispatcher.dispatch_force(sample_event);
    Json(ApiResponse::ok(
        "测试通知已派发至已启用的渠道，请查看目标平台",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_test_ip_rejects_command() {
        let req = TestIpRequest {
            ip_type: Some("ipv4".to_string()),
            http_interface: None,
            config: IpFetchConfig {
                enabled: true,
                source_type: IpSourceType::Command,
                cmd: Some("whoami".to_string()),
                ..Default::default()
            },
        };
        let res = test_ip_handler(Json(req)).await.into_response();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_test_ip_rejects_invalid_scheme() {
        let req = TestIpRequest {
            ip_type: Some("ipv4".to_string()),
            http_interface: None,
            config: IpFetchConfig {
                enabled: true,
                source_type: IpSourceType::Url,
                url_endpoints: vec!["file:///etc/passwd".to_string()],
                ..Default::default()
            },
        };
        let res = test_ip_handler(Json(req)).await.into_response();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }
}
