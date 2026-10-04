//! rddns 动态域名解析与通知服务
//!
//! # 设计原理
//! - **实现初衷**：将各功能模块从 `main.rs` 中剥离，使本 crate 同时具备
//!   「可执行程序」与「可被集成测试引用的库」两种能力。
//!
//! # 模块职责
//! - [`config`]：配置数据契约（模型）与原子持久化存储
//! - [`core`]：DDNS 调度引擎、运行时状态与域名解析
//! - [`dns`]：各DNS 服务商的同步驱动抽象与实现
//! - [`ip_fetcher`]：公网 IP 探测器（URL / 网卡 / STUN / 外部命令）
//! - [`notifier`]：多渠道通知分发
//! - [`util`]：HTTP 客户端治理、加密、IP 判定等基础设施
//! - [`web`]：Axum 管理后台与静态资源托管
//!
//! # 分层约定
//! 依赖方向自上而下单向流动：`web` → `core` → `dns`/`ip_fetcher`/`notifier`
//! → `config`/`util`。其中 `config` 与 `util` 不依赖任何上层模块，
//! 严禁引入反向依赖或循环引用。

pub mod config;
pub mod core;
pub mod dns;
pub mod ip_fetcher;
pub mod notifier;
pub mod util;
pub mod web;
