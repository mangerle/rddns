<div align="center">

# 🚀 rddns

**基于纯 Rust 打造的高性能、极轻量、全功能动态域名解析（DDNS）与告警服务**

[![Rust](https://img.shields.io/badge/Rust-2024_Edition-orange.svg?logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-brightgreen.svg)]()
[![Memory](https://img.shields.io/badge/Memory-~2.9_MB_Private-success.svg)]()
[![Single Binary](https://img.shields.io/badge/Binary-Single_Self--Contained-blueviolet.svg)]()

</div>

---

## 💡 项目背景与致敬

本项目在架构设计、功能交互与用户体验上深度参考并致敬了优秀的开源项目 **[ddns-go](https://github.com/jeessy2/ddns-go)**。

在传承其优秀特性的基础上，`rddns` 采用 **纯 Rust（2024 Edition + Tokio 异步运行时）** 进行了全新重构与深度优化，彻底去除外部运行时与垃圾回收（GC）开销，追求极致的**内存控制、低资源消耗与零依赖单文件自包含分发**。

---

## ✨ 核心特性

- ⚡ **极致轻量与高性能**：
  - **实测私有内存（Private Bytes）仅约 2.9 MB**，物理工作集仅约 10.5 MB；
  - 采用纯 Rust 零成本抽象与 RAII 内存管理，无 GC 停顿与内存膨胀风险；
  - 启动毫秒级响应，即使在 64MB/128MB 的老旧嵌入式路由器或廉价 VPS 上亦可从容运行。
- 📦 **单文件绿色自包含**：
  - 前端 Web 资产与 CA 根证书全量嵌入二进制，单可执行文件（约 5.6 MB）双击即可运行。
- 📋 **多任务主从管理 (Master-Detail)**：
  - 现代化多任务双栏主从管理界面，支持独立配置多条 DDNS 任务；
  - 每个任务均可独立分配域名、服务商、出站网卡与解析策略。
- 🌐 **全方位双栈 IP 探测能力**：
  - **URL 接口提取**：内置多个高可用公共 IP 接口，支持用户自定义 URL 列表与正则表达式提取。
  - **网卡设备直读**：自动枚举系统物理与虚拟网卡，支持 `@1`、`@2` 序号语法快捷选取指定 IPv6 地址。
  - **系统脚本/命令**：支持执行自定义 Shell / PowerShell 命令或外部脚本获取 IP。
- 🔗 **多 WAN 软路由出口绑定 (HttpInterface)**：
  - 支持按任务指定绑定的出站物理网卡（如 `eth0`、`pppoe-wan`），多宽带聚合/软路由多拨环境下利器。
- 🛡️ **网络抗污染与自定义 DNS**：
  - 内置纯 Rust 异步 DNS UDP 查询器，支持命令行 `--dns` 及 Web 控制台配置公共 DNS 节点（如 `223.5.5.5`、`1.1.1.1`），直连递归解析，彻底规避运营商 Local DNS 劫持与缓存污染。
- ☁️ **支持 24+ 款主流 DNS 服务商（纯 Rust 算法签名）**：
  - **主流云厂商**：Cloudflare、阿里云 (AliDNS)、腾讯云 (DNSPod)、华为云 (Huawei Cloud)、百度智能云 (Baidu Cloud)、火山引擎 (TrafficRoute)；
  - **海外注册商**：Porkbun、GoDaddy、Namecheap、NameSilo、Spaceship、Dynadot、Name.com、Gcore、Dynv6、ClouDNS、NS1 Connect；
  - **边缘加速与云托管**：阿里云 ESA (边缘安全加速)、腾讯云 EdgeOne (含动态源站组 OriginGroup 同步)、Vercel (含团队 teamId 支持)、雨云 (RainYun)、DNS.LA；
  - **国内传统与专线**：时代互联 (Now.cn / Eranet / TNetHK)、HiPM DNSMgr (自建 DNS 管理系统)、通用自定义 Webhook Callback。
- 📢 **多渠道实时告警通知**：
  - 微信公众号 (官方原生模板消息)、企业微信 (群机器人 / 自建应用)、钉钉机器人 (支持加签)、飞书机器人 (支持加签)、Telegram Bot、Bark (iOS 实时推送)、SMTP 邮件 (SSL/TLS)、通用自定义 Webhook。
- 🔐 **安全与运维保障**：
  - 支持 Web 管理员密码登录（BCrypt 安全加密存储）；
  - **一键禁止公网访问保护**（WAN 安全拦截）；
  - 支持一键重置密码（`--resetPassword`）、跳过证书校验（`--skipVerify`）、开机网络就绪等待防假死。

---

## 📊 资源与内存占用实测

基于 Windows 11 / Linux x86_64 环境在 Release 优化构建下的实测数据：

| 运行模式 | 二进制体积 | 私有提交内存 (Private Bytes) | 物理工作集 (Working Set) | 运行时依赖 |
| :--- | :---: | :---: | :---: | :---: |
| **完整 Web 管理模式** | 5.60 MB | **~2.93 MB** | ~10.53 MB | 无（单文件） |
| **纯后台静默模式 (`--noweb`)** | 5.60 MB | **~2.88 MB** | ~10.35 MB | 无（单文件） |

> 💡 *注：Working Set 包含操作系统共享动态链接库与系统 API 映射，真实应用程序常驻占用的私有内存仅不到 3.0 MB。*

---

## 🛠️ 快速开始

### 1. 下载或编译

确保已安装 [Rust 工具链](https://rustup.rs/)（推荐 Rust 1.85+）：

```bash
# 克隆仓库
git clone https://github.com/mangerle/rddns.git
cd rddns

# 编译 Release 优化版本
cargo build --release
```

编译产物位于 `target/release/rddns`（Windows 下为 `rddns.exe`）。

### 2. 运行

```bash
# 启动服务（默认监听 http://0.0.0.0:9876）
./target/release/rddns

# 指定监听端口（支持 -p 或 -l）
./target/release/rddns -p 8888

# 纯后台静默同步模式（不开启 Web 界面）
./target/release/rddns --noweb

# 指定抗污染公共 DNS 服务器
./target/release/rddns --dns 223.5.5.5

# 忘记密码时一键重置
./target/release/rddns --resetPassword MyNewPassword123
```

启动后在浏览器中访问 `http://localhost:9876` 即可进入现代 Web 控制台。

---

## 💻 命令行参数一览

| 参数 | 短参数 | 默认值 | 说明 |
| :--- | :---: | :---: | :--- |
| `--config <PATH>` | `-c` | `.rddns_config.yaml` | 配置文件读取与写入路径（优先读取当前目录） |
| `--listen <ADDR>` / `--port` | `-l` / `-p` | `9876` | 自定义 Web 服务监听端口或套接字地址（如 `8888` 或 `:8888`） |
| `--frequency <SECS>` | `-f` | `300` | 定时同步轮询间隔时间（单位: 秒） |
| `--noweb` | - | `false` | 纯无界面后台静默同步模式 |
| `--dns <SERVER>` | - | - | 自定义抗污染公网 DNS 递归查询服务器（如 `223.5.5.5` 或 `1.1.1.1:53`） |
| `--skipVerify` / `--skip-verify` | - | `false` | 跳过 HTTPS/TLS 证书有效性校验（内网或自签名场景使用） |
| `--resetPassword <PASS>` | - | - | 一键重置 Web 控制台管理员登录密码并立即退出 |
| `--daemon` | `-d` | `false` | 以系统独立后台守护进程（Daemon）模式运行 |
| `--upgrade` | `-u` | `false` | 在线检测并一键自更新至 GitHub 仓库最新发布版本 |
| `--service <ACTION>` | `-s` | - | 系统服务一键管理 (`install` / `uninstall` / `start` / `stop` / `status` / `restart`) |

---

## ⚙️ 配置文件示例 (`.rddns_config.yaml`)

```yaml
# Web 服务监听端口
listen_port: 9876

# 全局同步检查周期 (秒)
interval_secs: 300

# 连续未变动时的远程记录校对周期
cache_times: 10

# 是否禁止公网 (WAN) 访问 Web 控制台
not_allow_wan_access: true

# 自定义抗污染 DNS 服务器 (选填，留空使用系统默认)
dns_server: "223.5.5.5"

# Web 登录认证配置
auth:
  username: "admin"
  password_hash: "$2b$12$..." # BCrypt 加密哈希

# 多任务列表
dns_tasks:
  - name: "主宽带动态解析"
    enabled: true
    ttl: 600
    http_interface: "eth0" # 绑定的出站物理网卡 (可选)
    provider:
      type: "cloudflare"
      api_token: "your-cloudflare-token"
    ipv4:
      enabled: true
      source_type: "url"
      url_endpoints:
        - "https://api.ipify.org"
      domains:
        - "nas.example.com"
    ipv6:
      enabled: true
      source_type: "net_interface"
      net_interface: "eth0"
      regex: "@1" # 快捷匹配第 1 个公网 IPv6
      domains:
        - "nas-v6.example.com"

# 通知推送配置
notifications:
  dingtalk:
    enabled: true
    webhook_url: "https://oapi.dingtalk.com/robot/send?access_token=..."
    secret: "SEC..."
```

---

## 💖 致谢 (Acknowledgments)

- **[ddns-go](https://github.com/jeessy2/ddns-go)**：提供了卓越的 DDNS 交互设计与功能参考标杆。
- **[Tokio](https://tokio.rs/) & [Axum](https://github.com/tokio-rs/axum)**：构建可靠异步并发与高性能 Web 服务的基石。
- **[reqwest](https://github.com/seanmonstar/reqwest)**：强大优雅的 Rust HTTP 客户端。

---

## 📄 开源许可证

本项目基于 [MIT 许可证](LICENSE) 开源发布。
