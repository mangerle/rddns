<div align="center">

<img src="assets/logo-badge.svg" height="46" alt="RDDNS" style="margin-bottom: 12px;" />

**基于纯 Rust 打造的高性能、极轻量、全功能动态域名解析（DDNS）与告警服务**

<p align="center">
  <b>简体中文</b> | <a href="README.md">English</a>
</p>

[![Rust](https://img.shields.io/badge/Rust-2024_Edition-orange.svg?logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-brightgreen.svg)]()
[![Memory](https://img.shields.io/badge/Memory-~2.9_MB_Private-success.svg)]()
[![Single Binary](https://img.shields.io/badge/Binary-Single_Self--Contained-blueviolet.svg)]()

</div>

---

## 项目背景与致敬

本项目在架构设计、功能交互与用户体验上深度参考并致敬了优秀的开源项目 **[ddns-go](https://github.com/jeessy2/ddns-go)**。

在传承其优秀特性的基础上，`rddns` 采用 **纯 Rust（2024 Edition + Tokio 异步运行时 + Axum Web 框架）** 进行了全新重构与深度优化，彻底去除外部运行时与垃圾回收（GC）开销，追求极致的**低资源消耗、高吞吐并发与零依赖单文件绿色自包含分发**。

---

## 核心特性

- **极致轻量与高性能**：
  - **实测私有常驻内存（Private Bytes）仅约 2.9 MB**，物理工作集约 10.5 MB；
  - 采用纯 Rust 零成本抽象与 RAII 内存管理，无 GC 停顿与内存膨胀风险；
  - 启动毫秒级响应，即使在 64MB / 128MB 的老旧嵌入式路由器（如 OpenWrt）、轻量 VPS 或 NAS 设备上亦可从容常驻。
- **单文件绿色自包含**：
  - 前端 Web 响应式控制台与 CA 根证书全量嵌入二进制，单可执行文件双击即用，无需安装任何额外依赖或运行时环境。
- **多任务主从管理 (Master-Detail)**：
  - 现代化双栏响应式管理界面，支持独立配置多条 DDNS 同步任务；
  - 每个任务均可独立分配服务商、出站网卡、域名列表、TTL 及双栈解析策略。
- **全场景双栈 IP 探测能力**：
  - **URL 接口提取**：内置多个高可用公共 IP 查询接口，支持自定义 URL 列表与正则表达式精准提取；
  - **网卡设备直读**：自动枚举系统物理与虚拟网卡，支持 `@1`、`@2` 序号语法快捷选取指定 IPv6 地址；
  - **系统脚本/命令**：支持执行自定义 Shell / PowerShell 命令或外部脚本获取 IP。
- **多 WAN 软路由出口绑定 (HttpInterface)**：
  - 支持按任务指定绑定的出站物理网卡（如 `eth0`、`pppoe-wan`），多宽带聚合、策略路由及软路由多拨环境下的刚需利器。
- **网络抗污染与自定义 DNS**：
  - 内置纯 Rust 异步 DNS UDP 查询器，支持命令行 `--dns` 及 Web 控制台配置公共 DNS 节点（如 `223.5.5.5`、`1.1.1.1`），直连递归解析，彻底规避运营商 Local DNS 劫持与缓存污染。
- **支持 25 款主流 DNS 服务商（纯 Rust 驱动与算法签名）**：
  - **主流云厂商**：Cloudflare、阿里云 (AliDNS)、腾讯云 (DNSPod)、华为云 (Huawei Cloud)、百度智能云 (Baidu Cloud)、火山引擎 (TrafficRoute)；
  - **海外注册商**：Porkbun、GoDaddy、Namecheap、NameSilo、Spaceship、Dynadot、Name.com、Gcore、Dynv6、ClouDNS、NS1 Connect (IBM NS1)；
  - **边缘加速与云托管**：阿里云 ESA (边缘安全加速)、腾讯云 EdgeOne (含动态源站组 OriginGroup 同步)、Vercel (含团队 teamId 支持)、雨云 (RainYun)、DNS.LA；
  - **国内传统专线与自建**：时代互联 (Now.cn / Eranet / TNetHK)、HiPM DNSMgr (自建 DNS 管理系统)、通用自定义 Webhook Callback。
- **8 大主流渠道实时告警通知**：
  - **企业微信**：支持群机器人 Webhook 及企业自建应用 API 消息推送；
  - **飞书**：支持群机器人 Webhook（支持加签校验与交互式卡片消息）；
  - **钉钉**：支持群机器人 Webhook（支持 Secret 加签校验）；
  - **微信公众号**：官方原生模板消息直达个人微信；
  - **Telegram**：支持 Telegram Bot 实时通知；
  - **Bark**：iOS 极速即时推送（支持分组、自定义图标与铃声）；
  - **SMTP 邮件**：纯 Rust 异步 TLS 发送（支持 STARTTLS 与优雅 HTML 模板）；
  - **通用自定义 Webhook**：支持自定义 HTTP 请求头、请求体模板及占位符自动替换。
- **安全加固与运维保障**：
  - **敏感凭据脱敏保护**：前端配置获取接口全面脱敏掩码化，杜绝 Token/Secret 被二次窥探；
  - **访问控制**：Web 管理员登录密码采用 BCrypt 强哈希加密存储；
  - **WAN 隔离防护**：支持一键禁止公网访问 Web 控制台（仅限内网管理）；
  - **开机网络等待防假死**：智能并发探测网络连通性后再启动同步；
  - **运维便捷性**：支持一键重置密码（`--resetPassword`）、跳过证书校验（`--skipVerify`）、在线自更新（`--upgrade`）。

---

## 资源与内存占用实测

基于 64 位操作系统在 Release 优化构建下的实测数据：

| 运行模式 | 二进制体积 | 私有提交内存 (Private Bytes) | 物理工作集 (Working Set) | 运行时依赖 |
| :--- | :---: | :---: | :---: | :---: |
| **完整 Web 管理模式** | ~5.6 MB | **~2.93 MB** | ~10.53 MB | 无（单文件静态） |
| **纯后台静默模式 (`--noweb`)** | ~5.6 MB | **~2.88 MB** | ~10.35 MB | 无（单文件静态） |

> *注：Working Set 包含操作系统共享动态链接库与系统 API 映射，真实应用程序常驻占用的私有物理提交内存仅约 2.9 MB。*

---

## 安装与部署

### 方式 1：直接下载预编译二进制（推荐）

前往 [GitHub Releases](https://github.com/mangerle/rddns/releases) 下载适用于您系统架构的预编译归档：

| 平台 / 架构 | 适用设备与场景 | 二进制特性 |
| :--- | :--- | :--- |
| **Linux x86_64** (`x86_64-unknown-linux-musl`) | 常见 64 位 PC、云服务器、x86 软路由、NAS | 纯静态 musl 编译，零依赖兼容所有发行版与 Alpine/OpenWrt |
| **Linux ARM64** (`aarch64-unknown-linux-musl`) | 树莓派 4/5、ARM 软路由、各类 ARM64 架构设备 | 纯静态 musl 编译，零系统库依赖 |
| **Linux ARMv7** (`armv7-unknown-linux-musleabihf`) | 早期 32 位树莓派、老旧 32 位 ARM 路由器 | 纯静态 musl 编译 |
| **Windows 64位** (`x86_64-pc-windows-msvc`) | Windows 10 / 11 / Server | 原生绿色单文件，解压即用 |
| **macOS Apple Silicon** (`aarch64-apple-darwin`) | Apple M 系列芯片 Mac (M1/M2/M3/M4) | 原生 ARM64 架构 |
| **macOS Intel** (`x86_64-apple-darwin`) | Intel 处理器 Mac | 原生 x86_64 架构 |

下载解压后赋予执行权限即可直接运行：
```bash
chmod +x rddns
./rddns
```

---

### 方式 2：系统服务一键管理 (开机自启与后台守护)

`rddns` 内置了原生跨平台系统服务管理器，支持自动注册为系统后台自启服务：

```bash
# 1. 一键安装并注册为系统开机自启服务
./rddns -s install

# 2. 启动服务
./rddns -s start

# 3. 查看服务运行状态
./rddns -s status

# 4. 重启服务
./rddns -s restart

# 5. 停止服务
./rddns -s stop

# 6. 卸载服务
./rddns -s uninstall
```

- **Linux**：自动创建并管理 `/etc/systemd/system/rddns.service`，通过 `systemd` 守护；
- **Windows**：自动注册 Windows 高权限计划任务与服务守护，开机或登录后无黑框静默常驻；
- **macOS**：自动生成 `~/Library/LaunchAgents/com.rddns.service.plist`，由 `launchd` 托管。

---

### 方式 3：守护进程模式运行 (Daemon)

在不需要注册系统服务的情况下，您也可以通过 `-d` / `--daemon` 参数让程序派生独立后台进程并自动退出当前终端：

```bash
./rddns -d
```

---

### 方式 4：在线一键自动升级

`rddns` 具备在线自检测与热更新能力，会自动匹配当前运行平台的架构包并完成替换：

```bash
./rddns -u
# 或
./rddns --upgrade
```

---

### 方式 5：Docker 部署

您也可以使用 Docker 或 Docker Compose 进行容器化部署：

#### 命令行运行
```bash
docker run -d \
  --name rddns \
  --restart always \
  --net host \
  -v /etc/rddns:/.rddns_config.yaml \
  mangerle/rddns:latest
```

#### Docker Compose
```yaml
services:
  rddns:
    image: mangerle/rddns:latest
    container_name: rddns
    restart: always
    network_mode: host
    volumes:
      - ./data:/app/data
    environment:
      - TZ=Asia/Shanghai
```

> *提示：建议使用 `network_mode: host`，以便直接读取宿主机物理网卡接口与公网 IPv6 地址。*

---

### 方式 6：源码编译安装

确保本地已安装 [Rust 工具链](https://rustup.rs/)（建议 Rust 1.85+）：

```bash
# 克隆仓库
git clone https://github.com/mangerle/rddns.git
cd rddns

# 编译极致优化 Release 版本
cargo build --release
```

编译输出位于 `target/release/rddns`（Windows 下为 `rddns.exe`）。

---

## 常用运行示例

```bash
# 1. 默认前台启动（监听 http://0.0.0.0:9876）
./rddns

# 2. 自定义监听端口（支持 -p 或 -l）
./rddns -p 8888

# 3. 纯后台静默同步模式（不开启 Web 服务，节省更多内存）
./rddns --noweb

# 4. 指定公共抗污染 DNS 节点进行域名解析比对
./rddns --dns 223.5.5.5

# 5. 调整同步检查轮询周期（例如 120 秒）
./rddns -f 120

# 6. 忘记 Web 登录密码时一键重置
./rddns --resetPassword MyNewPassword123
```

启动后在浏览器中打开 `http://localhost:9876` 即可进入 Web 管理控制台。

---

## 命令行参数速查

| 参数 | 短参数 | 别名 | 默认值 | 说明 |
| :--- | :---: | :---: | :---: | :--- |
| `--config <PATH>` | `-c` | - | `.rddns_config.yaml` | 配置文件路径（优先读取当前目录或程序所在目录） |
| `--listen <ADDR>` | `-l` | `-p`, `--port` | `9876` | Web 控制台监听地址或端口（如 `8888` 或 `127.0.0.1:8888`） |
| `--frequency <SECS>` | `-f` | - | `300` | 同步轮询周期（秒，仅覆盖当前运行时） |
| `--noweb` | - | - | `false` | 纯静默后台同步模式（不开启 Web 控制台） |
| `--dns <SERVER>` | - | - | - | 指定抗污染递归 DNS 服务器（如 `223.5.5.5` 或 `1.1.1.1:53`） |
| `--skip-verify` | - | `--skipVerify` | `false` | 跳过 HTTPS/TLS 证书有效性校验（内网或自签名场景） |
| `--reset-password <PASS>` | - | `--resetPassword` | - | 一键重置 Web 控制台管理员登录密码并立即退出 |
| `--daemon` | `-d` | - | `false` | 以系统独立后台守护进程（Daemon）模式运行并退出父终端 |
| `--upgrade` | `-u` | - | `false` | 在线检测并自动升级至 GitHub 最新发布版本 |
| `--service <ACTION>` | `-s` | - | - | 系统自启服务管理（`install` / `uninstall` / `start` / `stop` / `restart` / `status`） |
| `--help` | `-h` | - | - | 打印帮助信息 |
| `--version` | `-V` | - | - | 打印版本信息 |

---

## 配置文件示例 (`.rddns_config.yaml`)

```yaml
# Web 控制台监听端口
listen_port: 9876

# 全局定时同步周期 (秒)
interval_secs: 300

# 连续 IP 未发生变动时的远程记录校对周期 (每 N 次同步执行一次远程比对)
cache_times: 10

# 是否禁止公网 (WAN) 访问 Web 管理界面
not_allow_wan_access: true

# 自定义抗污染 DNS 解析服务器 (留空使用系统默认)
dns_server: "223.5.5.5"

# Web 管理员认证配置
auth:
  username: "admin"
  password_hash: "$2b$12$..." # BCrypt 安全哈希

# 多任务配置列表
dns_tasks:
  - name: "主宽带-Cloudflare解析"
    enabled: true
    ttl: 600
    http_interface: "eth0" # 绑定的出站物理网卡 (可选，用于软路由多 WAN)
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
      regex: "@1" # 快捷选取第 1 个公网 IPv6 地址
      domains:
        - "nas-v6.example.com"

  - name: "副宽带-阿里云解析"
    enabled: true
    ttl: 600
    http_interface: "pppoe-wan2"
    provider:
      type: "alidns"
      access_key_id: "your-aliyun-ak"
      access_key_secret: "your-aliyun-sk"
    ipv4:
      enabled: true
      source_type: "url"
      url_endpoints:
        - "https://myip4.ipip.net"
      domains:
        - "backup.example.com"

# 告警通知配置 (支持多渠道同时开启)
notifications:
  feishu:
    enabled: true
    webhook_url: "https://open.feishu.cn/open-apis/bot/v2/hook/..."
    secret: "your-feishu-secret"
  dingtalk:
    enabled: true
    webhook_url: "https://oapi.dingtalk.com/robot/send?access_token=..."
    secret: "SEC..."
  wecom:
    enabled: false
    webhook_url: "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=..."
  bark:
    enabled: false
    server_url: "https://api.day.app/your-key"
  mail:
    enabled: false
    smtp_server: "smtp.example.com"
    smtp_port: 465
    username: "notify@example.com"
    password: "your-smtp-password"
    to: "admin@example.com"
```

---

## 致谢

- **[ddns-go](https://github.com/jeessy2/ddns-go)**：提供了卓越的 DDNS 交互设计与功能标杆。
- **[Tokio](https://tokio.rs/) & [Axum](https://github.com/tokio-rs/axum)**：构建极速异步并发与现代化 Web 服务的基石。
- **[reqwest](https://github.com/seanmonstar/reqwest)**：优雅强大的 Rust HTTP 客户端。

---

## 开源许可证

本项目基于 [MIT 许可证](LICENSE) 开源发布。
