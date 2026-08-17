<div align="center">

**基于纯 Rust 打造的高性能、轻量级、全功能动态域名解析（DDNS）与告警服务**

[![Rust](https://img.shields.io/badge/Rust-2024_Edition-orange.svg?logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-brightgreen.svg)]()
[![Single Binary](https://img.shields.io/badge/Binary-Single_Self--Contained-success.svg)]()

</div>

---

## ✨ 核心特性

- ⚡ **纯 Rust 原生高性能**：极低内存占用（常驻运行仅约 10~15 MB），毫秒级极速响应，无需 Python/Node.js/Java 等任何额外运行时环境。
- 📦 **单文件自包含**：静态资源内置嵌入，一个二进制可执行文件即可独立运行全部 Web 管理控制台与核心守护进程。
- 🌐 **双栈 IPv4 / IPv6 全支持**：
  - **URL 接口探测**：内置与自定义多接口轮询容灾，支持自定义正则精确提取。
  - **本地网卡枚举**：自动识别物理网卡与虚拟网卡，原生获取本机公网/内网 IPv4 / IPv6 地址。
  - **自定义脚本/命令**：支持执行任意系统命令与 Shell 脚本提取 IP。
- ☁️ **多云 DNS 服务商原生驱动（纯 Rust 算法签名）**：
  - **Cloudflare**：支持 API Token 与 Global API Key 鉴权，支持保留/配置小黄云 CDN 代理状态，TTL 智能匹配。
  - **阿里云 (AliDNS)**：内置纯 Rust 实现的 POP HMAC-SHA1 规范签名，零官方重型 SDK 依赖。
  - **腾讯云 (DNSPod)**：内置纯 Rust 实现的 TC3-HMAC-SHA256 规范签名。
  - **自定义 Callback**：支持向任意私有 DNS 或第三方 Webhook 发起自定义请求。
- 🖥️ **现代一体化 Web UI**：
  - 支持暗黑/明亮主题一键切换。
  - 实时 SSE 日志流推送与动态控制台。
  - 在线实时 IP 连通性探测、网卡一键下拉选择。
  - 智能 TTL 预设阶梯（支持 1秒、10分钟、1小时等快速选择与自定义输入）。
  - 支持一键手动触发立即同步。
- 📢 **多通道实时通知推送**：
  - 钉钉机器人（支持加签鉴权）
  - 飞书机器人（支持签名校验）
  - 企业微信机器人（支持 Webhook 与应用消息）
  - Server酱（支持 Turbo 通道）
  - Telegram Bot
  - 邮件 SMTP（基于 `lettre` 驱动，支持 SSL/STARTTLS 与主流邮箱快捷预设）
  - 自定义通知 Webhook
- 🛡️ **安全防护**：
  - 密码认证登录（基于 BCrypt 加密存储）。
  - **禁止公网访问保护**（WAN 安全拦截）：一键开启局域网/本机独占模式，防止控制台意外暴露。

---

## 🛠️ 快速开始

### 1. 编译与打包

确保已安装 [Rust 工具链](https://rustup.rs/)：

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

# 自定义监听地址与配置文件路径
./target/release/rddns -l 127.0.0.1:9876 -c /etc/rddns/config.yaml

# 纯后台静默模式（不启动 Web 界面）
./target/release/rddns --noweb
```

启动后在浏览器中访问 `http://localhost:9876` 即可进入 Web 管理面板。

---

## 💻 命令行参数详解

| 参数 | 短参数 | 默认值 | 说明 |
| :--- | :---: | :---: | :--- |
| `--config <PATH>` | `-c` | `.rddns_config.yaml` | 自定义配置文件读取与保存路径 |
| `--listen <ADDR>` | `-l` | `0.0.0.0:9876` | 自定义 Web 服务监听地址与端口 |
| `--frequency <SECS>` | `-f` | `300` | 覆盖定时同步检查间隔（秒） |
| `--noweb` | - | `false` | 禁用 Web 管理面板，仅作为后台守护进程运行 |
| `--reset-password <PASS>` | - | - | 快速重置 Web 控制台管理员密码并立即退出 |

---

## ⚙️ 配置文件说明 (`.rddns_config.yaml`)

项目支持在 Web 控制台直观配置，同时也支持直接编辑 YAML 配置文件：

```yaml
# 全局同步检查周期 (秒)
interval_secs: 300

# 连续失败/未变化时的缓存衰减倍数
cache_times: 10

# 是否禁止公网 (WAN) 访问 Web 控制台
not_allow_wan_access: false

# Web 登录认证配置
auth:
  username: "admin"
  password_hash: "$2b$12$..." # BCrypt 加密哈希

# DNS 同步任务列表
dns_tasks:
  - name: "主域名同步任务"
    ttl: 600
    provider:
      type: "cloudflare" # cloudflare | ali_dns | tencent_cloud | callback
      api_token: "your-cloudflare-api-token"
    ipv4:
      enabled: true
      source_type: "url" # url | net_interface | cmd
      url_endpoints:
        - "https://api.ipify.org"
        - "https://ipv4.icanhazip.com"
      domains:
        - "ddns.example.com"
        - "@.example.com"
    ipv6:
      enabled: false
      source_type: "net_interface"
      net_interface: "eth0"
      domains:
        - "v6.example.com"

# 通知推送配置
notifiers:
  dingtalk:
    enabled: true
    webhook_url: "https://oapi.dingtalk.com/robot/send?access_token=..."
    secret: "SEC..."
```

---

## 📦 二进制体积进一步压缩建议

本项目默认已在 `[profile.release]` 中启用了 `opt-level = "z"`, `lto = true`, `codegen-units = 1`, `panic = "abort"` 以及符号表剥离 `strip = true`。

如需进一步极致压缩（由 ~4.3MB 压至 ~1.5MB），可使用 **UPX** 壳压缩工具：

```bash
# 使用 UPX 进行 LZMA 极限压缩
upx --best --lzma target/release/rddns.exe
```

---

## 📄 开源许可证

本项目基于 [MIT 许可证](LICENSE) 开源发布。
