<div align="center">

<img src="assets/logo-badge.svg" height="46" alt="RDDNS" style="margin-bottom: 12px;" />

**A high-performance, ultra-lightweight, and full-featured Dynamic DNS (DDNS) and notification service written in pure Rust**

<p align="center">
  <a href="README_zh.md">简体中文</a> | <b>English</b>
</p>

[![Rust](https://img.shields.io/badge/Rust-2024_Edition-orange.svg?logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-brightgreen.svg)]()
[![Memory](https://img.shields.io/badge/Memory-~2.9_MB_Private-success.svg)]()
[![Single Binary](https://img.shields.io/badge/Binary-Single_Self--Contained-blueviolet.svg)]()

</div>

---

## Project Background & Tribute

`rddns` draws deep architectural and user experience inspiration from the outstanding open-source project **[ddns-go](https://github.com/jeessy2/ddns-go)**.

Building upon its battle-tested workflow, `rddns` is rewritten entirely in **pure Rust (2024 Edition + Tokio async runtime + Axum web framework)** with zero GC overhead, offering **ultra-low memory footprint, high-throughput concurrency, and single self-contained binary distribution**.

---

## Key Features

- **Ultra-lightweight & High Performance**:
  - **Private memory usage is only ~2.9 MB** (Physical working set ~10.5 MB);
  - Zero-cost abstractions and RAII memory management in pure Rust, eliminating garbage collection pauses and memory bloat;
  - Millisecond-level startup response, running comfortably on 64MB / 128MB low-end embedded routers (e.g. OpenWrt), lightweight VPSs, or NAS devices.
- **Single Self-Contained Binary**:
  - Web dashboard frontend assets and trusted CA root certificates are fully embedded inside the executable. No external runtimes or dependencies needed.
- **Multi-Task Master-Detail Management**:
  - Modern responsive dual-pane dashboard with independent configurations for multiple DDNS synchronization tasks;
  - Each task can independently specify DNS provider, outbound network interface, domain list, TTL, and dual-stack strategies.
- **Comprehensive Dual-Stack IP Detection**:
  - **URL Endpoints**: Built-in high-availability public IP query endpoints, supporting custom URL lists and regular expression matching;
  - **Network Interface Direct Reading**: Automatic enumeration of system physical and virtual interfaces, with `@1`, `@2` indexing syntax to select specific IPv6 addresses;
  - **System Script / Command**: Execute custom Shell / PowerShell commands or external scripts to retrieve IPs.
- **Multi-WAN Router Interface Binding (`HttpInterface`)**:
  - Bind individual tasks to specific outbound physical interfaces (such as `eth0`, `pppoe-wan`), essential for multi-WAN load balancing and policy routing.
- **Anti-Pollution & Custom DNS Resolution**:
  - Built-in pure Rust async DNS resolver, supporting `--dns` CLI parameter and Web UI configuration for custom upstream DNS servers (e.g. `223.5.5.5`, `1.1.1.1`), directly querying authoritative servers to bypass local ISP DNS hijacking and cache poisoning.
- **Supports 25 Mainstream DNS Providers (Pure Rust drivers & signatures)**:
  - **Global Cloud Providers**: Cloudflare, Alibaba Cloud (AliDNS), Tencent Cloud (DNSPod), Huawei Cloud, Baidu Cloud, Volcano Engine (TrafficRoute);
  - **Domain Registrars**: Porkbun, GoDaddy, Namecheap, NameSilo, Spaceship, Dynadot, Name.com, Gcore, Dynv6, ClouDNS, NS1 Connect (IBM NS1);
  - **Edge & Cloud Hosting**: Alibaba Cloud ESA, Tencent Cloud EdgeOne (supports dynamic OriginGroup syncing), Vercel (with teamId support), RainYun, DNS.LA;
  - **Dedicated & Self-Hosted**: Now.cn / Eranet / TNetHK, HiPM DNSMgr, and Generic Custom Webhook Callbacks.
- **8 Major Notification Channels**:
  - **WeCom (Enterprise WeChat)**: Group bot Webhooks & Corporate App API messaging;
  - **Feishu / Lark**: Group bot Webhooks with secret signatures and interactive card messages;
  - **DingTalk**: Group bot Webhooks with secret signing;
  - **WeChat Official Account**: Native template messages directly delivered to personal WeChat;
  - **Telegram**: Real-time push notifications via Telegram Bot;
  - **Bark**: iOS instant push notification (supports grouping, custom icons, and ringtones);
  - **SMTP Email**: Pure Rust async TLS mail delivery (supports STARTTLS and HTML templates);
  - **Custom Webhook**: Customizable HTTP headers, request body templates, and dynamic placeholder substitutions.
- **Security Hardening & Operations**:
  - **Credential Masking**: Web configuration APIs automatically mask tokens and secrets to prevent sniffing;
  - **Access Control**: Web admin credentials hashed using BCrypt;
  - **WAN Access Isolation**: One-click toggle to disable WAN access to the Web console (LAN-only management);
  - **Startup Network Probing**: Concurrent network connectivity probing before running DDNS sync loops;
  - **Operational Utilities**: Password reset (`--resetPassword`), skip TLS certificate verification (`--skipVerify`), and online auto-upgrade (`--upgrade`).

---

## Resource & Memory Benchmarks

Tested on a 64-bit operating system with Release optimization profile:

| Running Mode | Binary Size | Private Committed Bytes | Working Set | Runtime Dependencies |
| :--- | :---: | :---: | :---: | :---: |
| **Full Web Management Mode** | ~5.6 MB | **~2.93 MB** | ~10.53 MB | None (Single Static Binary) |
| **Silent Background Sync (`--noweb`)** | ~5.6 MB | **~2.88 MB** | ~10.35 MB | None (Single Static Binary) |

> *Note: Working Set includes OS shared dynamic libraries and system API mappings. The actual private heap and stack committed by the application is only ~2.9 MB.*

---

## Installation & Deployment

### Method 1: Download Pre-compiled Binary (Recommended)

Download the pre-compiled binary for your architecture from [GitHub Releases](https://github.com/mangerle/rddns/releases):

| Platform / Architecture | Recommended Devices | Binary Characteristics |
| :--- | :--- | :--- |
| **Linux x86_64** (`x86_64-unknown-linux-musl`) | 64-bit PC, Cloud VPS, x86 Soft Router, NAS | Statically linked with musl, compatible with all distros, Alpine & OpenWrt |
| **Linux ARM64** (`aarch64-unknown-linux-musl`) | Raspberry Pi 4/5, ARM Routers, ARM64 Servers | Statically linked with musl, zero shared library dependencies |
| **Linux ARMv7** (`armv7-unknown-linux-musleabihf`) | Raspberry Pi 2/3, 32-bit ARM Routers | Statically linked with musl |
| **Windows 64-bit** (`x86_64-pc-windows-msvc`) | Windows 10 / 11 / Server | Native standalone executable |
| **macOS Apple Silicon** (`aarch64-apple-darwin`) | Apple Silicon Mac (M1/M2/M3/M4) | Native ARM64 binary |
| **macOS Intel** (`x86_64-apple-darwin`) | Intel-based Mac | Native x86_64 binary |

Extract the archive and run:
```bash
chmod +x rddns
./rddns
```

---

### Method 2: System Service Management (Auto-start on boot)

`rddns` includes a cross-platform service manager to register and run as a system daemon:

```bash
# 1. Install and register as a system service
./rddns -s install

# 2. Start service
./rddns -s start

# 3. Check service status
./rddns -s status

# 4. Restart service
./rddns -s restart

# 5. Stop service
./rddns -s stop

# 6. Uninstall service
./rddns -s uninstall
```

- **Linux**: Automatically creates and manages `/etc/systemd/system/rddns.service` via `systemd`;
- **Windows**: Registers a background scheduled task/service with high privileges;
- **macOS**: Generates `~/Library/LaunchAgents/com.rddns.service.plist` managed by `launchd`.

---

### Method 3: Run as Daemon

Run in background daemon mode without installing a system service:

```bash
./rddns -d
```

---

### Method 4: Online Self-Upgrade

`rddns` can automatically detect the latest release from GitHub and replace its binary in-place:

```bash
./rddns -u
# or
./rddns --upgrade
```

---

### Method 5: Docker Deployment

Deploy with Docker or Docker Compose:

#### Command Line
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

> *Tip: Using `network_mode: host` is recommended so the application can directly read physical network interfaces and public IPv6 addresses.*

---

### Method 6: Build from Source

Ensure you have the [Rust toolchain](https://rustup.rs/) installed (Rust 1.85+ recommended):

```bash
# Clone the repository
git clone https://github.com/mangerle/rddns.git
cd rddns

# Build with maximum release optimizations
cargo build --release
```

The compiled binary will be located at `target/release/rddns` (`rddns.exe` on Windows).

---

## Quick Start Examples

```bash
# 1. Default foreground start (listens on http://0.0.0.0:9876)
./rddns

# 2. Custom listening port
./rddns -p 8888

# 3. Silent background mode (disable Web UI to minimize memory usage)
./rddns --noweb

# 4. Use custom upstream anti-pollution DNS resolver
./rddns --dns 223.5.5.5

# 5. Set check interval to 120 seconds
./rddns -f 120

# 6. Reset Web console admin password
./rddns --resetPassword MyNewPassword123
```

Open `http://localhost:9876` in your browser to access the Web Management Console.

---

## CLI Options Reference

| Parameter | Short | Alias | Default | Description |
| :--- | :---: | :---: | :---: | :--- |
| `--config <PATH>` | `-c` | - | `.rddns_config.yaml` | Path to configuration file |
| `--listen <ADDR>` | `-l` | `-p`, `--port` | `9876` | Web console listening address or port (e.g. `8888` or `127.0.0.1:8888`) |
| `--frequency <SECS>` | `-f` | - | `300` | Sync check interval in seconds (runtime override) |
| `--noweb` | - | - | `false` | Silent background mode (disable Web UI) |
| `--dns <SERVER>` | - | - | - | Custom upstream DNS server (e.g. `223.5.5.5` or `1.1.1.1:53`) |
| `--skip-verify` | - | `--skipVerify` | `false` | Skip HTTPS/TLS certificate verification |
| `--reset-password <PASS>` | - | `--resetPassword` | - | Reset Web admin password and exit immediately |
| `--daemon` | `-d` | - | `false` | Run as detached background daemon and exit terminal |
| `--upgrade` | `-u` | - | `false` | Check for updates and upgrade to the latest GitHub release |
| `--service <ACTION>` | `-s` | - | - | Manage system service (`install`, `uninstall`, `start`, `stop`, `restart`, `status`) |
| `--help` | `-h` | - | - | Print help information |
| `--version` | `-V` | - | - | Print version information |

---

## Configuration File (`.rddns_config.yaml`)

```yaml
# Web console listen port
listen_port: 9876

# Global synchronization interval (seconds)
interval_secs: 300

# Remote record check frequency when local IP has not changed (checks cloud every N intervals)
cache_times: 10

# Disallow WAN access to Web management dashboard (LAN-only)
not_allow_wan_access: true

# Custom anti-pollution upstream DNS server (leave blank to use system default)
dns_server: "223.5.5.5"

# Web dashboard authentication
auth:
  username: "admin"
  password_hash: "$2b$12$..." # BCrypt hash

# Multi-task configuration
dns_tasks:
  - name: "Main-WAN-Cloudflare"
    enabled: true
    ttl: 600
    http_interface: "eth0" # Bound outbound physical interface (optional, for multi-WAN)
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
      regex: "@1" # Select 1st public IPv6 address
      domains:
        - "nas-v6.example.com"

  - name: "Secondary-WAN-AliDNS"
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

# Notification settings (multiple channels can be enabled simultaneously)
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

## Acknowledgements

- **[ddns-go](https://github.com/jeessy2/ddns-go)**: Exceptional DDNS design and functional benchmark.
- **[Tokio](https://tokio.rs/) & [Axum](https://github.com/tokio-rs/axum)**: Foundation for lightning-fast asynchronous concurrency and modern web services.
- **[reqwest](https://github.com/seanmonstar/reqwest)**: Elegant and robust HTTP client for Rust.

---

## License

This project is licensed under the [MIT License](LICENSE).
