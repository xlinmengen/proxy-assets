# Infra-Red Assets · 代理管理与穿透控制台

<p align="center">
  <img src="https://img.shields.io/badge/status-stable-brightgreen">
  <img src="https://img.shields.io/badge/Xray-Reality-1f8ef5">
  <img src="https://img.shields.io/badge/FRP-0.69.1-ff9800">
  <img src="https://img.shields.io/badge/Flask-3.0.3-000000">
  <img src="https://img.shields.io/badge/gRPC-1.78.0-00bcd4">
  <img src="https://img.shields.io/badge/license-MIT-blue">
</p>

**Infra-Red Assets** 是一个面向自建代理与内网穿透的一体化控制面板，专为境外 VPS 环境设计。它整合了 **Xray (Reality 协议)**、**FRP 内网穿透**、**流量监控**、**用户分级管理** 以及 **Web 管理界面**，提供从部署到运维的完整闭环。

---

## ✨ 核心特性

| 类别 | 特性 |
| :--- | :--- |
| **代理服务** | Xray Reality (VLESS + TCP) / 多用户隔离 / 等级化策略 / 高并发优化 |
| **内网穿透** | FRP 服务端 / OIDC 认证 / 支持 TCP 隧道 / 支持 wireProtocol v2 (AEAD 加密) |
| **管理面板** | 用户 CRUD / 实时流量图表 / 一键配置下载 / 设备感知导入 / 独立密码保护 / DDoS 防护 |
| **资源代理** | GeoIP / GeoSite / 客户端安装包 / 规则集（内置 CDN 回源） |
| **安全与证书** | 自动生成自签名 CA / 动态签发服务器证书 / 强制 HTTPS |
| **可观测性** | gRPC 流量统计（实时速率 + 累计用量） / 月度自动重置 / 系统指标 / 邮件告警 |

---

## 🧩 组件关系

- **Xray** 提供 Reality 协议代理服务（端口 `443`），支持多用户、多等级策略，并通过 gRPC API（端口 `15`）暴露流量统计数据。
- **FRP** 作为内网穿透服务端（端口 `10`），认证方式为 OIDC，与 Xray 路由联动（可将特定域名流量转入 FRP 隧道）。
- **Monitor** 是基于 Flask 的 Web 面板（端口 `1000`），负责用户管理、配置生成、证书签发、流量可视化，并通过 gRPC 与 Xray 通信。面板内置 DDoS 防护、SMTP 邮件告警和 OIDC 认证服务。
- **FRPX** 是 Rust 编写的跨平台 FRPC 客户端管理工具，与服务端配合使用，提供自动配置、进程守护和证书管理功能。

---

## 🚀 快速部署

### 环境要求

- Linux (Debian/Ubuntu 20.04+ 推荐)
- root 权限
- 开放端口：`10`、`443`、`1000`

### 一键安装

```bash
bash <(curl -sSL https://raw.githubusercontent.com/xlinmengen/proxy-assets/main/setup.sh)
```

安装过程会交互式提示输入：

- 管理员邮箱
- 管理员密码

### 安装后访问

| 服务 | 地址 | 说明 |
| :--- | :--- | :--- |
| Web 管理面板 | `https://<VPS_IP>:1000` | 用户管理 / 流量监控 / 配置下载 |
| FRP 管理面板 | `http://127.0.0.1:1020` | FRP 服务端状态（仅限本地访问，用户名/密码同管理员） |
| CA 证书下载 | `https://<VPS_IP>:1000/cert` | 用于客户端信任自签名证书 |

> ⚠️ 首次访问需手动信任自签名证书（浏览器会提示不安全，添加例外即可）。

> 💡 FRP 管理面板端口 `1020` 默认仅监听本地，如需外部访问请手动开放防火墙。

---

## 👥 用户体系与等级

系统内置三档用户等级，对应不同的 xray 策略与缓存配置：

| 等级 | 权限类型 | xray 等级 | 缓冲区 (bufferSize) | 适用场景 |
| :--- | :--- | :--- | :--- | :--- |
| 0 | 管理员 | 0 (顶级) | 16 MiB | 全权限管理，高吞吐需求 |
| 1 | 普通用户 | 1 (优质) | 8 MiB | 常规使用，中等流量 |
| 2 | 普通用户 | 2 (标准) | 4 MiB | 基础使用，低资源消耗 |

- **管理员**：可增删用户、重置密钥、修改全局认证、查看所有流量。
- **普通用户**：仅可查看自己的流量、下载配置、修改密码。

---

## 📦 内置组件与版本

| 组件 | 版本 | 用途 |
| :--- | :--- | :--- |
| [Xray-core](https://github.com/XTLS/Xray-core) | 26.3.27+ | 代理核心 (Reality 协议) |
| [FRP](https://github.com/fatedier/frp) | 0.69.1 | 内网穿透服务端 (支持 wireProtocol v2) |
| [Flask](https://flask.palletsprojects.com/) | 3.0.3 | Web 框架 |
| [gRPC](https://grpc.io/) | 1.78.0 | 与 Xray API 通信 |
| [Granian](https://github.com/emmett-framework/granian) | latest | 高性能 WSGI 服务器 |
| [cryptography](https://cryptography.io/) | latest | 证书生成与处理 |
| [FRPX](https://github.com/xlinmengen/proxy-assets) | 1.0.0 | Rust 编写的 FRPC 客户端管理工具 (跨平台) |

---

## 📱 客户端集成

### 一键导入（自动识别设备）

Web 面板中点击 **“一键导入”** 按钮，系统会根据 User-Agent 自动唤起对应客户端：

| 设备类型 | 客户端 | 协议 |
| :--- | :--- | :--- |
| Android | Clash Meta | `intent://` |
| iOS | Shadowrocket | `shadowrocket://` |
| Windows / macOS / Linux | Clash Verge | `clash://` |

### 手动配置

1. 下载根证书：`https://<VPS_IP>:1000/cert` 并安装为受信任的 CA。
2. 在 Web 面板中点击 **“下载配置”** 获取 `config.yaml`。
3. 导入客户端（Clash Meta / Verge / Shadowrocket 均可）。

### 生成的配置示例

```yaml
proxies:
  - name: "WORK-REMOTE"
    type: vless
    server: <VPS_IP>
    port: 443
    uuid: <用户UUID>
    network: tcp
    tls: true
    flow: xtls-rprx-vision
    servername: www.apple.com          # 推荐伪装目标 (苹果 CDN)
    reality-opts:
      public-key: <服务器公钥>
      short-id: <用户短ID>
    client-fingerprint: chrome
```

> 💡 **伪装目标说明**：为避免因过度使用微软域名 (`www.microsoft.com`) 导致的连接干扰，推荐使用 `www.apple.com` 作为 Reality 伪装目标。苹果 CDN 流量巨大且不易被运营商 QoS 策略误伤。

---

## 🔧 FRPX — FRPC 客户端管理工具

**FRPX** 是一个用 Rust 编写的 FRPC 客户端管理工具，提供跨平台的 frpc 进程管理、自动配置生成、证书签发和进程守护功能。

### 特性

| 特性 | 说明 |
| :--- | :--- |
| **跨平台支持** | Windows / Linux / macOS (x86_64 / ARM64) |
| **自动配置生成** | 自动从服务端获取认证信息，生成 `frpc.toml` |
| **进程守护** | frpc 异常退出后自动重启（可配置间隔） |
| **证书管理** | 自动签发和更新客户端证书 |
| **独立密码保护** | Web 管理界面支持独立密码认证 |
| **轻量高效** | Rust 编写，内存占用低，启动迅速 |

### 下载

从 [Releases](https://github.com/xlinmengen/proxy-assets/releases) 下载对应平台的 FRPX 二进制文件：

| 平台 | 文件 |
| :--- | :--- |
| Linux (x86_64) | `frpx-linux-unknown-x86_64-musl.tar.xz` |
| Linux (ARM64) | `frpx-linux-unknown-aarch64-musl.tar.xz` |
| Windows (x86_64) | `frpx-windows-pc-x86_64-gnu.zip` |
| macOS (Intel) | `frpx-apple-darwin-x86_64.tar.xz` |
| macOS (Apple Silicon) | `frpx-apple-darwin-aarch64.tar.xz` |

### 快速使用

```bash
# 1. 解压并运行（以 Linux 为例）
tar -xf frpx-linux-unknown-x86_64-musl.tar.xz
chmod +x frpx
./frpx

# 2. 首次运行会自动生成配置并启动 frpc
# 3. 访问 http://127.0.0.1:9500 管理 FRPC 代理
```

### 配置说明

FRPX 启动后会在当前目录创建以下文件：

| 文件 | 说明 |
| :--- | :--- |
| `frpc/frpc.toml` | 自动生成的 FRPC 配置文件 |
| `cert/ca.crt` | CA 根证书 |
| `cert/client.crt` | 客户端证书 |
| `cert/client.key` | 客户端私钥 |
| `data.db` | 登录凭证存储 |

### 与 FRPX 配合使用

FRPX 与 `worker.py` 面板配合，用户可在 Web 面板中：

1. 查看 FRPC 代理状态
2. 添加/编辑/删除 TCP/HTTP/HTTPS/STCP/XTCP/SUDP 代理
3. 管理访客 (Visitor) 配置

---

## 🔌 内网穿透 (FRP)

### 服务端（已自动配置）

- **绑定端口**：`10` (TCP 穿透)
- **认证方式**：OIDC（自动管理，支持 `transport.wireProtocol = "v2"` 启用 AEAD 加密）
- **管理界面**：`http://127.0.0.1:1020`（仅限本地访问，用户名/密码同管理员）

### FRP v2 协议 (可选)

FRP 0.69.1 引入了 `transport.wireProtocol = "v2"`，启用后控制通道使用 AEAD 加密（`xchacha20-poly1305` 或 `aes-256-gcm`）。如需启用，在 `frpc.toml` 中添加：

```toml
transport.wireProtocol = "v2"
```

> ⚠️ 启用 v2 需先升级 frps，再升级 frpc，且 v2 的 frpc 无法连接旧版 frps。

---

## 📊 流量统计与监控

- **实时速度**：每秒通过 gRPC 拉取，区分上行/下行。
- **累计流量**：按用户独立存储，每月 1 日自动重置。
- **系统指标**：Xray 内存占用、运行时间等。
- **API 接口**：`/api/xray/traffic`、`/api/xray/all-traffic` 等（用于前端轮询）。

---

## 🛠️ 运维指南

### 服务管理

```bash
systemctl status xray      # Xray 服务
systemctl status frps      # FRP 服务端
systemctl status monitor   # Web 面板 (含 worker + RPC 服务)

systemctl restart xray frps monitor
```

### 日志查看

```bash
journalctl -u xray -f -n 100
journalctl -u monitor -f -n 50
```

### 防火墙（已预配置）

| 端口 | 用途 | 状态 |
| :--- | :--- | :--- |
| `10` | FRP 内网穿透 | ✅ 已开放 |
| `443` | Xray Reality 代理 | ✅ 已开放 |
| `1000` | Web 管理面板 | ✅ 已开放 |
| `1020` | FRP 管理面板 | ❌ 仅限本地 |

查看当前规则：`ufw status verbose`

### 备份与恢复

- 用户数据：`/opt/monitor/datas/settings.json`
- Xray 配置：`/opt/xray/config.json`
- FRP 配置：`/opt/frps/frps.toml`
- 证书目录：`/opt/monitor/certs/`

建议定期备份以上目录。

---

## 📁 目录结构

```
/opt/monitor/
├── worker.py                 # Flask 应用入口 (Granian 启动)
├── service.py                # RPC 服务端 (业务逻辑)
├── launch.py                 # 启动脚本 (生成证书并启动 Granian)
├── config.py                 # 全局配置
├── command/                  # 核心模块
│   ├── auth.py               # 认证管理 (Session / 多因素)
│   ├── captcha.py            # 图形验证码生成
│   ├── ddos.py               # DDoS 防护 (令牌桶 + 自适应限流)
│   ├── mkcert.py             # CA 与证书签发
│   ├── oidc.py               # OIDC 认证服务 (/oauth2/token)
│   ├── rpc.py                # TCP/UDP RPC 框架
│   ├── settings.py           # 用户/配置管理
│   ├── smtp.py               # 邮件发送 (SMTP)
│   ├── update_assets.py      # 资产后台更新 (GeoIP/规则集)
│   ├── update_blacklist.py   # IP 黑名单自动更新
│   ├── utils.py              # 通用工具函数
│   └── xray_stats.py         # gRPC 流量统计 (与 Xray API 通信)
├── command_pb2/              # gRPC 生成代码 (Xray API)
│   ├── stats.py
│   └── stats_grpc.py
├── database/                 # GeoIP / 规则集缓存
│   ├── geoip.dat
│   ├── geosite.dat
│   ├── country.mmdb
│   ├── GeoLite2-*.mmdb
│   └── *.txt
├── datas/                    # 配置文件 (动态生成)
│   ├── settings.json         # 用户/密钥/认证
│   ├── config.json           # Xray 配置 (动态)
│   ├── config.yaml           # 客户端配置模板
│   └── frps.toml             # FRP 配置 (动态)
├── certs/                    # 证书 (动态生成)
│   ├── ca.crt
│   ├── ca.key
│   ├── server.crt
│   └── server.key
├── static/                   # 前端静态资源
│   ├── all.min.css
│   ├── *.js
│   └── Fonts/
└── templates/                # HTML 模板
    ├── *.html                # 主页面 (login/index/monitor/assets/reset)
    ├── email/                # 邮件模板
    │   ├── code.html
    │   ├── test.html
    │   └── warn.html
    └── tools/                # 在线工具模板
        ├── index.html
        ├── 2fa.html
        ├── base64.html
        ├── crypto.html
        └── ...
```

---

## ⚙️ 系统调优参数

安装脚本会自动应用以下优化（`/etc/sysctl.conf`）：

| 参数 | 值 | 说明 |
| :--- | :--- | :--- |
| `net.core.default_qdisc` | `fq` | 为 BBR 提供公平队列 |
| `net.ipv4.tcp_congestion_control` | `bbr` | 启用 BBR 拥塞控制 |
| `net.core.rmem_max / wmem_max` | 256 MiB | 最大接收/发送缓冲区 (适配高 BDP) |
| `net.ipv4.tcp_rmem / wmem` | 4K–256M | 动态缓冲区范围 |
| `net.ipv4.tcp_fastopen` | 0 | 禁用 TFO (保证兼容性) |
| `net.ipv4.tcp_slow_start_after_idle` | 0 | 禁用空闲后慢启动 |
| `net.ipv4.tcp_keepalive_time` | 20 | 保活探测间隔 (适配 NAT 超时短的环境) |
| `net.ipv4.tcp_keepalive_intvl` | 10 | 保活探测间隔 |
| `net.ipv4.tcp_keepalive_probes` | 3 | 保活探测次数 |
| `net.ipv4.tcp_ecn` | 0 | 关闭 ECN (避免运营商干扰) |
| `net.core.somaxconn` | 65535 | 监听队列长度 |
| `net.ipv4.conf.all.rp_filter` | 1 | 反向路径过滤 (安全) |
| `net.netfilter.nf_conntrack_max` | 524288 | 连接跟踪表 (适配 1GB 内存) |
| `net.ipv4.tcp_fin_timeout` | 30 | FIN-WAIT-2 超时 |

---

## 🛡️ 安全与防护

### DDoS 防护

面板内置 DDoS 防护模块（`command/ddos.py`），采用令牌桶 + 自适应限流 + 曲线惩罚机制，支持：

- 动态限流阈值（根据违规次数和全局防御因子）
- 恶意 Bot 指纹识别（User-Agent 检测）
- 临时黑名单与衰减解封
- 全局防御模式（随被封 IP 数量自动增强）

### 防火墙策略

```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow 10/tcp
ufw allow 443/tcp
ufw allow 1000/tcp
```

---

## ❓ 常见问题

### 1. 代理速度远低于 VPS 标称带宽？

- **可能原因**：本地网络（尤其是广电、长城等二级运营商）上行带宽不足或路由绕路。
- **验证方法**：使用 `traceroute <VPS_IP>` 查看路由路径，确认是否走了 CN2 GIA (`59.43.x.x`)。
- **解决方案**：更换为电信/联通宽带（CN2 GIA 对电信用户最优）；或使用 FRP xtcp 模式尝试 P2P 穿透。

### 2. 浏览器提示“证书不受信任”？

- 下载 `https://<VPS_IP>:1000/cert` 并安装为**受信任的根证书**（Windows 需导入“受信任的根证书颁发机构”）。

### 3. 流量统计显示为 0 或不准？

- 检查 Xray 配置中 `policy` 是否开启 `statsUserUplink` / `statsUserDownlink`。
- 确认 Xray API 端口 `15` 可访问：`netstat -tlnp | grep 15`。

### 4. 连接突然中断（昨天能用今天不能用）？

- **可能原因**：Reality 伪装域名被运营商特殊关照。
- **解决方案**：更换 `serverNames` 中的域名，推荐使用 `www.apple.com` 或 `www.bing.com`。可使用 `RealiTLScanner` 扫描同 IP 段的域名作为备选。

### 5. 如何更新 Xray 到最新版？

```bash
systemctl stop xray
wget -O /tmp/xray.zip https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip
unzip -p /tmp/xray.zip xray > /opt/xray/xray
chmod +x /opt/xray/xray
systemctl start xray
```

### 6. FRP 管理面板无法访问？

FRP 管理面板（`1020`）默认仅监听本地，如需外部访问：

```bash
# 修改 /opt/frps/frps.toml 中的 webServer.addr
webServer.addr = "0.0.0.0"

# 重启 FRP 并开放防火墙
systemctl restart frps
ufw allow 1020/tcp
```

### 7. FRPX 无法启动 frpc？

- 检查 `frpc/` 目录下是否存在 `frpc` 可执行文件（FRPX 不会自动下载 frpc，需要用户自行放置）。
- 查看 FRPX 日志输出，确认认证信息是否正确。
- 确保服务端 `1000` 端口可访问。

---

## 🤝 贡献与反馈

欢迎提交 Issue 或 Pull Request。  
项目地址：[https://github.com/xlinmengen/proxy-assets](https://github.com/xlinmengen/proxy-assets)

---

## 📄 许可证

[MIT License](https://opensource.org/licenses/MIT)  
Copyright © 2025-2026 xlinmengen

---

## 🙏 致谢

- [XTLS/Xray-core](https://github.com/XTLS/Xray-core) – 核心代理引擎
- [fatedier/frp](https://github.com/fatedier/frp) – 内网穿透服务端
- [Flask](https://flask.palletsprojects.com/) – Web 框架
- [Granian](https://github.com/emmett-framework/granian) – WSGI 服务器
