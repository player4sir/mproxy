# mproxy: 高性能、强抗干扰、全协议现代代理程序

mproxy 是一个集成了 **Hysteria 2 (QUIC)、VLESS (v0) + Reality、Trojan、Shadowsocks (AEAD)、SOCKS5 与 HTTP Proxy** 的全能高性能现代代理程序，专为复杂网络环境与高吞吐低延迟场景打造。

---

## 协议支持矩阵

| 协议 | 传输层 | 加密 / 伪装 | UDP 支持 | 特性与适用场景 |
| :--- | :--- | :--- | :--- | :--- |
| **Hysteria 2 (Hy2)** | UDP / QUIC | TLS 1.3 (`h3` ALPN) | RFC 9221 Datagram | **抗丢包王牌**：内置激进拥塞控制，在 30%+ 严重丢包的高延迟跨洋线路上依然跑满物理带宽；支持 HTTP/3 伪装回落。 |
| **VLESS + Reality** | TCP | 真实海外大站证书借用 | 原生多路复用 | **抗封锁天花板**：免自购域名与证书，未授权主动扫描自动透明反弹至微软/苹果等真实大站，杜绝特征识别。 |
| **VLESS + WebSocket** | TCP / WS | TLS 或 CDN 卸载 | 原生中继 | **CDN 救砖与中转**：支持挂载在 Cloudflare CDN 之后，实现真实 VPS IP 隐藏与被墙节点复活。 |
| **Trojan** | TCP + TLS | TLS 1.2 / 1.3 | 原生 UDP Associate | **经典 Web 伪装**：双 ALPN (`h2` + `http/1.1`) 协商，未认证流量支持 PROXY protocol v1 透传回落真实网站。 |
| **Shadowsocks** | TCP + UDP | aes-128-gcm / aes-256-gcm | SIP003 AEAD | **经典穿透**：集成双代内存重放过滤器，认证失败随机化延时吞噬，消除固定超时指纹。 |
| **SOCKS5** | TCP + UDP | 用户名 / 密码 (RFC 1929) | RFC 1928 UDP Associate | **通用内网穿透**：完整支持 Full-Cone UDP 中继，适配各类终端工具。 |
| **HTTP Proxy** | TCP | Basic Auth (RFC 7617) | HTTP CONNECT 隧道 | **标准代理**：兼容各类开发工具、包管理器与爬虫。 |

---

## 快速一键部署与管理

### 1. 一键部署安装
上传代码压缩包并解压后，直接执行全自动安装脚本（自动配置环境、生成高强随机密码、配置 BBR 与自启服务）：

```bash
tar -xzvf mproxy.tar.gz
cd mproxy
sudo bash deploy/install.sh
```

### 2. 快捷管理面板 (`mproxy`)
安装完成后，在服务器任意终端中输入 `mproxy` 即可随时呼出交互式管理控制台：

```bash
mproxy
```

#### 常用快捷命令：
* `mproxy`：打开交互式主菜单
* `mproxy sub`：查看所有客户端通用导入链接 (vless://, hysteria2://, trojan://) 及 Clash.Meta / sing-box 配置
* `mproxy status`：查看服务运行状态与 BBR 开启状态
* `mproxy start` / `stop` / `restart`：控制服务启停
* `mproxy log`：实时查看服务端运行与访问日志
* `mproxy config`：快速编辑服务端 `/etc/mproxy/config.json` 配置文件
* `mproxy bbr`：一键开启并调优 Linux 内核 BBR 拥塞控制算法
* `mproxy uninstall`：一键完全卸载

---

## 配置文件结构 (`/etc/mproxy/config.json`)

```json
{
  "log_level": "info",
  "metrics_listen": "127.0.0.1:9090",
  "limits": {
    "max_conns": 20000,
    "max_conns_per_ip": 512,
    "idle_timeout": "5m",
    "handshake_timeout": "10s",
    "ban_after_failures": 8,
    "ban_duration": "10m",
    "shutdown_grace": "30s"
  },
  "outbound": {
    "dial_timeout": "8s",
    "block_private": true,
    "bind": ""
  },
  "listeners": [
    {
      "type": "vless",
      "listen": "0.0.0.0:443",
      "udp": true,
      "passwords": ["a5e18239-6523-446f-b258-2e06180632a7"],
      "reality": {
        "dest": "www.microsoft.com:443",
        "server_names": ["www.microsoft.com", "microsoft.com"],
        "short_ids": ["0123456789abcdef"]
      }
    },
    {
      "type": "vless",
      "listen": "0.0.0.0:8080",
      "udp": true,
      "passwords": ["a5e18239-6523-446f-b258-2e06180632a7"],
      "transport": {
        "type": "ws",
        "ws": { "path": "/vless-ws" }
      }
    },
    {
      "type": "hysteria2",
      "listen": "0.0.0.0:8443",
      "udp": true,
      "tls": {
        "cert": "/etc/mproxy/cert.pem",
        "key": "/etc/mproxy/key.pem"
      },
      "hy2": {
        "password": "CHANGE_ME_HY2_SECURE_TOKEN",
        "alpn": ["h3"],
        "masquerade": "127.0.0.1:8080"
      }
    },
    {
      "type": "trojan",
      "listen": "0.0.0.0:9443",
      "udp": true,
      "tls": {
        "cert": "/etc/mproxy/cert.pem",
        "key": "/etc/mproxy/key.pem"
      },
      "passwords": ["CHANGE_ME_LONG_RANDOM_TROJAN_PASSWORD"],
      "fallback": "127.0.0.1:8080",
      "fallback_proxy_protocol": true
    },
    {
      "type": "shadowsocks",
      "listen": "0.0.0.0:8388",
      "udp": true,
      "method": "aes-256-gcm",
      "password": "CHANGE_ME_ANOTHER_LONG_RANDOM_PASSWORD"
    },
    {
      "type": "socks5",
      "listen": "127.0.0.1:1080",
      "udp": true,
      "users": { "admin": "CHANGE_ME_PASSWORD" }
    }
  ]
}
```

---

## 客户端支持

安装后运行 `mproxy sub` 即可直接导出支持以下客户端的配置：
1. **v2rayN / Shadowrocket / Quantumult X / Loon / Surge / v2rayNG**：一键从剪贴板导入通用标准 URI 链接。
2. **Clash.Meta (Mihomo)**：直接复制导出的 `proxies` 结构即可。
3. **sing-box**：直接复制导出的 `outbounds` 结构即可。
