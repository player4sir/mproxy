#!/usr/bin/env bash
# ====================================================================
# mproxy 全自动一键部署与初始化脚本
# 支持本地执行与 GitHub 远程一键安装:
# bash <(curl -fsSL https://raw.githubusercontent.com/player4sir/mproxy/main/deploy/install.sh)
# ====================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
PLAIN='\033[0m'

GITHUB_REPO="${GITHUB_REPO:-"player4sir/mproxy"}"

echo -e "=========================================================="
echo -e "         ${CYAN}mproxy 现代多协议代理 全自动一键部署${PLAIN}"
echo -e "=========================================================="

# 1. 检查 root 权限
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[错误]${PLAIN} 本安装脚本必须以 root 权限运行！请使用: sudo bash $0"
    exit 1
fi

# 2. 检查系统架构 (amd64 / arm64)
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)
        BIN_ARCH="amd64"
        ;;
    aarch64|arm64)
        BIN_ARCH="arm64"
        ;;
    *)
        echo -e "${RED}[错误]${PLAIN} 暂不支持的 CPU 架构: $ARCH"
        exit 1
        ;;
esac
echo -e "${GREEN}[1/7]${PLAIN} 检测到 CPU 架构: ${CYAN}${BIN_ARCH}${PLAIN}"

# 3. 安装依赖工具 (curl, openssl, tar)
echo -e "${GREEN}[2/7]${PLAIN} 检查并安装基础依赖工具..."
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y curl openssl tar systemd >/dev/null 2>&1 || true
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y curl openssl tar systemd >/dev/null 2>&1 || true
elif command -v yum >/dev/null 2>&1; then
    yum install -y curl openssl tar systemd >/dev/null 2>&1 || true
fi

# 4. 定位与安装核心二进制
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || echo "")"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR" 2>/dev/null || echo "")"

echo -e "${GREEN}[3/7]${PLAIN} 部署 mproxy 核心二进制..."

COMPILED=0

# 如果系统没有 go，自动安装官方 Go 1.22
if ! command -v go >/dev/null 2>&1 && [[ ! -x /usr/local/go/bin/go ]]; then
    echo -e "${CYAN}正在配置 Go 编译环境以确保构建最新版核心...${PLAIN}"
    GO_TAR="go1.22.8.linux-${BIN_ARCH}.tar.gz"
    if curl -fsSL -o "/tmp/${GO_TAR}" "https://go.dev/dl/${GO_TAR}" 2>/dev/null; then
        rm -rf /usr/local/go && tar -C /usr/local -xzf "/tmp/${GO_TAR}"
        rm -f "/tmp/${GO_TAR}"
        export PATH=$PATH:/usr/local/go/bin
    elif command -v apt-get >/dev/null 2>&1; then
        apt-get install -y golang git >/dev/null 2>&1 || true
    fi
fi
if [[ -x /usr/local/go/bin/go ]]; then
    export PATH=$PATH:/usr/local/go/bin
fi

# 1. 优先策略：如果本地当前目录有源码，直接本地编译最新版本
if command -v go >/dev/null 2>&1 && [[ -f "$PROJECT_ROOT/main.go" ]]; then
    echo -e "${CYAN}检测到本地源码，正在整理依赖并编译最新版本...${PLAIN}"
    (cd "$PROJECT_ROOT" && rm -f go.sum && go mod tidy && go build -trimpath -ldflags="-s -w" -o /usr/local/bin/mproxy-core .)
    chmod +x /usr/local/bin/mproxy-core
    COMPILED=1
fi

# 2. 如果是远程一键执行且有 Go，从 GitHub 拉取最新代码直接编译（保证绝对是最新 commit！）
if [[ $COMPILED -eq 0 ]] && command -v go >/dev/null 2>&1; then
    echo -e "${CYAN}正在从 GitHub (${GITHUB_REPO}) 拉取最新代码并进行本地编译...${PLAIN}"
    TMP_SRC=$(mktemp -d)
    if git clone --depth=1 "https://github.com/${GITHUB_REPO}.git" "$TMP_SRC" 2>/dev/null; then
        (cd "$TMP_SRC" && rm -f go.sum && go mod tidy && go build -trimpath -ldflags="-s -w" -o /usr/local/bin/mproxy-core .)
        chmod +x /usr/local/bin/mproxy-core
        rm -rf "$TMP_SRC"
        COMPILED=1
    fi
fi

# 3. 如果编译未能完成，降级到下载预编译版本
if [[ $COMPILED -eq 0 ]]; then
    RELEASE_BIN_URL="https://github.com/${GITHUB_REPO}/releases/latest/download/mproxy-linux-${BIN_ARCH}"
    RAW_BIN_URL="https://raw.githubusercontent.com/${GITHUB_REPO}/main/dist/mproxy-linux-${BIN_ARCH}"
    echo -e "${CYAN}正在从 GitHub 获取预编译程序...${PLAIN}"
    if curl -fsSL -o /usr/local/bin/mproxy-core "$RELEASE_BIN_URL" 2>/dev/null; then
        chmod +x /usr/local/bin/mproxy-core
    elif curl -fsSL -o /usr/local/bin/mproxy-core "$RAW_BIN_URL" 2>/dev/null; then
        chmod +x /usr/local/bin/mproxy-core
    fi
fi

# 校验核心二进制是否就绪
if [[ ! -f /usr/local/bin/mproxy-core || ! -x /usr/local/bin/mproxy-core ]]; then
    echo -e "${RED}[错误]${PLAIN} 无法获取 mproxy-core 可执行文件！"
    echo -e "若当前目录有源码，请执行: cd ~/mproxy && go mod tidy && go build -o /usr/local/bin/mproxy-core ."
    exit 1
fi

# 安装 CLI 快捷管理工具
if [[ -f "$SCRIPT_DIR/mproxy.sh" ]]; then
    cp "$SCRIPT_DIR/mproxy.sh" /usr/local/bin/mproxy
    chmod +x /usr/local/bin/mproxy
else
    curl -fsSL "https://raw.githubusercontent.com/${GITHUB_REPO}/main/deploy/mproxy.sh" -o /usr/local/bin/mproxy 2>/dev/null || true
    chmod +x /usr/local/bin/mproxy
fi

# 5. 生成生产环境配置与安全凭证
echo -e "${GREEN}[4/7]${PLAIN} 初始化配置与安全凭据..."
mkdir -p /etc/mproxy

# 生成默认自签 TLS 证书
if [[ ! -f /etc/mproxy/cert.pem || ! -f /etc/mproxy/key.pem ]]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout /etc/mproxy/key.pem -out /etc/mproxy/cert.pem \
        -days 3650 -nodes -subj "/CN=www.microsoft.com" >/dev/null 2>&1
    chmod 600 /etc/mproxy/key.pem
fi

# 若不存在配置文件，则全自动生成高强度凭证配置文件
if [[ ! -f /etc/mproxy/config.json ]]; then
    VLESS_UUID=$(openssl rand -hex 16 | awk '{print substr($0,1,8)"-"substr($0,9,4)"-"substr($0,13,4)"-"substr($0,17,4)"-"substr($0,21,12)}')
    TROJAN_PW=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c 16)
    HY2_PW=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c 16)
    SS_PW=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c 16)
    SOCKS_PW=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 12)

    # 生成 Reality X25519 密钥对与 short_id
    KEYGEN_OUT=$(/usr/local/bin/mproxy-core -keygen 2>/dev/null || true)
    REALITY_PRIV=$(echo "$KEYGEN_OUT" | awk '/PrivateKey:/ {print $2}')
    REALITY_PUB=$(echo "$KEYGEN_OUT" | awk '/PublicKey:/ {print $2}')
    REALITY_SID=$(echo "$KEYGEN_OUT" | awk '/ShortID:/ {print $2}')
    if [[ -z "$REALITY_SID" ]]; then
        REALITY_SID=$(openssl rand -hex 8)
    fi

    cat > /etc/mproxy/config.json << EOF
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
      "passwords": ["${VLESS_UUID}"],
      "reality": {
        "dest": "www.microsoft.com:443",
        "server_names": ["www.microsoft.com", "microsoft.com"],
        "private_key": "${REALITY_PRIV}",
        "public_key": "${REALITY_PUB}",
        "short_ids": ["${REALITY_SID}"]
      }
    },
    {
      "type": "vless",
      "listen": "0.0.0.0:8080",
      "udp": true,
      "passwords": ["${VLESS_UUID}"],
      "transport": {
        "type": "ws",
        "ws": {
          "path": "/vless-ws"
        }
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
        "password": "${HY2_PW}",
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
      "passwords": ["${TROJAN_PW}"],
      "fallback": "127.0.0.1:8080",
      "fallback_proxy_protocol": true
    },
    {
      "type": "shadowsocks",
      "listen": "0.0.0.0:8388",
      "udp": true,
      "method": "aes-256-gcm",
      "password": "${SS_PW}"
    },
    {
      "type": "socks5",
      "listen": "127.0.0.1:1080",
      "udp": true,
      "users": {
        "admin": "${SOCKS_PW}"
      }
    }
  ]
}
EOF
    chmod 600 /etc/mproxy/config.json
    echo -e "${GREEN}[成功]${PLAIN} 已生成全新配置文件: /etc/mproxy/config.json"
fi

# 6. 配置网络内核调优 (BBR & TCP Fast Open)
echo -e "${GREEN}[5/7]${PLAIN} 开启 BBR 拥塞控制算法与网络内核优化..."
cat > /etc/sysctl.d/99-mproxy.conf << 'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.somaxconn = 8192
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 10240 65535
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 131072 16777216
net.ipv4.tcp_wmem = 4096 131072 16777216
EOF
sysctl --system >/dev/null 2>&1 || true

# 配置 UDP Port Hopping (针对 Hysteria 2 UDP 端口跳跃抗 QoS)
if command -v iptables >/dev/null 2>&1; then
    iptables -t nat -C PREROUTING -p udp --dport 20000:50000 -j REDIRECT --to-ports 8443 2>/dev/null || \
    iptables -t nat -A PREROUTING -p udp --dport 20000:50000 -j REDIRECT --to-ports 8443 2>/dev/null || true
fi

# 自动放行防火墙端口 (443, 8443 UDP, 20000-50000 UDP 等)
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    ufw allow 443/tcp >/dev/null 2>&1 || true
    ufw allow 8443/udp >/dev/null 2>&1 || true
    ufw allow 20000:50000/udp >/dev/null 2>&1 || true
    ufw allow 8080/tcp >/dev/null 2>&1 || true
    ufw allow 9443/tcp >/dev/null 2>&1 || true
    ufw allow 8388/tcp >/dev/null 2>&1 || true
    ufw allow 8388/udp >/dev/null 2>&1 || true
elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
    firewall-cmd --permanent --add-port=443/tcp >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-port=8443/udp >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-port=20000-50000/udp >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-port=8080/tcp >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-port=9443/tcp >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-port=8388/tcp >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-port=8388/udp >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
fi

# 7. 配置 systemd 服务自启并启动
echo -e "${GREEN}[6/7]${PLAIN} 配置 systemd 系统服务..."
cat > /etc/systemd/system/mproxy.service << 'EOF'
[Unit]
Description=mproxy multi-protocol proxy service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/mproxy-core -c /etc/mproxy/config.json
Restart=always
RestartSec=3
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable mproxy >/dev/null 2>&1
systemctl restart mproxy

# 8. 验证服务启动状态
echo -e "${GREEN}[7/7]${PLAIN} 验证服务运行状态..."
sleep 1
if systemctl is-active --quiet mproxy; then
    echo -e "\n${GREEN}==========================================================${PLAIN}"
    echo -e "${GREEN}       恭喜！mproxy 现代多协议代理服务已成功部署并启动！${PLAIN}"
    echo -e "${GREEN}==========================================================${PLAIN}"
    echo -e " 快捷管理命令: ${CYAN}mproxy${PLAIN} (在任意终端输入即可打开管理面板)"
    echo -e " 配置文件路径: ${YELLOW}/etc/mproxy/config.json${PLAIN}"
    echo -e " 服务状态查询: ${CYAN}systemctl status mproxy${PLAIN}"
    echo -e " 实时日志查看: ${CYAN}journalctl -u mproxy -f${PLAIN}"
    echo -e "----------------------------------------------------------\n"

    PUBLIC_IP=$(curl -s4 --max-time 3 ip.sb || curl -s4 --max-time 3 ifconfig.me || echo "YOUR_SERVER_IP")
    /usr/local/bin/mproxy-core -sub -host "$PUBLIC_IP" -c /etc/mproxy/config.json
else
    echo -e "${RED}[警告]${PLAIN} 服务启动异常，请执行: journalctl -u mproxy -n 30 查看详细原因"
fi
