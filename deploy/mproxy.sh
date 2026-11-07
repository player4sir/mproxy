#!/bin/bash
# =========================================================
# mproxy 管理面板 & 快捷命令工具
# =========================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
PLAIN='\033[0m'

CONFIG_FILE="/etc/mproxy/config.json"
BIN_CORE="/usr/local/bin/mproxy-core"
SERVICE_NAME="mproxy"

# 如果带有参数，且首个参数以 - 开头（如 -c config.json），直接透传给核心程序
if [[ "$#" -gt 0 && "$1" == -* ]]; then
    exec "$BIN_CORE" "$@"
fi

# 检查权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[错误]${PLAIN} 该命令必须以 root 权限运行！请使用 sudo mproxy"
        exit 1
    fi
}

# 获取服务运行状态
get_status() {
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        echo -e "${GREEN}正在运行${PLAIN}"
    else
        echo -e "${RED}未运行${PLAIN}"
    fi
}

# 获取 BBR 状态
get_bbr_status() {
    local bbr=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')
    if [[ "$bbr" == "bbr" ]]; then
        echo -e "${GREEN}已开启 (BBR)${PLAIN}"
    else
        echo -e "${YELLOW}未启用 ($bbr)${PLAIN}"
    fi
}

# 启动服务
start_service() {
    check_root
    echo -e "${CYAN}正在启动 mproxy...${PLAIN}"
    systemctl start "$SERVICE_NAME"
    sleep 1
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        echo -e "${GREEN}[成功] mproxy 已启动！${PLAIN}"
    else
        echo -e "${RED}[失败] 启动失败，请检查配置或日志 (journalctl -u mproxy -n 20)${PLAIN}"
    fi
}

# 停止服务
stop_service() {
    check_root
    echo -e "${CYAN}正在停止 mproxy...${PLAIN}"
    systemctl stop "$SERVICE_NAME"
    echo -e "${GREEN}[成功] mproxy 已停止！${PLAIN}"
}

# 重启服务
restart_service() {
    check_root
    echo -e "${CYAN}正在重启 mproxy...${PLAIN}"
    systemctl restart "$SERVICE_NAME"
    sleep 1
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        echo -e "${GREEN}[成功] mproxy 重启成功！${PLAIN}"
    else
        echo -e "${RED}[失败] 重启失败，请检查配置或日志！${PLAIN}"
    fi
}

# 查看实时日志
view_log() {
    echo -e "${CYAN}正在查看 mproxy 实时日志 (按 Ctrl+C 退出)...${PLAIN}"
    journalctl -u "$SERVICE_NAME" -f -n 50
}

# 查看节点与客户端订阅配置
view_sub() {
    check_root
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo -e "${RED}[错误] 配置文件不存在: $CONFIG_FILE${PLAIN}"
        return
    fi
    local host_arg="$1"
    local srv_ip=$(curl -s4 --max-time 2 ip.sb || curl -s4 --max-time 2 ifconfig.me || echo "")
    if [[ -z "$host_arg" ]]; then
        # 优先读取已绑定的正规证书域名，或从 /etc/mproxy/cert.pem 自动提取非自签域名
        if [[ -f /etc/mproxy/domain ]]; then
            host_arg=$(cat /etc/mproxy/domain | tr -d ' \r\n')
        elif [[ -f /etc/mproxy/cert.pem ]] && command -v openssl >/dev/null 2>&1; then
            local cert_cn=$(openssl x509 -in /etc/mproxy/cert.pem -noout -subject 2>/dev/null | sed -n 's/.*CN[[:space:]]*=[[:space:]]*\([^,/]*\).*/\1/p')
            if [[ -n "$cert_cn" && "$cert_cn" != "www.microsoft.com" && "$cert_cn" != "localhost" ]]; then
                host_arg="$cert_cn"
            fi
        fi
    fi
    if [[ -z "$host_arg" ]]; then
        host_arg="${srv_ip:-YOUR_SERVER_IP}"
    fi
    echo -e "${CYAN}正在生成节点与订阅配置 (域名/地址: $host_arg, 直连 IPv4: ${srv_ip:-自动解析})...${PLAIN}\n"
    "$BIN_CORE" -sub -host "$host_arg" -ip "$srv_ip" -c "$CONFIG_FILE"
}

# 编辑配置文件
edit_config() {
    check_root
    if command -v nano >/dev/null 2>&1; then
        nano "$CONFIG_FILE"
    elif command -v vim >/dev/null 2>&1; then
        vim "$CONFIG_FILE"
    else
        vi "$CONFIG_FILE"
    fi
    echo -e "\n${YELLOW}配置文件已修改，是否立即重启服务？[Y/n]: ${PLAIN}\c"
    read -r choice
    choice=${choice:-Y}
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        restart_service
    fi
}

# 申请正规 Let's Encrypt 证书
apply_cert() {
    check_root
    local domain="$1"
    local srv_ip=$(curl -s4 --max-time 3 ip.sb || curl -s4 --max-time 3 ifconfig.me || echo "")

    if [[ -z "$domain" ]]; then
        echo -e "${YELLOW}请输入已解析到当前服务器 ($srv_ip) 的域名: ${PLAIN}\c"
        read -r domain
    fi

    if [[ -z "$domain" ]]; then
        echo -e "${RED}[错误] 域名不能为空！${PLAIN}"
        return
    fi

    echo -e "${CYAN}正在校验域名 DNS 解析...${PLAIN}"
    local resolved_ip=$(ping -c 1 "$domain" 2>/dev/null | head -n 1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || echo "")
    if [[ -n "$srv_ip" && -n "$resolved_ip" && "$srv_ip" != "$resolved_ip" ]]; then
        echo -e "${RED}[警告] 域名 $domain 解析到的 IP ($resolved_ip) 与服务器公网 IP ($srv_ip) 不一致！${PLAIN}"
        echo -e "${YELLOW}请确保已在域名提供商控制台添加 A 记录指向 $srv_ip，继续申请可能因无法完成 HTTP 验证而失败。${PLAIN}"
        echo -e "是否强行继续？[y/N]: \c"
        read -r continue_apply
        if [[ ! "$continue_apply" =~ ^[Yy]$ ]]; then
            return
        fi
    fi

    echo -e "${CYAN}正在安装 acme.sh 自动化证书工具...${PLAIN}"
    if ! command -v socat >/dev/null 2>&1; then
        apt-get update -y >/dev/null 2>&1 && apt-get install -y socat >/dev/null 2>&1 || true
    fi

    if [[ ! -f ~/.acme.sh/acme.sh ]]; then
        curl -fsSL https://get.acme.sh | sh -s email="admin@${domain}"
    fi

    echo -e "${CYAN}正在向 Let's Encrypt 申请 ECC (prime256v1) 权威证书...${PLAIN}"
    # 释放 80 端口短暂用于 ACME 验证
    systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true

    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    if ~/.acme.sh/acme.sh --issue -d "$domain" --standalone --keylength ec-256 --force; then
        mkdir -p /etc/mproxy
        echo "$domain" > /etc/mproxy/domain
        ~/.acme.sh/acme.sh --install-cert -d "$domain" --ecc \
            --fullchain-file /etc/mproxy/cert.pem \
            --key-file /etc/mproxy/key.pem \
            --reloadcmd "systemctl restart mproxy"

        echo -e "\n${GREEN}[成功] 权威 SSL 证书已成功申请并安装至 /etc/mproxy/！${PLAIN}"
        echo -e "${GREEN}[成功] 已自动添加证书续期定时任务 (每天自动检查，到期前自动续约)。${PLAIN}"

        systemctl start "$SERVICE_NAME"
        echo -e "\n${CYAN}正在生成使用域名 ($domain) 的全新正规证书节点配置:${PLAIN}\n"
        view_sub "$domain"
    else
        echo -e "\n${RED}[失败] 证书申请失败！请检查 80 端口是否被占用，以及域名 A 记录是否正确解析到当前服务器。${PLAIN}"
        systemctl start "$SERVICE_NAME" >/dev/null 2>&1 || true
    fi
}

# 开启并调优 BBR
enable_bbr() {
    check_root
    echo -e "${CYAN}正在开启 Linux BBR 拥塞控制算法与网络调优...${PLAIN}"
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
net.core.rmem_default = 2097152
net.core.wmem_default = 2097152
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 131072 16777216
net.ipv4.tcp_wmem = 4096 131072 16777216
EOF
    sysctl --system >/dev/null 2>&1
    echo -e "${GREEN}[成功] BBR 拥塞控制及网络调优参数已生效！当前算法: $(get_bbr_status)${PLAIN}"
}

# 生成 Reality X25519 密钥对
generate_keys() {
    echo -e "${CYAN}正在生成全新 Reality X25519 密钥对与 short_id...${PLAIN}\n"
    "$BIN_CORE" -keygen
    echo -e "\n${YELLOW}提示：您可以将上述密钥与 shortID 填入 /etc/mproxy/config.json 的 reality 配置节中。${PLAIN}"
}

# UDP 端口跳跃管理 (Hysteria 2 Port Hopping)
manage_port_hop() {
    check_root
    echo -e "${CYAN}--- UDP 端口跳跃转发规则管理 (20000:50000 -> 8443) ---${PLAIN}"
    if iptables -t nat -C PREROUTING -p udp --dport 20000:50000 -j REDIRECT --to-ports 8443 2>/dev/null; then
        echo -e "当前状态: ${GREEN}已生效 (Active)${PLAIN}"
        echo -e "${YELLOW}是否需要移除该规则？[y/N]: ${PLAIN}\c"
        read -r choice
        if [[ "$choice" =~ ^[Yy]$ ]]; then
            iptables -t nat -D PREROUTING -p udp --dport 20000:50000 -j REDIRECT --to-ports 8443 2>/dev/null || true
            echo -e "${GREEN}[成功] 已移除 UDP 端口跳跃规则。${PLAIN}"
        fi
    else
        echo -e "当前状态: ${RED}未生效 (Inactive)${PLAIN}"
        echo -e "${YELLOW}是否立即添加并开启端口跳跃？[Y/n]: ${PLAIN}\c"
        read -r choice
        choice=${choice:-Y}
        if [[ "$choice" =~ ^[Yy]$ ]]; then
            iptables -t nat -A PREROUTING -p udp --dport 20000:50000 -j REDIRECT --to-ports 8443 2>/dev/null || true
            echo -e "${GREEN}[成功] 已成功开启 UDP 20000:50000 -> 8443 端口跳跃！${PLAIN}"
        fi
    fi
}

# 一键从 GitHub 拉取最新代码并编译更新
update_mproxy() {
    check_root
    echo -e "${CYAN}正在从 GitHub 拉取最新源码并编译更新 mproxy...${PLAIN}"
    if [[ -x /usr/local/go/bin/go ]]; then
        export PATH=$PATH:/usr/local/go/bin
    fi
    if ! command -v go >/dev/null 2>&1; then
        echo -e "${RED}[错误] 未检测到 Go 编译环境，正在调用在线安装器更新...${PLAIN}"
        bash <(curl -fsSL https://raw.githubusercontent.com/player4sir/mproxy/main/deploy/install.sh)
        return
    fi

    local src_dir="/tmp/mproxy"
    if [[ -d "$src_dir/.git" ]]; then
        (cd "$src_dir" && git fetch --all && git reset --hard origin/main)
    else
        rm -rf "$src_dir"
        git clone --depth=1 https://github.com/player4sir/mproxy.git "$src_dir"
    fi

    if ! (cd "$src_dir" && rm -f go.sum && go mod tidy && go build -trimpath -ldflags="-s -w" -o "$BIN_CORE" .); then
        echo -e "${RED}[错误] 编译失败，请检查上方报错信息！${PLAIN}"
        exit 1
    fi
    chmod +x "$BIN_CORE"
    if [[ -f "$src_dir/deploy/mproxy.sh" ]]; then
        cp "$src_dir/deploy/mproxy.sh" /usr/local/bin/mproxy
        chmod +x /usr/local/bin/mproxy
    fi
    systemctl restart "$SERVICE_NAME"
    echo -e "${GREEN}[成功] mproxy 已更新至最新版本并成功重启！${PLAIN}"
}

# 卸载 mproxy
uninstall_mproxy() {
    check_root
    echo -e "${RED}警告：此操作将彻底删除 mproxy 服务、二进制及配置文件！${PLAIN}"
    echo -e "${YELLOW}确定要卸载吗？[y/N]: ${PLAIN}\c"
    read -r confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        systemctl stop "$SERVICE_NAME" >/dev/null 2>&1
        systemctl disable "$SERVICE_NAME" >/dev/null 2>&1
        rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
        systemctl daemon-reload
        rm -rf /etc/mproxy
        rm -f /usr/local/bin/mproxy-core /usr/local/bin/mproxy
        rm -f /etc/sysctl.d/99-mproxy.conf
        echo -e "${GREEN}[成功] mproxy 已完全卸载！${PLAIN}"
        exit 0
    else
        echo -e "${CYAN}已取消卸载。${PLAIN}"
    fi
}

# 快捷命令行分流
case "$1" in
    start)
        start_service
        exit 0
        ;;
    stop)
        stop_service
        exit 0
        ;;
    restart)
        restart_service
        exit 0
        ;;
    status)
        echo -e "mproxy 状态: $(get_status)"
        echo -e "BBR 状态   : $(get_bbr_status)"
        exit 0
        ;;
    log|logs)
        view_log
        exit 0
        ;;
    sub|link|links)
        view_sub "$2"
        exit 0
        ;;
    cert|ssl)
        apply_cert "$2"
        exit 0
        ;;
    config)
        edit_config
        exit 0
        ;;
    hop|port-hop)
        manage_port_hop
        exit 0
        ;;
    keygen|key)
        generate_keys
        exit 0
        ;;
    bbr)
        enable_bbr
        exit 0
        ;;
    update|upgrade)
        update_mproxy
        exit 0
        ;;
    uninstall)
        uninstall_mproxy
        exit 0
        ;;
esac

# 交互式管理主菜单
show_menu() {
    clear
    echo -e "=========================================================="
    echo -e "         ${CYAN}mproxy 多协议现代代理 一键管理面板${PLAIN}"
    echo -e "=========================================================="
    echo -e " 服务状态: $(get_status)"
    echo -e " BBR 加速: $(get_bbr_status)"
    echo -e " 配置文件: ${CONFIG_FILE}"
    echo -e "----------------------------------------------------------"
    echo -e " ${GREEN}1.${PLAIN} 查看客户端节点链接与订阅配置 (sing-box/Clash/v2rayN)"
    echo -e " ${GREEN}2.${PLAIN} 一键申请并配置正规域名权威证书 (Let's Encrypt)"
    echo -e " ${GREEN}3.${PLAIN} 管理 UDP 端口跳跃规则 (Port Hopping 20000-50000)"
    echo -e " ${GREEN}4.${PLAIN} 生成 Reality X25519 密钥对与 ShortID"
    echo -e "----------------------------------------------------------"
    echo -e " ${GREEN}5.${PLAIN} 启动 mproxy"
    echo -e " ${GREEN}6.${PLAIN} 停止 mproxy"
    echo -e " ${GREEN}7.${PLAIN} 重启 mproxy"
    echo -e "----------------------------------------------------------"
    echo -e " ${GREEN}8.${PLAIN} 查看实时运行日志"
    echo -e " ${GREEN}9.${PLAIN} 修改服务端配置文件 (config.json)"
    echo -e " ${GREEN}10.${PLAIN} 一键开启与优化 BBR 内核加速"
    echo -e " ${GREEN}11.${PLAIN} 一键拉取 GitHub 最新源码更新 (mproxy update)"
    echo -e " ${RED}12.${PLAIN} 彻底卸载 mproxy"
    echo -e "----------------------------------------------------------"
    echo -e " ${CYAN}0.${PLAIN} 退出管理面板"
    echo -e "=========================================================="
    echo -e "请输入选项 [0-12]: \c"
    read -r num

    case "$num" in
        1) view_sub ;;
        2) apply_cert ;;
        3) manage_port_hop ;;
        4) generate_keys ;;
        5) start_service ;;
        6) stop_service ;;
        7) restart_service ;;
        8) view_log ;;
        9) edit_config ;;
        10) enable_bbr ;;
        11) update_mproxy ;;
        12) uninstall_mproxy ;;
        0) exit 0 ;;
        *) echo -e "${RED}[错误] 无效选项！${PLAIN}" ;;
    esac
}

show_menu
