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
    local ip=$(curl -s4 --max-time 3 ip.sb || curl -s4 --max-time 3 ifconfig.me || echo "YOUR_SERVER_IP")
    echo -e "${CYAN}正在根据服务器公网 IP ($ip) 生成订阅与节点配置...${PLAIN}\n"
    "$BIN_CORE" -sub -host "$ip" -c "$CONFIG_FILE"
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
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 131072 16777216
net.ipv4.tcp_wmem = 4096 131072 16777216
EOF
    sysctl --system >/dev/null 2>&1
    echo -e "${GREEN}[成功] BBR 拥塞控制及网络调优参数已生效！当前算法: $(get_bbr_status)${PLAIN}"
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
        view_sub
        exit 0
        ;;
    config)
        edit_config
        exit 0
        ;;
    bbr)
        enable_bbr
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
    echo -e " ${GREEN}2.${PLAIN} 启动 mproxy"
    echo -e " ${GREEN}3.${PLAIN} 停止 mproxy"
    echo -e " ${GREEN}4.${PLAIN} 重启 mproxy"
    echo -e "----------------------------------------------------------"
    echo -e " ${GREEN}5.${PLAIN} 查看实时运行日志"
    echo -e " ${GREEN}6.${PLAIN} 修改服务端配置文件 (config.json)"
    echo -e " ${GREEN}7.${PLAIN} 一键开启与优化 BBR 内核加速"
    echo -e " ${RED}8.${PLAIN} 彻底卸载 mproxy"
    echo -e "----------------------------------------------------------"
    echo -e " ${CYAN}0.${PLAIN} 退出管理面板"
    echo -e "=========================================================="
    echo -e "请输入选项 [0-8]: \c"
    read -r num

    case "$num" in
        1) view_sub ;;
        2) start_service ;;
        3) stop_service ;;
        4) restart_service ;;
        5) view_log ;;
        6) edit_config ;;
        7) enable_bbr ;;
        8) uninstall_mproxy ;;
        0) exit 0 ;;
        *) echo -e "${RED}[错误] 无效选项！${PLAIN}" ;;
    esac
}

show_menu
