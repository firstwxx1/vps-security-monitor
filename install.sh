#!/usr/bin/env bash
# =======================================================
# VPS 安全监控一键安装脚本
# 支持本地执行与在线一键安装:
# curl -fsSL https://raw.githubusercontent.com/firstwxx1/vps-security-monitor/main/install.sh | sudo bash
# =======================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
PLAIN='\033[0m'

REPO_URL="https://github.com/firstwxx1/vps-security-monitor.git"
INSTALL_DIR="/opt/vps-security-monitor"
BIN_LINK="/usr/local/bin/vps-guard"

# 解析参数
AUTO_MODE=false
CLI_TOKEN=""
CLI_CHAT=""
CLI_NAME=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --token)
            CLI_TOKEN="$2"; shift 2 ;;
        --chat)
            CLI_CHAT="$2"; shift 2 ;;
        --name)
            CLI_NAME="$2"; shift 2 ;;
        --auto)
            AUTO_MODE=true; shift ;;
        *)
            shift ;;
    esac
done

echo -e "${GREEN}=====================================================${PLAIN}"
echo -e "${GREEN}        开始部署 VPS 安全监控与日报巡检系统          ${PLAIN}"
echo -e "${GREEN}=====================================================${PLAIN}"

# 1. 检查 root 权限
if [ "$(id -u)" != "0" ]; then
    echo -e "${RED}[错误] 请使用 sudo 或 root 账户运行此安装脚本！${PLAIN}"
    exit 1
fi

# 2. 检查并安装基础依赖 (Python3, git, curl, openssl)
echo -e "${YELLOW}[*] 正在检查基础环境依赖...${PLAIN}"
if command -v apt &>/dev/null; then
    apt update -y && apt install -y python3 python3-pip git curl openssl
elif command -v yum &>/dev/null; then
    yum install -y python3 python3-pip git curl openssl
elif command -v dnf &>/dev/null; then
    dnf install -y python3 python3-pip git curl openssl
fi

# 3. 部署程序文件
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)"

if [ -f "${SCRIPT_DIR}/vps_security_guard.py" ]; then
    # 本地目录执行
    mkdir -p "${INSTALL_DIR}"
    if [ "$SCRIPT_DIR" != "$INSTALL_DIR" ]; then
        cp -rf "${SCRIPT_DIR}"/* "${INSTALL_DIR}/" || true
    fi
else
    # 管道在线安装 (curl | bash)
    if [ -d "${INSTALL_DIR}/.git" ]; then
        echo -e "${YELLOW}[*] 正在更新已有版本...${PLAIN}"
        cd "${INSTALL_DIR}"
        git reset --hard HEAD
        git pull || true
    else
        echo -e "${YELLOW}[*] 正在从 GitHub 克隆源码...${PLAIN}"
        rm -rf "${INSTALL_DIR}"
        git clone "${REPO_URL}" "${INSTALL_DIR}"
    fi
fi

cd "${INSTALL_DIR}"
chmod +x menu.sh vps_security_guard.py vps_security_bot.py

if [ ! -f "${INSTALL_DIR}/config.json" ]; then
    if [ -f "${INSTALL_DIR}/config.example.json" ]; then
        cp "${INSTALL_DIR}/config.example.json" "${INSTALL_DIR}/config.json"
    fi
fi

# 写入命令行传入的 Token / Chat / Name
if [ -n "$CLI_TOKEN" ] || [ -n "$CLI_CHAT" ] || [ -n "$CLI_NAME" ]; then
    python3 - "$CLI_TOKEN" "$CLI_CHAT" "$CLI_NAME" "${INSTALL_DIR}/config.json" << 'EOF'
import sys, json, os

token, chat, name, cfg_path = sys.argv[1].strip(), sys.argv[2].strip(), sys.argv[3].strip(), sys.argv[4].strip()
cfg = {}
if os.path.exists(cfg_path):
    try:
        with open(cfg_path, 'r', encoding='utf-8') as f:
            cfg = json.load(f)
    except Exception:
        pass

if token:
    cfg.setdefault("telegram", {})["bot_token"] = token
if chat:
    cfg.setdefault("telegram", {})["chat_id"] = chat
if name:
    cfg["node_name"] = name

with open(cfg_path, 'w', encoding='utf-8') as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)
EOF
fi

# 4. 创建全局快捷命令 (使用直接调用包装器，确保环境与路径绝对可靠)
rm -f "${BIN_LINK}"
cat << 'EOF' > "${BIN_LINK}"
#!/usr/bin/env bash
exec /opt/vps-security-monitor/menu.sh "$@"
EOF
chmod +x "${BIN_LINK}"

# 5. 配置 systemd 服务 (交互机器人守护进程)
cat << 'EOF' > /etc/systemd/system/vps-security-bot.service
[Unit]
Description=VPS Security Monitor Telegram Bot Daemon
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/vps-security-monitor
ExecStart=/usr/bin/python3 /opt/vps-security-monitor/vps_security_bot.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload 2>/dev/null || true

# 6. 如果是自动安装模式 (--auto)
if [ "$AUTO_MODE" = true ]; then
    # 自动安装 Crontab 定时任务
    crontab -l 2>/dev/null | grep -v "vps_security_guard.py" > /tmp/cron_temp.txt || true
    echo "*/5 * * * * /usr/bin/python3 ${INSTALL_DIR}/vps_security_guard.py check >/dev/null 2>&1" >> /tmp/cron_temp.txt
    echo "0 9 * * * /usr/bin/python3 ${INSTALL_DIR}/vps_security_guard.py daily >/dev/null 2>&1" >> /tmp/cron_temp.txt
    crontab /tmp/cron_temp.txt
    rm -f /tmp/cron_temp.txt

    # 尝试启动 bot 服务 (如果配置了 token)
    if [ -n "$CLI_TOKEN" ]; then
        systemctl enable vps-security-bot.service 2>/dev/null || true
        systemctl restart vps-security-bot.service 2>/dev/null || true

        # 发送上线通知
        node_display="${CLI_NAME:-$(hostname)}"
        python3 - "${INSTALL_DIR}" "${node_display}" << 'EOF'
import sys, os
sys.path.insert(0, sys.argv[1])
import vps_security_guard as guard
cfg = guard.load_config()
guard.send_telegram(cfg, f"🔔 新 VPS 节点接入成功！\n节点名称: {sys.argv[2]}\n守护进程与定时安全巡检已全部就绪。")
EOF
    fi

    echo -e "${GREEN}[+] 自动部署配置完成！${PLAIN}"
    exit 0
fi

echo -e "${GREEN}[+] 部署成功！${PLAIN}"
echo -e "你可以随时在任意终端输入命令：${GREEN}vps-guard${PLAIN} 打开管理菜单！"
echo ""
sleep 1

# 7. 如果是交互式终端，直接启动管理菜单
if [ -t 0 ]; then
    exec "${INSTALL_DIR}/menu.sh"
else
    echo -e "请在终端执行: ${GREEN}vps-guard${PLAIN} 开始配置"
fi
