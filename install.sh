#!/usr/bin/env bash
# =======================================================
# VPS 安全监控一键安装脚本 (全发行版适配)
# 适用: Debian/Ubuntu, CentOS/RHEL/Alma/Rocky/Fedora, Alpine, Arch, OpenSUSE
# 支持直接使用:
# curl -fsSL https://raw.githubusercontent.com/firstwxx1/vps-security-monitor/main/install.sh | bash -s -- --token '...' --chat '...' --auto
# =======================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
PLAIN='\033[0m'

REPO_URL="https://github.com/firstwxx1/vps-security-monitor.git"
INSTALL_DIR="/opt/vps-security-monitor"
BIN_LINK="/usr/local/bin/vps-guard"

# 1. 权限自适应处理 (支持 root 或自动提权)
if [ "$(id -u)" != "0" ]; then
    if command -v sudo >/dev/null 2>&1; then
        echo -e "${YELLOW}[*] 检测到非 root 用户，正在使用 sudo 权限执行安装...${PLAIN}"
        exec sudo bash "$0" "$@"
    else
        echo -e "${RED}[错误] 当前非 root 账户且系统中未安装 sudo，请切换到 root (执行 su -) 后再运行此命令！${PLAIN}"
        exit 1
    fi
fi

# 解析命令行参数
AUTO_MODE=false
CLI_TOKEN=""
CLI_CHAT=""
CLI_NAME=""
CLI_MASTER=""
IS_AGENT=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --token)
            CLI_TOKEN="$2"; shift 2 ;;
        --chat)
            CLI_CHAT="$2"; shift 2 ;;
        --name)
            CLI_NAME="$2"; shift 2 ;;
        --master)
            CLI_MASTER="$2"; IS_AGENT=true; shift 2 ;;
        --agent)
            IS_AGENT=true; shift ;;
        --auto)
            AUTO_MODE=true; shift ;;
        *)
            shift ;;
    esac
done

echo -e "${GREEN}=====================================================${PLAIN}"
echo -e "${GREEN}        开始部署 VPS 安全监控与日报巡检系统          ${PLAIN}"
echo -e "${GREEN}=====================================================${PLAIN}"

# 2. 全发行版包管理器适配安装依赖
install_dependencies() {
    echo -e "${YELLOW}[*] 正在检测并安装基础环境依赖 (Python3, git, curl, openssl, cron)...${PLAIN}"
    if command -v apt-get &>/dev/null; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -y -q 2>/dev/null || true
        apt-get install -y -q python3 python3-pip git curl openssl cron 2>/dev/null || apt-get install -y python3 git curl openssl 2>/dev/null || true
        systemctl enable --now cron 2>/dev/null || service cron start 2>/dev/null || true
    elif command -v dnf &>/dev/null; then
        dnf install -y -q python3 python3-pip git curl openssl cronie 2>/dev/null || dnf install -y python3 git curl openssl 2>/dev/null || true
        systemctl enable --now cronie 2>/dev/null || service crond start 2>/dev/null || true
    elif command -v yum &>/dev/null; then
        yum install -y -q python3 python3-pip git curl openssl cronie 2>/dev/null || yum install -y python3 git curl openssl 2>/dev/null || true
        systemctl enable --now cronie 2>/dev/null || service crond start 2>/dev/null || true
    elif command -v apk &>/dev/null; then
        apk update 2>/dev/null || true
        apk add python3 py3-pip git curl openssl bash 2>/dev/null || apk add python3 git curl openssl 2>/dev/null || true
        rc-update add crond 2>/dev/null || true
        rc-service crond start 2>/dev/null || crond 2>/dev/null || true
    elif command -v pacman &>/dev/null; then
        pacman -Sy --noconfirm python git curl openssl cronie 2>/dev/null || true
        systemctl enable --now cronie 2>/dev/null || true
    elif command -v zypper &>/dev/null; then
        zypper --non-interactive install python3 git curl openssl cron 2>/dev/null || true
        systemctl enable --now cron 2>/dev/null || true
    fi
}

install_dependencies

# 确保 Python3 存在
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}[错误] 未检测到 Python 3，请手动安装 python3 后重试。${PLAIN}"
    exit 1
fi

# 3. 部署程序文件
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)"

if [ -f "${SCRIPT_DIR}/vps_security_guard.py" ]; then
    mkdir -p "${INSTALL_DIR}"
    if [ "$SCRIPT_DIR" != "$INSTALL_DIR" ]; then
        cp -rf "${SCRIPT_DIR}"/* "${INSTALL_DIR}/" || true
    fi
else
    # 管道在线安装 (curl | bash)
    if [ -d "${INSTALL_DIR}/.git" ]; then
        echo -e "${YELLOW}[*] 正在更新已有程序版本...${PLAIN}"
        cd "${INSTALL_DIR}"
        git reset --hard HEAD 2>/dev/null || true
        git pull 2>/dev/null || true
    else
        echo -e "${YELLOW}[*] 正在从 GitHub 克隆源码...${PLAIN}"
        rm -rf "${INSTALL_DIR}"
        git clone "${REPO_URL}" "${INSTALL_DIR}"
    fi
fi

cd "${INSTALL_DIR}"
chmod +x menu.sh vps_security_guard.py vps_security_bot.py 2>/dev/null || true

# 初始化配置文件
if [ ! -f "${INSTALL_DIR}/config.json" ]; then
    if [ -f "${INSTALL_DIR}/config.example.json" ]; then
        cp "${INSTALL_DIR}/config.example.json" "${INSTALL_DIR}/config.json"
    fi
fi

# 智能探测当前系统的 Nginx / Web 访问日志路径
detect_nginx_log() {
    for log_path in \
        "/var/log/nginx/access.log" \
        "/opt/1panel/runtime/nginx/logs/access.log" \
        "/www/wwwlogs/access.log" \
        "/var/log/caddy/access.log" \
        "/var/log/httpd/access_log"; do
        if [ -f "$log_path" ]; then
            echo "$log_path"
            return
        fi
    done
    echo "/var/log/nginx/access.log"
}

DETECTED_LOG="$(detect_nginx_log)"

# 写入命令行传入的配置参数或更新默认日志路径
python3 - "$CLI_TOKEN" "$CLI_CHAT" "$CLI_NAME" "$DETECTED_LOG" "${INSTALL_DIR}/config.json" "$IS_AGENT" "$CLI_MASTER" << 'EOF'
import sys, json, os

token, chat, name, detected_log, cfg_path = (
    sys.argv[1].strip(), sys.argv[2].strip(), sys.argv[3].strip(),
    sys.argv[4].strip(), sys.argv[5].strip()
)
is_agent = sys.argv[6].strip().lower() if len(sys.argv) > 6 else "false"
cli_master = sys.argv[7].strip() if len(sys.argv) > 7 else ""

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
if is_agent == "true":
    cfg["role"] = "agent"
if cli_master:
    cfg["master"] = cli_master

# 如果默认配置的日志路径不存在但探测到了存在的路径，自动修正
current_log = cfg.get("logs", {}).get("nginx_access_log", "")
if (not current_log or not os.path.exists(current_log)) and os.path.exists(detected_log):
    cfg.setdefault("logs", {})["nginx_access_log"] = detected_log

with open(cfg_path, 'w', encoding='utf-8') as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)
EOF

# 4. 创建全局快捷命令 (vps-guard)
mkdir -p /usr/local/bin
rm -f "${BIN_LINK}"
cat << 'EOF' > "${BIN_LINK}"
#!/usr/bin/env bash
exec /opt/vps-security-monitor/menu.sh "$@"
EOF
chmod +x "${BIN_LINK}"

# 5. 配置后台守护服务 (适配 Systemd 或自动兜底)
if [ "$IS_AGENT" = true ]; then
    echo -e "${YELLOW}[*] 当前节点为被控子节点 (Agent)，自动关闭并禁用 Telegram Bot 轮询进程，防止多端冲突...${PLAIN}"
    systemctl stop vps-security-bot.service 2>/dev/null || true
    systemctl disable vps-security-bot.service 2>/dev/null || true
    pkill -f "vps_security_bot.py" 2>/dev/null || true
else
    # 仅主控节点运行 Telegram 交互机器人 Daemon
    if command -v systemctl &>/dev/null && [ -d /run/systemd/system ]; then
        cat << 'EOF' > /etc/systemd/system/vps-security-bot.service
[Unit]
Description=VPS Security Monitor Telegram Bot Daemon
After=network.target

[Service]
Type=simple
User=root
Environment=PYTHONUNBUFFERED=1
WorkingDirectory=/opt/vps-security-monitor
ExecStart=/usr/bin/python3 /opt/vps-security-monitor/vps_security_bot.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload 2>/dev/null || true
        if [ -n "$CLI_TOKEN" ]; then
            systemctl enable vps-security-bot.service 2>/dev/null || true
            systemctl restart vps-security-bot.service 2>/dev/null || true
        fi
    else
        # 非 Systemd 环境 (Alpine / OpenRC / Docker 等)
        if [ -n "$CLI_TOKEN" ]; then
            pkill -f "vps_security_bot.py" 2>/dev/null || true
            nohup python3 "${INSTALL_DIR}/vps_security_bot.py" >/dev/null 2>&1 &
        fi
    fi
fi

# 6. 如果是无人值守自动安装模式 (--auto)
if [ "$AUTO_MODE" = true ]; then
    # 自动配置开机自启与定时保活 (@reboot 自启通知 + 5分钟突发检测 + 每天早晨09:00安全日报)
    crontab -l 2>/dev/null | grep -v "vps_security_guard.py" > /tmp/cron_temp.txt || true
    echo "@reboot /usr/bin/python3 ${INSTALL_DIR}/vps_security_guard.py boot >/dev/null 2>&1" >> /tmp/cron_temp.txt
    echo "*/5 * * * * /usr/bin/python3 ${INSTALL_DIR}/vps_security_guard.py check >/dev/null 2>&1" >> /tmp/cron_temp.txt
    echo "0 9 * * * /usr/bin/python3 ${INSTALL_DIR}/vps_security_guard.py daily >/dev/null 2>&1" >> /tmp/cron_temp.txt
    crontab /tmp/cron_temp.txt
    rm -f /tmp/cron_temp.txt

    # 启用 Cron 服务开机自启动
    systemctl enable cron 2>/dev/null || systemctl enable cronie 2>/dev/null || chkconfig crond on 2>/dev/null || rc-update add crond default 2>/dev/null || true
    systemctl restart cron 2>/dev/null || systemctl restart cronie 2>/dev/null || service cron restart 2>/dev/null || service crond restart 2>/dev/null || true

    # 配置 Systemd 常驻守护进程与崩溃自愈保活 (vps-security-guard.service)
    if command -v systemctl >/dev/null 2>&1; then
        cat << 'EOF_SVC' > /etc/systemd/system/vps-security-guard.service
[Unit]
Description=VPS Security Monitor Guard Daemon
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/vps-security-monitor
Environment=PYTHONUNBUFFERED=1
ExecStart=/usr/bin/python3 /opt/vps-security-monitor/vps_security_guard.py daemon
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF_SVC
        systemctl daemon-reload 2>/dev/null || true
        systemctl enable vps-security-guard.service 2>/dev/null || true
        systemctl restart vps-security-guard.service 2>/dev/null || true
    fi

    # 如果传入了 Token，执行向主控端自动入库并推送 Telegram
    if [ -n "$CLI_TOKEN" ]; then
        node_display="${CLI_NAME:-$(hostname 2>/dev/null || echo 'VPS节点')}"
        public_ip="$(curl -sS -m 4 https://api.ipify.org 2>/dev/null || curl -sS -m 4 ifconfig.me 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}')"
        public_ip="${public_ip:-127.0.0.1}"
        os_info="$(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '\"' || uname -sr)"

        python3 - "${INSTALL_DIR}" "${node_display}" "${public_ip}" "${os_info}" "${CLI_MASTER}" << 'EOF'
import sys, os, json, urllib.request, urllib.parse, hashlib

install_dir = sys.argv[1]
node_name = sys.argv[2]
public_ip = sys.argv[3]
os_info = sys.argv[4]
cli_master = sys.argv[5] if len(sys.argv) > 5 else ""

cfg_path = os.path.join(install_dir, "config.json")
try:
    with open(cfg_path, 'r', encoding='utf-8') as f:
        cfg = json.load(f)

    token = cfg.get("telegram", {}).get("bot_token")
    chat_id = cfg.get("telegram", {}).get("chat_id")

    if token and chat_id:
        master_ip = ""
        master_port = "9527"
        secret = hashlib.sha256(token.encode('utf-8')).hexdigest()[:16]

        if cli_master:
            if ":" in cli_master:
                master_ip, master_port = cli_master.split(":", 1)
            else:
                master_ip = cli_master
        else:
            # 尝试通过 Telegram 机器人的 ShortDescription 自动发现主控 IP 与端口
            try:
                desc_url = f"https://api.telegram.org/bot{token}/getMyShortDescription"
                with urllib.request.urlopen(desc_url, timeout=5) as r:
                    desc_res = json.loads(r.read().decode('utf-8'))
                    s_desc = desc_res.get("result", {}).get("short_description", "")
                    if s_desc.startswith("master:"):
                        parts = s_desc.split(":")
                        master_ip = parts[1]
                        master_port = parts[2] if len(parts) > 2 else "9527"
                        if len(parts) > 3:
                            secret = parts[3]
            except Exception:
                pass

        # 尝试通过 HTTP API 自动向主控机登记纳管
        registered = False
        if master_ip:
            try:
                reg_url = f"http://{master_ip}:{master_port}/api/register?" + urllib.parse.urlencode({
                    "ip": public_ip,
                    "name": node_name,
                    "os": os_info,
                    "secret": secret
                })
                with urllib.request.urlopen(reg_url, timeout=6) as reg_r:
                    reg_res = json.loads(reg_r.read().decode('utf-8'))
                    if reg_res.get("ok"):
                        registered = True
                        print("[+] 节点已成功自动注册登记至中央监控主控机！")
            except Exception:
                pass

        if registered:
            text = (
                f"🔔 <b>[新 VPS 节点接入成功]</b>\n"
                f"━━━━━━━━━━━━━━━━━━\n"
                f"🏷️ <b>节点名称</b>: <code>{node_name}</code>\n"
                f"🌐 <b>公网地址</b>: <code>{public_ip}</code>\n"
                f"💻 <b>操作系统</b>: <code>{os_info}</code>\n"
                f"🛡️ <b>纳管状态</b>: ✅ 已全自动录入中央监控列表\n"
                f"━━━━━━━━━━━━━━━━━━\n"
                f"<i>该 VPS 已纳管，可在 Telegram 中发送 /nodes 查看并随时发起巡检。</i>"
            )
            payload = {
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "HTML",
                "reply_markup": {
                    "inline_keyboard": [
                        [{"text": "📋 查看已纳管 VPS 列表", "callback_data": "nav:nodes"}]
                    ]
                }
            }
        else:
            cb_data = f"act:reg_quick:{public_ip}:{node_name}"
            if len(cb_data.encode('utf-8')) > 64:
                cb_data = f"act:reg_quick:{public_ip}:{node_name[:15]}"
            text = (
                f"🔔 <b>[新 VPS 节点接入成功]</b>\n"
                f"━━━━━━━━━━━━━━━━━━\n"
                f"🏷️ <b>节点名称</b>: <code>{node_name}</code>\n"
                f"🌐 <b>公网地址</b>: <code>{public_ip}</code>\n"
                f"💻 <b>操作系统</b>: <code>{os_info}</code>\n"
                f"🛡️ <b>安全守护</b>: 增量拦截与每日巡检已就绪\n"
                f"━━━━━━━━━━━━━━━━━━\n"
                f"👇 <b>点击下方按钮，即可将该 VPS 加入中央监控列表：</b>"
            )
            payload = {
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "HTML",
                "reply_markup": {
                    "inline_keyboard": [
                        [{"text": "📥 一键将此 VPS 录入列表", "callback_data": cb_data}]
                    ]
                }
            }

        url = f"https://api.telegram.org/bot{token}/sendMessage"
        req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10)
except Exception as e:
    pass
EOF
    fi

    echo -e "${GREEN}[+] 自动部署成功！守护进程与定时安全巡检已全部就绪。${PLAIN}"
    exit 0
fi

echo -e "${GREEN}[+] 部署成功！${PLAIN}"
echo -e "你可以随时在任意终端输入命令：${GREEN}vps-guard${PLAIN} 打开管理菜单！"
echo ""

# 7. 交互模式直接调出管理菜单
if [ -t 0 ]; then
    exec "${INSTALL_DIR}/menu.sh"
else
    echo -e "请在终端执行: ${GREEN}vps-guard${PLAIN} 开始配置"
fi
