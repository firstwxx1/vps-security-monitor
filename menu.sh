#!/usr/bin/env bash
# =======================================================
# VPS 安全巡检与监控终端管理面板
# =======================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
PLAIN='\033[0m'

# 正确解析软链接获取真实物理路径 (防止 /usr/local/bin/vps-guard 调用时路径漂移)
if command -v readlink &>/dev/null; then
    REAL_SCRIPT="$(readlink -f "${BASH_SOURCE[0]}")"
    SCRIPT_DIR="$(cd -P "$(dirname "$REAL_SCRIPT")" >/dev/null 2>&1 && pwd)"
else
    SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
fi

# 如果仍然判定为 /usr/local/bin，且 /opt/vps-security-monitor 存在，则强制修正为 /opt/vps-security-monitor
if [[ "$SCRIPT_DIR" == "/usr/local/bin"* ]] && [ -d "/opt/vps-security-monitor" ]; then
    SCRIPT_DIR="/opt/vps-security-monitor"
fi

CONFIG_FILE="${SCRIPT_DIR}/config.json"
GUARD_PY="${SCRIPT_DIR}/vps_security_guard.py"

# 检查 Python3
check_python() {
    if ! command -v python3 &>/dev/null; then
        echo -e "${RED}[错误] 未检测到 python3，请先安装: apt update && apt install -y python3 或 yum install -y python3${PLAIN}"
        exit 1
    fi
}

# 确保 config.json 存在
init_config() {
    if [ ! -f "${CONFIG_FILE}" ]; then
        if [ -f "${SCRIPT_DIR}/config.example.json" ]; then
            cp "${SCRIPT_DIR}/config.example.json" "${CONFIG_FILE}"
        fi
    fi
}

# 读取配置状态
get_status() {
    TG_STATUS="${RED}未配置${PLAIN}"
    CRON_STATUS="${RED}未安装${PLAIN}"
    NGINX_STATUS="${RED}不存在${PLAIN}"
    BOT_DAEMON_STATUS="${RED}未运行${PLAIN}"

    if [ -f "${CONFIG_FILE}" ]; then
        local token=$(python3 - "$CONFIG_FILE" << 'EOF'
import sys, json
try:
    with open(sys.argv[1], 'r', encoding='utf-8') as f:
        cfg = json.load(f)
    print(cfg.get('telegram', {}).get('bot_token', ''))
except Exception:
    print('')
EOF
)
        if [[ -n "$token" && "$token" != *"YOUR_"* ]]; then
            TG_STATUS="${GREEN}已配置${PLAIN}"
        fi

        local ngx_log=$(python3 - "$CONFIG_FILE" << 'EOF'
import sys, json
try:
    with open(sys.argv[1], 'r', encoding='utf-8') as f:
        cfg = json.load(f)
    print(cfg.get('logs', {}).get('nginx_access_log', ''))
except Exception:
    print('')
EOF
)
        if [ -n "$ngx_log" ] && [ -f "$ngx_log" ]; then
            NGINX_STATUS="${GREEN}正常${PLAIN} ($ngx_log)"
        fi
    fi

    if crontab -l 2>/dev/null | grep -q "vps_security_guard.py"; then
        CRON_STATUS="${GREEN}已激活${PLAIN}"
    fi

    if systemctl is-active --quiet vps-security-bot 2>/dev/null; then
        BOT_DAEMON_STATUS="${GREEN}🟢 运行中${PLAIN}"
    elif pgrep -f "vps_security_bot.py" >/dev/null 2>&1; then
        BOT_DAEMON_STATUS="${GREEN}🟢 运行中${PLAIN}"
    fi
}

# 1. 配置 Telegram
config_telegram() {
    clear
    echo -e "${CYAN}=====================================================${PLAIN}"
    echo -e "${CYAN}             配置 Telegram 报警通知机器人            ${PLAIN}"
    echo -e "${CYAN}=====================================================${PLAIN}"
    echo -e "说明："
    echo -e "1. 在 Telegram 搜索并私聊 ${YELLOW}@BotFather${PLAIN}，发送 /newbot 创建机器人获取 Token"
    echo -e "2. 私聊你的新 Bot 随便发一条消息激活对话"
    echo -e "3. 搜索并私聊 ${YELLOW}@userinfobot${PLAIN} 获取你的数字 Chat ID"
    echo ""

    local current_token=$(python3 - "$CONFIG_FILE" << 'EOF'
import sys, json
try:
    with open(sys.argv[1], 'r', encoding='utf-8') as f:
        cfg = json.load(f)
    print(cfg.get('telegram', {}).get('bot_token', ''))
except Exception:
    print('')
EOF
)
    local current_chat=$(python3 - "$CONFIG_FILE" << 'EOF'
import sys, json
try:
    with open(sys.argv[1], 'r', encoding='utf-8') as f:
        cfg = json.load(f)
    print(cfg.get('telegram', {}).get('chat_id', ''))
except Exception:
    print('')
EOF
)

    echo -e "当前 Bot Token: ${GREEN}${current_token}${PLAIN}"
    echo -e "当前 Chat ID  : ${GREEN}${current_chat}${PLAIN}"
    echo ""

    read -p "请输入新的 Bot Token (回车保持不变): " new_token
    read -p "请输入新的 Chat ID (回车保持不变): " new_chat

    if [ -n "$new_token" ] || [ -n "$new_chat" ]; then
        python3 - "$new_token" "$new_chat" "$CONFIG_FILE" << 'EOF'
import sys, json, os

new_token = sys.argv[1].strip()
new_chat = sys.argv[2].strip()
cfg_path = sys.argv[3].strip()

cfg = {}
if os.path.exists(cfg_path):
    try:
        with open(cfg_path, 'r', encoding='utf-8') as f:
            cfg = json.load(f)
    except Exception:
        cfg = {}

if not cfg:
    example_path = os.path.join(os.path.dirname(cfg_path), 'config.example.json')
    if os.path.exists(example_path):
        try:
            with open(example_path, 'r', encoding='utf-8') as f:
                cfg = json.load(f)
        except Exception:
            pass

if new_token:
    cfg.setdefault("telegram", {})["bot_token"] = new_token
if new_chat:
    cfg.setdefault("telegram", {})["chat_id"] = new_chat

with open(cfg_path, 'w', encoding='utf-8') as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)

print("[+] 配置已保存！")
EOF
    fi

    echo ""
    read -p "是否立即发送测试消息到 Telegram? (y/n) [y]: " send_test
    send_test=${send_test:-y}
    if [[ "$send_test" =~ ^[Yy]$ ]]; then
        python3 "${GUARD_PY}" test
    fi
    echo ""
    read -n 1 -s -r -p "按任意键返回主菜单..."
}

# 2. 配置敏感后台与监控路径
config_paths() {
    clear
    echo -e "${CYAN}=====================================================${PLAIN}"
    echo -e "${CYAN}            配置受监控的登录/敏感后台路径            ${PLAIN}"
    echo -e "${CYAN}=====================================================${PLAIN}"
    echo -e "当前监控的登录接口路径 (发生 400/401/403 时计为登录失败/撞库)："
    python3 - "$CONFIG_FILE" << 'EOF'
import sys, json
try:
    with open(sys.argv[1], 'r', encoding='utf-8') as f:
        cfg = json.load(f)
    paths = cfg.get("security", {}).get("login_paths", [])
    for i, p in enumerate(paths, 1):
        print(f"  [{i}] {p}")
except Exception:
    pass
EOF
    echo ""
    echo -e "  ${YELLOW}1.${PLAIN} 添加新的登录监控路径"
    echo -e "  ${YELLOW}2.${PLAIN} 删除已有监控路径"
    echo -e "  ${YELLOW}3.${PLAIN} 配置站点友好别名 (如 gpt.isoziyuan.com -> Sub2API 大模型后台)"
    echo -e "  ${YELLOW}0.${PLAIN} 返回上一级"
    echo ""
    read -p "请选择操作 [0-3]: " opt
    case "$opt" in
        1)
            read -p "请输入要监控的路径 (如 /api/v1/auth/login): " p_add
            if [ -n "$p_add" ]; then
                python3 - "$p_add" "$CONFIG_FILE" << 'EOF'
import sys, json
p_add, cfg_path = sys.argv[1].strip(), sys.argv[2].strip()
with open(cfg_path, 'r', encoding='utf-8') as f:
    cfg = json.load(f)
ps = cfg.setdefault("security", {}).setdefault("login_paths", [])
if p_add not in ps:
    ps.append(p_add)
with open(cfg_path, 'w', encoding='utf-8') as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)
print(f"[+] 路径已添加: {p_add}")
EOF
            fi
            ;;
        2)
            read -p "请输入要删除的路径序号: " del_idx
            python3 - "$del_idx" "$CONFIG_FILE" << 'EOF'
import sys, json
del_idx, cfg_path = sys.argv[1].strip(), sys.argv[2].strip()
with open(cfg_path, 'r', encoding='utf-8') as f:
    cfg = json.load(f)
ps = cfg.get("security", {}).get("login_paths", [])
try:
    idx = int(del_idx) - 1
    if 0 <= idx < len(ps):
        removed = ps.pop(idx)
        with open(cfg_path, 'w', encoding='utf-8') as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        print(f"[+] 已删除: {removed}")
    else:
        print("[-] 序号超出范围")
except Exception:
    print("[-] 序号无效")
EOF
            ;;
        3)
            read -p "请输入域名 (如 gpt.isoziyuan.com): " s_domain
            read -p "请输入展示别名 (如 Sub2API 大模型后台): " s_name
            if [ -n "$s_domain" ] && [ -n "$s_name" ]; then
                python3 - "$s_domain" "$s_name" "$CONFIG_FILE" << 'EOF'
import sys, json
s_dom, s_name, cfg_path = sys.argv[1].strip(), sys.argv[2].strip(), sys.argv[3].strip()
with open(cfg_path, 'r', encoding='utf-8') as f:
    cfg = json.load(f)
cfg.setdefault("sites", {})[s_dom] = s_name
with open(cfg_path, 'w', encoding='utf-8') as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)
print("[+] 站点映射已保存！")
EOF
            fi
            ;;
    esac
    read -n 1 -s -r -p "按任意键返回..."
}

# 3. 配置 SSL 证书监测域名
config_ssl() {
    clear
    echo -e "${CYAN}=====================================================${PLAIN}"
    echo -e "${CYAN}             配置 SSL 证书监控域名列表              ${PLAIN}"
    echo -e "${CYAN}=====================================================${PLAIN}"
    echo -e "当前监控的域名列表："
    python3 - "$CONFIG_FILE" << 'EOF'
import sys, json
try:
    with open(sys.argv[1], 'r', encoding='utf-8') as f:
        cfg = json.load(f)
    doms = cfg.get("ssl_domains", [])
    for i, d in enumerate(doms, 1):
        print(f"  [{i}] {d}")
except Exception:
    pass
EOF
    echo ""
    echo -e "  ${YELLOW}1.${PLAIN} 添加监控域名"
    echo -e "  ${YELLOW}2.${PLAIN} 删除监控域名"
    echo -e "  ${YELLOW}3.${PLAIN} 立即检测各域名剩余天数"
    echo -e "  ${YELLOW}0.${PLAIN} 返回上一级"
    echo ""
    read -p "请选择操作 [0-3]: " opt
    case "$opt" in
        1)
            read -p "请输入域名 (如 gpt.isoziyuan.com): " dom_add
            if [ -n "$dom_add" ]; then
                python3 - "$dom_add" "$CONFIG_FILE" << 'EOF'
import sys, json
dom_add, cfg_path = sys.argv[1].strip(), sys.argv[2].strip()
with open(cfg_path, 'r', encoding='utf-8') as f:
    cfg = json.load(f)
doms = cfg.setdefault("ssl_domains", [])
if dom_add not in doms:
    doms.append(dom_add)
with open(cfg_path, 'w', encoding='utf-8') as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)
print(f"[+] 域名已添加: {dom_add}")
EOF
            fi
            ;;
        2)
            read -p "请输入要删除的域名序号: " del_idx
            python3 - "$del_idx" "$CONFIG_FILE" << 'EOF'
import sys, json
del_idx, cfg_path = sys.argv[1].strip(), sys.argv[2].strip()
with open(cfg_path, 'r', encoding='utf-8') as f:
    cfg = json.load(f)
doms = cfg.get("ssl_domains", [])
try:
    idx = int(del_idx) - 1
    if 0 <= idx < len(doms):
        removed = doms.pop(idx)
        with open(cfg_path, 'w', encoding='utf-8') as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        print(f"[+] 已删除: {removed}")
    else:
        print("[-] 序号超出范围")
except Exception:
    print("[-] 序号无效")
EOF
            ;;
        3)
            echo "正在连接检测 SSL 证书有效期..."
            python3 - "$CONFIG_FILE" "$SCRIPT_DIR" << 'EOF'
import sys, json, os
cfg_path, s_dir = sys.argv[1].strip(), sys.argv[2].strip()
sys.path.insert(0, s_dir)
import vps_security_guard as guard
with open(cfg_path, 'r', encoding='utf-8') as f:
    cfg = json.load(f)
for dom in cfg.get("ssl_domains", []):
    days = guard.check_ssl_expiry(dom)
    if days is not None:
        print(f"  {dom} -> 剩余 {days} 天")
    else:
        print(f"  {dom} -> 探测失败/无法连接 443")
EOF
            ;;
    esac
    read -n 1 -s -r -p "按任意键返回..."
}

# 4. 配置 SSH 安全白名单
config_ssh_whitelist() {
    clear
    echo -e "${CYAN}=====================================================${PLAIN}"
    echo -e "${CYAN}           配置 SSH 允许白名单 IP (陌生登录审计)     ${PLAIN}"
    echo -e "${CYAN}=====================================================${PLAIN}"
    echo -e "如果登录成功的 IP 不在以下列表中，安全日报将标红发出警告："
    python3 - "$CONFIG_FILE" << 'EOF'
import sys, json
try:
    with open(sys.argv[1], 'r', encoding='utf-8') as f:
        cfg = json.load(f)
    ips = cfg.get("security", {}).get("known_ssh_ips", [])
    for i, ip in enumerate(ips, 1):
        print(f"  [{i}] {ip}")
except Exception:
    pass
EOF
    echo ""
    echo -e "当前你登录本终端的 IP 是: ${GREEN}${SSH_CLIENT%% *}${PLAIN}"
    echo ""
    echo -e "  ${YELLOW}1.${PLAIN} 将当前登录 IP 加入白名单"
    echo -e "  ${YELLOW}2.${PLAIN} 手动输入 IP 加入白名单"
    echo -e "  ${YELLOW}3.${PLAIN} 删除白名单 IP"
    echo -e "  ${YELLOW}0.${PLAIN} 返回上一级"
    echo ""
    read -p "请选择操作 [0-3]: " opt
    case "$opt" in
        1)
            local my_ip="${SSH_CLIENT%% *}"
            if [ -n "$my_ip" ]; then
                python3 - "$my_ip" "$CONFIG_FILE" << 'EOF'
import sys, json
my_ip, cfg_path = sys.argv[1].strip(), sys.argv[2].strip()
with open(cfg_path, 'r', encoding='utf-8') as f:
    cfg = json.load(f)
ips = cfg.setdefault("security", {}).setdefault("known_ssh_ips", [])
if my_ip not in ips:
    ips.append(my_ip)
with open(cfg_path, 'w', encoding='utf-8') as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)
print(f"[+] 当前 IP 已加入白名单: {my_ip}")
EOF
            fi
            ;;
        2)
            read -p "请输入 IP: " ip_add
            if [ -n "$ip_add" ]; then
                python3 - "$ip_add" "$CONFIG_FILE" << 'EOF'
import sys, json
ip_add, cfg_path = sys.argv[1].strip(), sys.argv[2].strip()
with open(cfg_path, 'r', encoding='utf-8') as f:
    cfg = json.load(f)
ips = cfg.setdefault("security", {}).setdefault("known_ssh_ips", [])
if ip_add not in ips:
    ips.append(ip_add)
with open(cfg_path, 'w', encoding='utf-8') as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)
print(f"[+] IP 已加入白名单: {ip_add}")
EOF
            fi
            ;;
        3)
            read -p "请输入要删除的序号: " del_idx
            python3 - "$del_idx" "$CONFIG_FILE" << 'EOF'
import sys, json
del_idx, cfg_path = sys.argv[1].strip(), sys.argv[2].strip()
with open(cfg_path, 'r', encoding='utf-8') as f:
    cfg = json.load(f)
ips = cfg.get("security", {}).get("known_ssh_ips", [])
try:
    idx = int(del_idx) - 1
    if 0 <= idx < len(ips):
        removed = ips.pop(idx)
        with open(cfg_path, 'w', encoding='utf-8') as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        print(f"[+] 已删除: {removed}")
    else:
        print("[-] 序号超出范围")
except Exception:
    print("[-] 序号无效")
EOF
            ;;
    esac
    read -n 1 -s -r -p "按任意键返回..."
}

# 5. 配置备份监控
config_backup() {
    clear
    echo -e "${CYAN}=====================================================${PLAIN}"
    echo -e "${CYAN}               配置备份校验状态监控                 ${PLAIN}"
    echo -e "${CYAN}=====================================================${PLAIN}"
    python3 - "$CONFIG_FILE" << 'EOF'
import sys, json
try:
    with open(sys.argv[1], 'r', encoding='utf-8') as f:
        cfg = json.load(f)
    b = cfg.get("backup", {})
    print(f"启用状态: {b.get('enabled', False)}")
    print(f"存储标识: {b.get('name', 'R2')}")
    print(f"校验模式: {b.get('type', 'file')}")
    print(f"监控路径: {b.get('path', '')}")
    print(f"校验命令: {b.get('command', '')}")
except Exception:
    pass
EOF
    echo ""
    echo -e "  ${YELLOW}1.${PLAIN} 启用/禁用备份状态展示"
    echo -e "  ${YELLOW}2.${PLAIN} 设置本地备份目录路径 (自动按最新文件时间校验)"
    echo -e "  ${YELLOW}3.${PLAIN} 设置自定义校验命令 (如 rclone/脚本检测)"
    echo -e "  ${YELLOW}0.${PLAIN} 返回上一级"
    echo ""
    read -p "请选择操作 [0-3]: " opt
    case "$opt" in
        1)
            python3 - "$CONFIG_FILE" << 'EOF'
import sys, json
cfg_path = sys.argv[1].strip()
with open(cfg_path, 'r', encoding='utf-8') as f:
    cfg = json.load(f)
b = cfg.setdefault("backup", {})
b["enabled"] = not b.get("enabled", False)
with open(cfg_path, 'w', encoding='utf-8') as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)
print(f"[+] 备份监控状态已切换为: {b['enabled']}")
EOF
            ;;
        2)
            read -p "请输入本地备份文件所在目录路径 (如 /data/backups): " b_path
            read -p "请输入显示名称 (默认 R2): " b_name
            b_name=${b_name:-R2}
            python3 - "$b_path" "$b_name" "$CONFIG_FILE" << 'EOF'
import sys, json
b_path, b_name, cfg_path = sys.argv[1].strip(), sys.argv[2].strip(), sys.argv[3].strip()
with open(cfg_path, 'r', encoding='utf-8') as f:
    cfg = json.load(f)
b = cfg.setdefault("backup", {})
b["enabled"] = True
b["type"] = "file"
b["name"] = b_name
b["path"] = b_path
with open(cfg_path, 'w', encoding='utf-8') as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)
print("[+] 本地备份路径配置已生效！")
EOF
            ;;
        3)
            read -p "请输入自定义校验 Shell 命令: " b_cmd
            read -p "请输入显示名称 (默认 R2): " b_name
            b_name=${b_name:-R2}
            python3 - "$b_cmd" "$b_name" "$CONFIG_FILE" << 'EOF'
import sys, json
b_cmd, b_name, cfg_path = sys.argv[1].strip(), sys.argv[2].strip(), sys.argv[3].strip()
with open(cfg_path, 'r', encoding='utf-8') as f:
    cfg = json.load(f)
b = cfg.setdefault("backup", {})
b["enabled"] = True
b["type"] = "command"
b["name"] = b_name
b["command"] = b_cmd
with open(cfg_path, 'w', encoding='utf-8') as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)
print("[+] 自定义命令配置已生效！")
EOF
            ;;
    esac
    read -n 1 -s -r -p "按任意键返回..."
}

# 6. 一键安装 Crontab 定时任务
install_crontab() {
    clear
    echo -e "${CYAN}=====================================================${PLAIN}"
    echo -e "${CYAN}             一键配置 Crontab 巡检任务               ${PLAIN}"
    echo -e "${CYAN}=====================================================${PLAIN}"
    echo -e "即将添加的计划任务："
    echo -e "  1. ${GREEN}*/5 * * * *${PLAIN} 突发拦截增量检测 (每 5 分钟扫描一次新攻击)"
    echo -e "  2. ${GREEN}0 9 * * *${PLAIN}   每日安全日报 (每天早晨 09:00 推送全天汇总)"
    echo ""
    read -p "确认安装到当前用户的 Crontab 吗? (y/n) [y]: " confirm
    confirm=${confirm:-y}
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        crontab -l 2>/dev/null | grep -v "vps_security_guard.py" > /tmp/cron_temp.txt || true
        echo "*/5 * * * * /usr/bin/python3 ${GUARD_PY} check >/dev/null 2>&1" >> /tmp/cron_temp.txt
        echo "0 9 * * * /usr/bin/python3 ${GUARD_PY} daily >/dev/null 2>&1" >> /tmp/cron_temp.txt
        crontab /tmp/cron_temp.txt
        rm -f /tmp/cron_temp.txt
        echo -e "${GREEN}[+] 定时任务安装成功！${PLAIN}"
    fi
    echo ""
    read -n 1 -s -r -p "按任意键返回主菜单..."
}

# 7. 一键卸载 Crontab 定时任务
uninstall_crontab() {
    clear
    echo -e "${YELLOW}正在清理 crontab 中的监控定时任务...${PLAIN}"
    crontab -l 2>/dev/null | grep -v "vps_security_guard.py" > /tmp/cron_temp.txt || true
    crontab /tmp/cron_temp.txt
    rm -f /tmp/cron_temp.txt
    echo -e "${GREEN}[+] 监控定时任务已全部移除！${PLAIN}"
    read -n 1 -s -r -p "按任意键返回主菜单..."
}

# 8. 立即手动执行检测
run_manual_check() {
    clear
    echo -e "${CYAN}正在执行增量突发检测 (check 模式)...${PLAIN}"
    echo -e "${YELLOW}提示: 如果最近 5 分钟内没有达到阈值 (>=5次失败) 的集中爆破，不会触发通知。${PLAIN}"
    python3 "${GUARD_PY}" check
    echo -e "${GREEN}[+] 检测完成！${PLAIN}"
    read -n 1 -s -r -p "按任意键返回主菜单..."
}

# 9. 立即生成全天安全日报
run_manual_daily() {
    clear
    echo -e "${CYAN}正在汇总过去 24 小时数据并生成安全日报 (daily 模式)...${PLAIN}"
    python3 "${GUARD_PY}" daily
    echo -e "${GREEN}[+] 日报已生成并推送到 Telegram！${PLAIN}"
    read -n 1 -s -r -p "按任意键返回主菜单..."
}

# 10. 系统环境与日志探测排查
diagnose_system() {
    clear
    echo -e "${CYAN}=====================================================${PLAIN}"
    echo -e "${CYAN}                 系统环境与日志自检                  ${PLAIN}"
    echo -e "${CYAN}=====================================================${PLAIN}"
    echo -e "1. 程序工作目录: ${GREEN}${SCRIPT_DIR}${PLAIN}"
    echo -e "2. 配置文件路径: ${GREEN}${CONFIG_FILE}${PLAIN}"
    echo -e "3. Python 环境: $(python3 --version 2>&1)"
    echo -e "4. Nginx 日志检测:"
    local ngx_log=$(python3 - "$CONFIG_FILE" << 'EOF'
import sys, json
try:
    with open(sys.argv[1], 'r', encoding='utf-8') as f:
        cfg = json.load(f)
    print(cfg.get('logs', {}).get('nginx_access_log', ''))
except Exception:
    print('')
EOF
)
    if [ -n "$ngx_log" ] && [ -f "$ngx_log" ]; then
        echo -e "   - 路径: ${GREEN}$ngx_log${PLAIN} (大小: $(du -sh $ngx_log | cut -f1))"
    else
        echo -e "   - 路径: ${RED}$ngx_log 不存在！${PLAIN} (请确认 Nginx 日志路径)"
    fi

    echo -e "5. SSH 认证日志:"
    for f in /var/log/auth.log /var/log/secure; do
        if [ -f "$f" ]; then
            echo -e "   - 找到日志文件: ${GREEN}$f${PLAIN}"
        fi
    done
    if command -v journalctl &>/dev/null; then
        echo -e "   - 支持 journalctl 读取 SSH 服务认证记录"
    fi

    echo -e "6. Fail2ban 状态:"
    if command -v fail2ban-client &>/dev/null; then
        echo -e "   - Fail2ban: ${GREEN}已安装${PLAIN}"
        fail2ban-client status 2>/dev/null | grep -E "Jail list" || echo "   - 服务未运行"
    else
        echo -e "   - Fail2ban: ${YELLOW}未安装 (不影响 Web/SSH/证书日志统计)${PLAIN}"
    fi

    echo -e "7. 系统资源:"
    df -h / | awk 'NR==2{print "   - 根分区已用: "$5" (可用 "$4")"}'
    free -m | awk 'NR==2{print "   - 内存可用: "$7" MB"}'
    echo ""
    read -n 1 -s -r -p "按任意键返回主菜单..."
}

# 管理 Telegram 交互机器人守护进程
manage_bot_daemon() {
    clear
    echo -e "${CYAN}=====================================================${PLAIN}"
    echo -e "${CYAN}         Telegram 交互管理机器人守护进程管理         ${PLAIN}"
    echo -e "${CYAN}=====================================================${PLAIN}"
    echo -e "说明："
    echo -e "启动后，机器人将以守护进程在后台运行，支持："
    echo -e "1. 在 Telegram 聊天中${GREEN}直接发送目标 VPS 的 SSH 账号密码${PLAIN}自动纳管并安装监控"
    echo -e "2. 在 Telegram 点击按钮实时查看所有纳管 VPS 列表、在线状态与巡检"
    echo -e "3. 一键生成专属接入命令，适配任意 Linux VPS"
    echo ""
    echo -e "当前状态: ${BOT_DAEMON_STATUS}"
    echo ""
    echo -e "  ${YELLOW}1.${PLAIN} 启动/重启 Telegram 机器人守护进程"
    echo -e "  ${YELLOW}2.${PLAIN} 停止 Telegram 机器人守护进程"
    echo -e "  ${YELLOW}3.${PLAIN} 查看机器人运行日志"
    echo -e "  ${YELLOW}0.${PLAIN} 返回上一级"
    echo ""
    read -p "请选择操作 [0-3]: " b_opt
    case "$b_opt" in
        1)
            # 确保 systemd 服务文件存在
            cat << 'EOF' > /etc/systemd/system/vps-security-bot.service
[Unit]
Description=VPS Security Monitor Telegram Bot Daemon
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/vps-security-monitor
Environment=PYTHONUNBUFFERED=1
ExecStart=/usr/bin/python3 /opt/vps-security-monitor/vps_security_bot.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload 2>/dev/null || true
            systemctl enable vps-security-bot 2>/dev/null || true
            systemctl restart vps-security-bot 2>/dev/null || true
            echo -e "${GREEN}[+] 机器人守护进程已启动！你可以在 Telegram 中向 Bot 发送 /start 或发送远程 VPS 的 SSH 账号密码开始管理！${PLAIN}"
            ;;
        2)
            systemctl stop vps-security-bot 2>/dev/null || true
            pkill -f "vps_security_bot.py" || true
            echo -e "${YELLOW}[+] 机器人守护进程已停止！${PLAIN}"
            ;;
        3)
            echo -e "${CYAN}--- 最近 30 行日志 (Ctrl+C 退出) ---${PLAIN}"
            journalctl -u vps-security-bot -n 30 --no-pager 2>/dev/null || true
            ;;
    esac
    read -n 1 -s -r -p "按任意键返回..."
}

# 🌐 多 VPS 节点纳管与状态控制
manage_nodes() {
    while true; do
        clear
        echo -e "${CYAN}=====================================================${PLAIN}"
        echo -e "${CYAN}             🌐 多 VPS 节点纳管与状态控制             ${PLAIN}"
        echo -e "${CYAN}=====================================================${PLAIN}"
        python3 - "${SCRIPT_DIR}/nodes.json" << 'EOF'
import sys, os, json

nodes_file = sys.argv[1]
nodes = []
if os.path.exists(nodes_file):
    try:
        with open(nodes_file, 'r', encoding='utf-8') as f:
            nodes = json.load(f)
    except Exception:
        nodes = []

print(f"当前已纳管 VPS 总数: {len(nodes)} 台\n")
if not nodes:
    print("  [暂无纳管节点]")
else:
    for idx, n in enumerate(nodes):
        name = n.get("name", "未命名")
        host = n.get("host", "")
        port = n.get("port", 22)
        user = n.get("user", "root")
        is_local = n.get("is_local", False)
        tag = "📍 本机主节点" if is_local else f"🌐 {user}@{host}:{port}"
        print(f"  {idx + 1}. {name}")
        print(f"     └ {tag}")
EOF
        echo -e "${CYAN}-----------------------------------------------------${PLAIN}"
        echo -e "  ${YELLOW}1.${PLAIN} 快速录入新 VPS 节点 (输入 IP / 别名)"
        echo -e "  ${YELLOW}2.${PLAIN} 移除已有 VPS 节点"
        echo -e "  ${YELLOW}3.${PLAIN} 获取专属一键安装命令 (在目标 VPS 终端执行全自动接入)"
        echo -e "  ${YELLOW}4.${PLAIN} 立即发起突发安全巡检"
        echo -e "  ${YELLOW}0.${PLAIN} 返回主菜单"
        echo ""
        read -p "请输入选项 [0-4]: " n_opt
        case "$n_opt" in
            1)
                echo ""
                read -p "请输入目标 VPS 的公网 IP: " target_ip
                if [ -z "$target_ip" ]; then
                    echo -e "${RED}[错误] IP 不能为空！${PLAIN}"
                    sleep 1
                    continue
                fi
                read -p "请输入节点别名 (如 香港CN2 / 美西节点，可回车留空): " target_name
                python3 - "${SCRIPT_DIR}/nodes.json" "$target_ip" "$target_name" << 'EOF'
import sys, os, json
from datetime import datetime

nodes_file = sys.argv[1]
ip = sys.argv[2].strip()
name = sys.argv[3].strip() if len(sys.argv) > 3 else ""
display_name = f"{name} ({ip})" if (name and name != ip) else f"VPS-{ip}"

nodes = []
if os.path.exists(nodes_file):
    try:
        with open(nodes_file, 'r', encoding='utf-8') as f:
            nodes = json.load(f)
    except Exception:
        pass

nodes = [n for n in nodes if n.get("host") != ip]
nodes.append({
    "name": display_name,
    "host": ip,
    "port": 22,
    "user": "root",
    "is_local": False,
    "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
})
with open(nodes_file, 'w', encoding='utf-8') as f:
    json.dump(nodes, f, ensure_ascii=False, indent=2)
print(f"[+] 成功录入节点: {display_name}")
EOF
                echo -e "${GREEN}[+] 录入成功！该 VPS 已加入监控列表。${PLAIN}"
                sleep 1.5
                ;;
            2)
                read -p "请输入要移除的节点序号: " del_idx
                if [ -n "$del_idx" ]; then
                    python3 - "${SCRIPT_DIR}/nodes.json" "$del_idx" << 'EOF'
import sys, os, json

nodes_file = sys.argv[1]
try:
    idx = int(sys.argv[2]) - 1
    with open(nodes_file, 'r', encoding='utf-8') as f:
        nodes = json.load(f)
    if 0 <= idx < len(nodes):
        if nodes[idx].get("is_local"):
            print("[-] 本机主节点不可移除！")
        else:
            removed = nodes.pop(idx)
            with open(nodes_file, 'w', encoding='utf-8') as f:
                json.dump(nodes, f, ensure_ascii=False, indent=2)
            print(f"[+] 已成功移除节点: {removed.get('name')}")
    else:
        print("[-] 节点序号不存在！")
except Exception as e:
    print(f"[-] 移除失败: {e}")
EOF
                fi
                sleep 1.5
                ;;
            3)
                clear
                echo -e "${CYAN}=====================================================${PLAIN}"
                echo -e "${CYAN}             ⚡ 专属一键安装接入命令                  ${PLAIN}"
                echo -e "${CYAN}=====================================================${PLAIN}"
                local token=$(python3 - "$CONFIG_FILE" << 'EOF'
import sys, json
try:
    with open(sys.argv[1], 'r', encoding='utf-8') as f:
        cfg = json.load(f)
    print(cfg.get('telegram', {}).get('bot_token', ''))
except Exception:
    print('')
EOF
)
                local chat_id=$(python3 - "$CONFIG_FILE" << 'EOF'
import sys, json
try:
    with open(sys.argv[1], 'r', encoding='utf-8') as f:
        cfg = json.load(f)
    print(cfg.get('telegram', {}).get('chat_id', ''))
except Exception:
    print('')
EOF
)
                local pub_ip=$(curl -sS -m 4 https://api.ipify.org 2>/dev/null || curl -sS -m 4 ifconfig.me 2>/dev/null || echo "45.130.166.10")
                echo -e "只需在你要纳管监控的${GREEN}任意 Linux VPS 终端${PLAIN}上粘贴运行以下命令："
                echo ""
                echo -e "${YELLOW}curl -fsSL https://raw.githubusercontent.com/firstwxx1/vps-security-monitor/main/install.sh | bash -s -- --token '${token}' --chat '${chat_id}' --master '${pub_ip}:9527' --auto${PLAIN}"
                echo ""
                echo -e "✅ 运行后，该 VPS 将${GREEN}全自动上报登记至本机的 nodes.json${PLAIN}，无需手动干预！"
                echo ""
                read -n 1 -s -r -p "按任意键返回..."
                ;;
            4)
                echo -e "${YELLOW}[*] 正在执行突发安全巡检...${PLAIN}"
                python3 "${SCRIPT_DIR}/vps_security_guard.py" check --interactive
                echo ""
                read -n 1 -s -r -p "按任意键返回..."
                ;;
            0)
                break
                ;;
            *)
                echo -e "${RED}输入无效！${PLAIN}"
                sleep 1
                ;;
        esac
    done
}

# 主菜单循环
main_menu() {
    check_python
    init_config

    while true; do
        clear
        get_status
        echo -e "${PURPLE}=====================================================${PLAIN}"
        echo -e "${PURPLE}         🛡️  VPS 安全巡检与监控终端管理面板          ${PLAIN}"
        echo -e "${PURPLE}=====================================================${PLAIN}"
        echo -e " 机器人通知 : ${TG_STATUS}   Crontab 定时 : ${CRON_STATUS}"
        echo -e " 机器人守护 : ${BOT_DAEMON_STATUS}"
        echo -e " Nginx 日志 : ${NGINX_STATUS}"
        echo -e "${PURPLE}-----------------------------------------------------${PLAIN}"
        echo -e " ${GREEN}1.${PLAIN} 配置 Telegram 报警通知机器人 (Token / Chat ID)"
        echo -e " ${GREEN}2.${PLAIN} 配置受监控的登录/敏感后台路径 (如 /api/v1/auth/login)"
        echo -e " ${GREEN}3.${PLAIN} 配置 SSL 证书监控域名列表"
        echo -e " ${GREEN}4.${PLAIN} 配置 SSH 允许白名单 IP (陌生登录审计)"
        echo -e " ${GREEN}5.${PLAIN} 配置备份校验状态 (R2 / 本地目录 / 自定义命令)"
        echo -e "${PURPLE}-----------------------------------------------------${PLAIN}"
        echo -e " ${CYAN}6.${PLAIN} 🤖 管理 Telegram 交互机器人后台守护 (TG内一键加VPS)"
        echo -e " ${CYAN}7.${PLAIN} 🌐 多 VPS 节点纳管与状态控制 (查看/添加/移除节点)"
        echo -e " ${CYAN}8.${PLAIN} 立即执行：突发攻击增量检测 (check)"
        echo -e " ${CYAN}9.${PLAIN} 立即生成：全天安全日报 (daily)"
        echo -e " ${CYAN}10.${PLAIN} 一键安装 / 更新 Crontab 定时任务"
        echo -e " ${CYAN}11.${PLAIN} 一键卸载 Crontab 定时任务"
        echo -e " ${CYAN}12.${PLAIN} 系统环境与日志排查自检"
        echo -e "${PURPLE}-----------------------------------------------------${PLAIN}"
        echo -e " ${YELLOW}0.${PLAIN} 退出管理菜单"
        echo -e "${PURPLE}=====================================================${PLAIN}"
        read -p "请输入选项 [0-12]: " choice
        case "$choice" in
            1) config_telegram ;;
            2) config_paths ;;
            3) config_ssl ;;
            4) config_ssh_whitelist ;;
            5) config_backup ;;
            6) manage_bot_daemon ;;
            7) manage_nodes ;;
            8) run_manual_check ;;
            9) run_manual_daily ;;
            10) install_crontab ;;
            11) uninstall_crontab ;;
            12) diagnose_system ;;
            0) clear; exit 0 ;;
            *) echo -e "${RED}输入无效，请重新输入！${PLAIN}"; sleep 1 ;;
        esac
    done
}

main_menu
