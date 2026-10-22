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
    apt update -y && apt install -y python3 git curl openssl
elif command -v yum &>/dev/null; then
    yum install -y python3 git curl openssl
elif command -v dnf &>/dev/null; then
    dnf install -y python3 git curl openssl
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
        git pull || true
    else
        echo -e "${YELLOW}[*] 正在从 GitHub 克隆源码...${PLAIN}"
        rm -rf "${INSTALL_DIR}"
        git clone "${REPO_URL}" "${INSTALL_DIR}"
    fi
fi

cd "${INSTALL_DIR}"
chmod +x menu.sh vps_security_guard.py

if [ ! -f "${INSTALL_DIR}/config.json" ]; then
    if [ -f "${INSTALL_DIR}/config.example.json" ]; then
        cp "${INSTALL_DIR}/config.example.json" "${INSTALL_DIR}/config.json"
    fi
fi

# 4. 创建全局快捷命令
ln -sf "${INSTALL_DIR}/menu.sh" "${BIN_LINK}"
chmod +x "${BIN_LINK}"

echo -e "${GREEN}[+] 部署成功！${PLAIN}"
echo -e "你可以随时在任意终端输入命令：${GREEN}vps-guard${PLAIN} 打开管理菜单！"
echo ""
sleep 1

# 5. 如果是交互式终端，直接启动管理菜单
if [ -t 0 ]; then
    exec "${INSTALL_DIR}/menu.sh"
else
    echo -e "请在终端执行: ${GREEN}vps-guard${PLAIN} 开始配置"
fi
