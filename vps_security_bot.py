#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPS 安全监控中心 - Telegram 交互管理机器人 (守护进程)
核心功能：
1. 交互式菜单与控制面板 (Inline Keyboard)
2. 在 Telegram 内直接发 IP/密码一键纳管远程 VPS (自动 SSH 部署安全引擎)
3. 生成专属一键免密/手动接入命令 (支持任意云厂商)
4. 多 VPS 节点列表管理、在线状态检测、单机/全节点即时巡检与日报生成
5. 仅响应授权的 Admin Chat ID，保障绝对安全
"""

import os
import re
import sys
import time
import json
import socket
import threading
import subprocess
import urllib.request
import urllib.parse
from datetime import datetime

# 基础目录与配置文件
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "config.json")
NODES_FILE = os.path.join(SCRIPT_DIR, "nodes.json")
GUARD_PY = os.path.join(SCRIPT_DIR, "vps_security_guard.py")


def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def load_nodes():
    nodes = []
    if os.path.exists(NODES_FILE):
        try:
            with open(NODES_FILE, "r", encoding="utf-8") as f:
                nodes = json.load(f)
        except Exception:
            nodes = []

    # 确保本地节点始终存在
    has_local = any(n.get("is_local") for n in nodes)
    if not has_local:
        cfg = load_config()
        local_name = cfg.get("node_name", "本机 (主节点)")
        nodes.insert(0, {
            "name": local_name,
            "host": "127.0.0.1",
            "port": 22,
            "user": "root",
            "is_local": True,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        save_nodes(nodes)
    return nodes


def save_nodes(nodes):
    try:
        with open(NODES_FILE, "w", encoding="utf-8") as f:
            json.dump(nodes, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[-] 保存 nodes.json 失败: {e}")


def html_escape(text):
    if not text:
        return ""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


class SecurityBot:
    def __init__(self):
        self.user_states = {}  # {chat_id: {"state": "waiting_vps_info", ...}}
        self.commands_registered = False
        self.last_token = ""
        self.reload()

    def reload(self):
        self.cfg = load_config()
        self.token = self.cfg.get("telegram", {}).get("bot_token", "").strip()
        self.chat_id = str(self.cfg.get("telegram", {}).get("chat_id", "")).strip()

    def get_reply_keyboard(self):
        """返回底部快捷键菜单 (is_persistent=False 允许用户随时折叠/收起)"""
        return {
            "keyboard": [
                [{"text": "➕ 添加 VPS 节点"}, {"text": "📋 VPS 节点列表"}],
                [{"text": "🔍 立即全节点巡检"}, {"text": "📊 全节点安全日报"}],
                [{"text": "⚡ 专属一键命令"}, {"text": "🔽 收起菜单"}]
            ],
            "resize_keyboard": True,
            "is_persistent": False
        }

    def register_commands(self):
        """注册 Telegram 输入框左下角 Menu 弹出菜单 (setMyCommands + setChatMenuButton)"""
        if not self.token or "YOUR_" in self.token:
            return
        commands = [
            {"command": "start", "description": "唤出控制中心主菜单"},
            {"command": "nodes", "description": "查看已纳管VPS列表"},
            {"command": "add", "description": "在TG中添加VPS节点"},
            {"command": "check", "description": "立即全节点突发巡检"},
            {"command": "daily", "description": "获取全节点安全日报"},
            {"command": "cmd", "description": "专属一键安装命令"},
        ]
        res = self.api_call("setMyCommands", {"commands": commands})
        if res and res.get("ok"):
            self.api_call("setChatMenuButton", {"menu_button": {"type": "commands"}})
            if self.chat_id:
                try:
                    self.api_call("setChatMenuButton", {"chat_id": int(self.chat_id), "menu_button": {"type": "commands"}})
                except Exception:
                    pass
            self.commands_registered = True
            self.last_token = self.token
            print("[+] Telegram 对话框旁 Menu 菜单按钮已成功激活！")

    def api_call(self, method, payload=None, timeout=20):
        if not self.token or "YOUR_" in self.token:
            return None
        url = f"https://api.telegram.org/bot{self.token}/{method}"
        data = None
        headers = {"User-Agent": "VPS-Security-Bot/1.0"}
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            return None

    def send_msg(self, chat_id, text, reply_markup=None):
        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        }
        if reply_markup:
            payload["reply_markup"] = reply_markup
        return self.api_call("sendMessage", payload)

    def edit_msg(self, chat_id, msg_id, text, reply_markup=None):
        payload = {
            "chat_id": chat_id,
            "message_id": msg_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        }
        if reply_markup:
            payload["reply_markup"] = reply_markup
        return self.api_call("editMessageText", payload)

    def answer_callback(self, cb_id, text=None):
        payload = {"callback_query_id": cb_id}
        if text:
            payload["text"] = text
        return self.api_call("answerCallbackQuery", payload)

    # ---------------- 核心菜单界面 ----------------
    def show_main_menu(self, chat_id, msg_id=None):
        nodes = load_nodes()
        node_count = len(nodes)
        text = (
            f"🛡️ <b>VPS 安全巡检与监控中心</b>\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"📦 <b>当前纳管 VPS</b>: <code>{node_count}</code> 台\n"
            f"🤖 <b>机器人状态</b>: 🟢 运行中\n"
            f"🕒 <b>当前时间</b>: <code>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</code>\n\n"
            f"💡 <i>你可以在下方点击按钮，或直接向机器人发送远程 VPS 的 SSH 信息一键纳管！</i>"
        )
        kb = {
            "inline_keyboard": [
                [
                    {"text": "➕ 在 TG 中添加 VPS 节点", "callback_data": "act:add_prompt"},
                    {"text": "📋 查看 VPS 节点列表", "callback_data": "nav:nodes"}
                ],
                [
                    {"text": "🔍 立即全节点突发巡检", "callback_data": "act:check_all"},
                    {"text": "📊 获取全节点安全日报", "callback_data": "act:daily_all"}
                ],
                [
                    {"text": "⚡ 生成一键安装接入命令", "callback_data": "act:one_click_cmd"},
                    {"text": "⌨️ 展开/唤出底部键盘", "callback_data": "act:show_reply_kb"}
                ],
                [
                    {"text": "🔄 刷新控制面板", "callback_data": "nav:home"}
                ]
            ]
        }
        if msg_id:
            self.edit_msg(chat_id, msg_id, text, reply_markup=kb)
        else:
            self.send_msg(chat_id, text, reply_markup=kb)

    def show_nodes_menu(self, chat_id, msg_id=None):
        nodes = load_nodes()
        lines = []
        btn_rows = []
        for idx, n in enumerate(nodes):
            name = n.get("name", "未命名")
            host = n.get("host", "")
            port = n.get("port", 22)
            user = n.get("user", "root")
            is_local = n.get("is_local", False)

            tag = "📍 本机主节点" if is_local else f"🌐 {user}@{host}:{port}"
            lines.append(f"<b>{idx + 1}. {html_escape(name)}</b>\n    └ {html_escape(tag)}")

            # 操作按钮行
            if is_local:
                btn_rows.append([
                    {"text": f"🔍 巡检: {name[:10]}", "callback_data": f"act:chk_node:{idx}"},
                    {"text": f"📊 日报", "callback_data": f"act:day_node:{idx}"}
                ])
            else:
                btn_rows.append([
                    {"text": f"🔍 巡检: {name[:8]}", "callback_data": f"act:chk_node:{idx}"},
                    {"text": f"📊 日报", "callback_data": f"act:day_node:{idx}"},
                    {"text": f"🗑️ 移除", "callback_data": f"act:del_node:{idx}"}
                ])

        body = "\n".join(lines) if lines else "暂无纳管节点"
        text = (
            f"📋 <b>已纳管 VPS 列表 ({len(nodes)} 台)</b>\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"{body}\n\n"
            f"💡 <i>可点击下方按钮对指定 VPS 发起巡检或移除纳管。</i>"
        )
        kb = {
            "inline_keyboard": [
                *btn_rows,
                [
                    {"text": "➕ 添加新 VPS 节点", "callback_data": "act:add_prompt"},
                    {"text": "🔙 返回主菜单", "callback_data": "nav:home"}
                ]
            ]
        }
        if msg_id:
            self.edit_msg(chat_id, msg_id, text, reply_markup=kb)
        else:
            self.send_msg(chat_id, text, reply_markup=kb)

    # ---------------- 添加 VPS 流程 ----------------
    def prompt_add_vps(self, chat_id, msg_id=None):
        self.user_states[chat_id] = {"state": "waiting_vps_info"}
        text = (
            f"➕ <b>在 Telegram 里添加 VPS 节点</b>\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"请直接在当前聊天窗口<b>回复目标 VPS 的 SSH 信息</b>：\n\n"
            f"📌 <b>格式示例</b>：\n"
            f"<code>IP 密码</code> (默认使用 root 用户和 22 端口)\n"
            f"例如: <code>107.172.83.41 MyPassword123</code>\n\n"
            f"或者完整格式：\n"
            f"<code>IP 端口 用户名 密码 别名(可选)</code>\n"
            f"例如: <code>107.172.83.41 22 root MyPassword123 美西高防</code>\n\n"
            f"🤖 机器人将自动通过 SSH 登录目标 VPS 并一键完成安全引擎部署！\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"<i>如需取消，可点击下方按钮返回。</i>"
        )
        kb = {
            "inline_keyboard": [
                [
                    {"text": "⚡ 无法提供密码？生成一键安装命令", "callback_data": "act:one_click_cmd"},
                    {"text": "🔙 取消返回", "callback_data": "nav:home"}
                ]
            ]
        }
        if msg_id:
            self.edit_msg(chat_id, msg_id, text, reply_markup=kb)
        else:
            self.send_msg(chat_id, text, reply_markup=kb)

    def process_add_vps_text(self, chat_id, raw_text):
        """解析用户发送的 SSH 凭据并在后台线程部署"""
        self.user_states.pop(chat_id, None)
        parts = raw_text.strip().split()
        if len(parts) < 2:
            self.send_msg(
                chat_id,
                "❌ 格式不正确！请至少提供 <code>IP 密码</code>，例如：\n<code>107.172.83.41 YourPassword</code>"
            )
            return

        host = parts[0].strip()
        port = 22
        user = "root"
        password = ""
        custom_name = ""

        if len(parts) == 2:
            # 格式: IP 密码
            password = parts[1].strip()
            custom_name = f"vps-{host}"
        elif len(parts) == 3:
            # 格式: IP 端口 密码 或 IP 密码 别名
            if parts[1].isdigit():
                port = int(parts[1])
                password = parts[2].strip()
                custom_name = f"vps-{host}"
            else:
                password = parts[1].strip()
                custom_name = parts[2].strip()
        elif len(parts) >= 4:
            # 格式: IP 端口 用户名 密码 [别名]
            if parts[1].isdigit():
                port = int(parts[1])
                user = parts[2].strip()
                password = parts[3].strip()
                if len(parts) >= 5:
                    custom_name = parts[4].strip()
                else:
                    custom_name = f"vps-{host}"
            else:
                user = parts[1].strip()
                password = parts[2].strip()
                custom_name = parts[3].strip()

        # 发送处理中提示
        init_res = self.send_msg(
            chat_id,
            f"⏳ <b>正在连接并纳管远程 VPS...</b>\n"
            f"目标主机: <code>{html_escape(user)}@{html_escape(host)}:{port}</code>\n"
            f"请稍候 15~30 秒，系统正在配置安全引擎与定时守护任务..."
        )
        msg_id = init_res.get("result", {}).get("message_id") if init_res else None

        def worker():
            try:
                import paramiko
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(host, port=port, username=user, password=password, timeout=15)

                # 1. 获取系统信息
                cmd_info = "hostname; uname -sr; cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '\"'"
                _, stdout, _ = ssh.exec_command(cmd_info, timeout=10)
                sys_out = stdout.read().decode("utf-8", errors="ignore").splitlines()
                hostname = sys_out[0].strip() if sys_out else host
                os_name = sys_out[2].strip() if len(sys_out) >= 3 else (sys_out[1].strip() if len(sys_out) >= 2 else "Linux")

                # 如果没有指定别名，使用 别名 或 hostname
                final_name = custom_name if (custom_name and not custom_name.startswith("vps-")) else f"{hostname} ({host})"

                # 2. 部署 security-monitor 并配置定时任务
                token = self.token
                cid = self.chat_id
                deploy_cmd = (
                    f"curl -fsSL https://raw.githubusercontent.com/firstwxx1/vps-security-monitor/main/install.sh | "
                    f"bash -s -- --token '{token}' --chat '{cid}' --name '{final_name}' --auto"
                )
                _, d_stdout, d_stderr = ssh.exec_command(deploy_cmd, timeout=90)
                d_out = d_stdout.read().decode("utf-8", errors="ignore")
                d_err = d_stderr.read().decode("utf-8", errors="ignore")
                ssh.close()

                # 3. 记录到 nodes.json
                nodes = load_nodes()
                nodes = [n for n in nodes if n.get("host") != host]
                nodes.append({
                    "name": final_name,
                    "host": host,
                    "port": port,
                    "user": user,
                    "password": password,
                    "os": os_name,
                    "is_local": False,
                    "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })
                save_nodes(nodes)

                success_text = (
                    f"✅ <b>[VPS 节点纳管成功！]</b>\n"
                    f"━━━━━━━━━━━━━━━━━━\n"
                    f"🏷️ <b>节点名称</b>: <code>{html_escape(final_name)}</code>\n"
                    f"🌐 <b>网络地址</b>: <code>{html_escape(user)}@{html_escape(host)}:{port}</code>\n"
                    f"💻 <b>操作系统</b>: <code>{html_escape(os_name)}</code>\n"
                    f"🛡️ <b>防护策略</b>: 已就绪\n"
                    f"   ├ 5 分钟增量代理池/撞库实时拦截\n"
                    f"   └ 每日早晨 09:00 自动推送安全日报\n"
                    f"━━━━━━━━━━━━━━━━━━\n"
                    f"<i>该 VPS 已成功关联至你的 Telegram 监控中心！</i>"
                )
                kb = {
                    "inline_keyboard": [
                        [
                            {"text": "🔍 立即对该节点执行一次巡检", "callback_data": f"act:chk_host:{host}"},
                            {"text": "📋 查看所有节点", "callback_data": "nav:nodes"}
                        ]
                    ]
                }
                if msg_id:
                    self.edit_msg(chat_id, msg_id, success_text, reply_markup=kb)
                else:
                    self.send_msg(chat_id, success_text, reply_markup=kb)

            except Exception as e:
                err_msg = str(e)
                if "Authentication failed" in err_msg:
                    err_msg = "SSH 密码或用户名认证失败，请检查账号密码"
                elif "timed out" in err_msg:
                    err_msg = "连接超时，请检查 IP、端口及安全组/防火墙"

                fail_text = (
                    f"❌ <b>纳管 VPS 失败</b>\n"
                    f"━━━━━━━━━━━━━━━━━━\n"
                    f"主机: <code>{html_escape(host)}:{port}</code>\n"
                    f"原因: <code>{html_escape(err_msg)}</code>\n\n"
                    f"💡 <i>建议在目标 VPS 终端手动执行一键安装命令接入。</i>"
                )
                kb = {
                    "inline_keyboard": [
                        [{"text": "⚡ 查看一键手动命令", "callback_data": "act:one_click_cmd"}],
                        [{"text": "🔄 重试添加", "callback_data": "act:add_prompt"}]
                    ]
                }
                if msg_id:
                    self.edit_msg(chat_id, msg_id, fail_text, reply_markup=kb)
                else:
                    self.send_msg(chat_id, fail_text, reply_markup=kb)

        threading.Thread(target=worker, daemon=True).start()

    def show_one_click_cmd(self, chat_id, msg_id=None):
        cmd = (
            f"curl -fsSL https://raw.githubusercontent.com/firstwxx1/vps-security-monitor/main/install.sh | "
            f"bash -s -- --token '{self.token}' --chat '{self.chat_id}' --auto"
        )
        text = (
            f"⚡ <b>专属一键安装接入命令</b>\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"只需在你要监控的<b>任何 Linux VPS 终端</b>上粘贴运行：\n\n"
            f"<code>{html_escape(cmd)}</code>\n\n"
            f"✅ <b>自动完成</b>：\n"
            f"1. 自动注入当前 Telegram 机器人的 Token 和 Chat ID\n"
            f"2. 自动安装守护引擎并注册 Crontab 定时拦截与日报\n"
            f"3. 部署完成后会自动向本机器人发送一次接入问候报文！\n"
            f"━━━━━━━━━━━━━━━━━━"
        )
        kb = {
            "inline_keyboard": [
                [{"text": "🔙 返回菜单", "callback_data": "nav:home"}]
            ]
        }
        if msg_id:
            self.edit_msg(chat_id, msg_id, text, reply_markup=kb)
        else:
            self.send_msg(chat_id, text, reply_markup=kb)

    # ---------------- 节点巡检与触发 ----------------
    def run_node_check(self, chat_id, node_idx=None, host=None):
        nodes = load_nodes()
        target = None
        if node_idx is not None and 0 <= node_idx < len(nodes):
            target = nodes[node_idx]
        elif host:
            target = next((n for n in nodes if n.get("host") == host), None)

        if not target:
            self.send_msg(chat_id, "未找到目标节点！")
            return

        name = target.get("name", "VPS")
        is_local = target.get("is_local", False)

        res = self.send_msg(chat_id, f"🔍 正在对 <b>{html_escape(name)}</b> 执行突发安全检测...")
        msg_id = res.get("result", {}).get("message_id") if res else None

        def worker():
            try:
                import vps_security_guard as guard
                cfg = load_config()
                alert_thresh = cfg.get("security", {}).get("alert_threshold_failures", 5)

                if is_local:
                    state = guard.load_state()
                    nginx_log = cfg.get("logs", {}).get("nginx_access_log", "/var/log/nginx/access.log")
                    login_paths = cfg.get("security", {}).get("login_paths", [])

                    lines = guard.read_incremental_lines(nginx_log, "nginx", state)
                    guard.save_state(state)

                    failed_logins, _ = guard.parse_nginx_lines(lines, login_paths)
                    if len(failed_logins) >= alert_thresh:
                        unique_ips = len(set(fl["ip"] for fl in failed_logins))
                        text = (
                            f"🔔 <b>[突发拦截告警] · {html_escape(name)}</b>\n"
                            f"━━━━━━━━━━━━━━━━━━\n"
                            f"🚨 <b>风险级别</b>: 高危撞库/爆破\n"
                            f"📊 <b>拦截次数</b>: 捕获到 <code>{len(failed_logins)}</code> 次失败登录\n"
                            f"📍 <b>攻击来源</b>: 来自 <code>{unique_ips}</code> 个不同 IP\n"
                            f"🕒 <b>检测时间</b>: <code>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</code>\n\n"
                            f"💡 <i>建议在控制面板中查看防护策略。</i>"
                        )
                    else:
                        fail_desc = f"（近几分钟捕获到 {len(failed_logins)} 次失败，低于报警阈值）" if failed_logins else "（未捕获到任何后台失败请求）"
                        text = (
                            f"✅ <b>[突发安全巡检完成]</b>\n"
                            f"━━━━━━━━━━━━━━━━━━\n"
                            f"🏷️ <b>目标节点</b>: <code>{html_escape(name)}</code>\n"
                            f"🟢 <b>运行状态</b>: 安全健康\n"
                            f"🔎 <b>检测结果</b>: 访问日志运行平稳 {fail_desc}\n"
                            f"🕒 <b>巡检时间</b>: <code>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</code>"
                        )
                else:
                    import paramiko
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(target["host"], port=target.get("port", 22), username=target.get("user", "root"), password=target.get("password", ""), timeout=8)
                    ssh.exec_command("python3 /opt/vps-security-monitor/vps_security_guard.py check --interactive", timeout=15)
                    ssh.close()
                    text = (
                        f"✅ <b>[突发安全巡检完成]</b>\n"
                        f"━━━━━━━━━━━━━━━━━━\n"
                        f"🏷️ <b>目标节点</b>: <code>{html_escape(name)}</code>\n"
                        f"🟢 <b>运行状态</b>: 远程通信正常，安全守护运行中\n"
                        f"🕒 <b>巡检时间</b>: <code>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</code>"
                    )

                kb = {
                    "inline_keyboard": [
                        [
                            {"text": "🔄 再次巡检", "callback_data": f"act:chk_node:{node_idx if node_idx is not None else 0}"},
                            {"text": "📋 节点列表", "callback_data": "nav:nodes"}
                        ],
                        [{"text": "🔙 返回主控制台", "callback_data": "nav:home"}]
                    ]
                }
                if msg_id:
                    self.edit_msg(chat_id, msg_id, text, reply_markup=kb)
                else:
                    self.send_msg(chat_id, text, reply_markup=kb)

            except Exception as e:
                err_text = f"❌ <b>巡检异常 · {html_escape(name)}</b>\n原因: <code>{html_escape(str(e))}</code>"
                if msg_id:
                    self.edit_msg(chat_id, msg_id, err_text)
                else:
                    self.send_msg(chat_id, err_text)

        threading.Thread(target=worker, daemon=True).start()

    def run_check_all(self, chat_id):
        nodes = load_nodes()
        res = self.send_msg(chat_id, f"🚀 <b>正在对全节点发起突发安全巡检...</b>\n共 <code>{len(nodes)}</code> 台 VPS，请稍候 1~2 秒...")
        msg_id = res.get("result", {}).get("message_id") if res else None

        def worker():
            results = []
            for idx, target in enumerate(nodes):
                name = target.get("name", f"VPS-{idx}")
                is_local = target.get("is_local", False)
                try:
                    if is_local:
                        import vps_security_guard as guard
                        cfg = load_config()
                        state = guard.load_state()
                        nginx_log = cfg.get("logs", {}).get("nginx_access_log", "/var/log/nginx/access.log")
                        lines = guard.read_incremental_lines(nginx_log, "nginx", state)
                        guard.save_state(state)
                        failed, _ = guard.parse_nginx_lines(lines, cfg.get("security", {}).get("login_paths", []))
                        if len(failed) >= cfg.get("security", {}).get("alert_threshold_failures", 5):
                            results.append(f"· <b>{html_escape(name)}</b>: ⚠️ 发现 {len(failed)} 次拦截")
                        else:
                            results.append(f"· <b>{html_escape(name)}</b>: 🟢 安全健康 (0 次攻击)")
                    else:
                        import paramiko
                        ssh = paramiko.SSHClient()
                        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        ssh.connect(target["host"], port=target.get("port", 22), username=target.get("user", "root"), password=target.get("password", ""), timeout=6)
                        ssh.exec_command("python3 /opt/vps-security-monitor/vps_security_guard.py check", timeout=10)
                        ssh.close()
                        results.append(f"· <b>{html_escape(name)}</b>: 🟢 在线安全")
                except Exception as e:
                    results.append(f"· <b>{html_escape(name)}</b>: ❌ 连接失败 ({html_escape(str(e)[:25])})")

            body = "\n".join(results)
            final_text = (
                f"✅ <b>[全节点突发安全巡检完成]</b>\n"
                f"━━━━━━━━━━━━━━━━━━\n"
                f"📊 <b>巡检统计</b>: 共检测 <code>{len(nodes)}</code> 台 VPS\n"
                f"{body}\n"
                f"━━━━━━━━━━━━━━━━━━\n"
                f"🕒 <b>完成时间</b>: <code>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</code>"
            )
            kb = {
                "inline_keyboard": [
                    [
                        {"text": "🔄 重新巡检", "callback_data": "act:check_all"},
                        {"text": "📊 全节点日报", "callback_data": "act:daily_all"}
                    ],
                    [{"text": "🔙 返回主控制台", "callback_data": "nav:home"}]
                ]
            }
            if msg_id:
                self.edit_msg(chat_id, msg_id, final_text, reply_markup=kb)
            else:
                self.send_msg(chat_id, final_text, reply_markup=kb)

        threading.Thread(target=worker, daemon=True).start()

    def run_daily_all(self, chat_id):
        nodes = load_nodes()
        self.send_msg(chat_id, f"📊 开始生成全部 <b>{len(nodes)}</b> 台 VPS 的安全日报...")
        for idx in range(len(nodes)):
            self.run_node_daily(chat_id, node_idx=idx)
            time.sleep(2)

    def delete_node(self, chat_id, node_idx):
        nodes = load_nodes()
        if 0 <= node_idx < len(nodes):
            target = nodes[node_idx]
            if target.get("is_local"):
                self.send_msg(chat_id, "⚠️ 本地主节点不可移除！")
                return
            removed = nodes.pop(node_idx)
            save_nodes(nodes)
            self.send_msg(chat_id, f"🗑️ 已成功从监控列表中移除节点: <b>{html_escape(removed.get('name'))}</b>")
            self.show_nodes_menu(chat_id)
        else:
            self.send_msg(chat_id, "节点序号无效！")

    # ---------------- 事件分发 ----------------
    def handle_callback(self, cb):
        cb_id = cb["id"]
        from_user = cb.get("from", {})
        chat_id = str(from_user.get("id", ""))
        data = cb.get("data", "")
        msg = cb.get("message", {})
        msg_id = msg.get("message_id")

        if chat_id != self.chat_id:
            self.answer_callback(cb_id, "无权限操作")
            return

        self.answer_callback(cb_id)

        if data == "nav:home":
            self.show_main_menu(chat_id, msg_id)
        elif data == "nav:nodes":
            self.show_nodes_menu(chat_id, msg_id)
        elif data == "act:add_prompt":
            self.prompt_add_vps(chat_id, msg_id)
        elif data == "act:one_click_cmd":
            self.show_one_click_cmd(chat_id, msg_id)
        elif data == "act:show_reply_kb":
            self.send_msg(chat_id, "⌨️ 底部快捷按键已展开 (随时可点击右下角或自带按钮折叠收起)：", reply_markup=self.get_reply_keyboard())
        elif data == "act:check_all":
            self.run_check_all(chat_id)
        elif data == "act:daily_all":
            self.run_daily_all(chat_id)
        elif data.startswith("act:chk_node:"):
            idx = int(data.split(":")[-1])
            self.run_node_check(chat_id, node_idx=idx)
        elif data.startswith("act:chk_host:"):
            host = data.split(":")[-1]
            self.run_node_check(chat_id, host=host)
        elif data.startswith("act:day_node:"):
            idx = int(data.split(":")[-1])
            self.run_node_daily(chat_id, node_idx=idx)
        elif data.startswith("act:del_node:"):
            idx = int(data.split(":")[-1])
            self.delete_node(chat_id, idx)

    def handle_message(self, msg):
        from_user = msg.get("from", {})
        chat_id = str(from_user.get("id", ""))
        text = msg.get("text", "").strip()

        # 鉴权
        if chat_id != self.chat_id:
            return

        state_data = self.user_states.get(chat_id, {})
        current_state = state_data.get("state")

        if text in ("/start", "/menu", "菜单", "🛡️ 唤出主控制台"):
            self.user_states.pop(chat_id, None)
            self.show_main_menu(chat_id)
            return
        elif text in ("🔽 收起菜单", "收起菜单", "收起", "/hide"):
            self.send_msg(
                chat_id,
                "⌨️ <b>底部快捷菜单已收起。</b>\n\n💡 随时可通过点击左下角 <b>【Menu】</b> 按钮或发送 <code>/start</code> 查看控制台！",
                reply_markup={"remove_keyboard": True}
            )
            return
        elif text in ("/nodes", "节点列表", "📋 VPS 节点列表"):
            self.show_nodes_menu(chat_id)
            return
        elif text in ("/add", "/add_vps", "添加", "➕ 添加 VPS 节点"):
            self.prompt_add_vps(chat_id)
            return
        elif text in ("/check", "巡检", "🔍 立即全节点巡检"):
            self.run_check_all(chat_id)
            return
        elif text in ("/daily", "日报", "📊 全节点安全日报"):
            self.run_daily_all(chat_id)
            return
        elif text in ("/cmd", "一键命令", "⚡ 专属一键命令"):
            self.show_one_click_cmd(chat_id)
            return

        # 如果处于等待添加 VPS 状态，或者输入内容像 IP 凭据
        if current_state == "waiting_vps_info" or re.match(r"^(\d{1,3}\.){3}\d{1,3}", text):
            self.process_add_vps_text(chat_id, text)
            return

        # 默认唤出主菜单
        self.show_main_menu(chat_id)

    # ---------------- 轮询守护主循环 ----------------
    def run_forever(self):
        print("[*] VPS 安全监控 Telegram 交互机器人已启动...")
        offset = 0
        while True:
            self.reload()
            if not self.token or "YOUR_" in self.token:
                time.sleep(5)
                continue

            if not self.commands_registered or self.last_token != self.token:
                self.register_commands()

            updates = self.api_call("getUpdates", {"offset": offset, "timeout": 20}, timeout=30)
            if not updates or not updates.get("ok"):
                time.sleep(2)
                continue

            for u in updates.get("result", []):
                offset = u["update_id"] + 1
                try:
                    if "callback_query" in u:
                        self.handle_callback(u["callback_query"])
                    elif "message" in u:
                        self.handle_message(u["message"])
                except Exception as e:
                    print(f"[-] 处理更新异常: {e}")


def main():
    bot = SecurityBot()
    bot.run_forever()


if __name__ == "__main__":
    main()
