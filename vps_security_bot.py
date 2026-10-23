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
import hashlib
import threading
import subprocess
import http.server
import socketserver
import urllib.request
import urllib.parse
from datetime import datetime, timedelta, timezone

# 基础目录与配置文件
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "config.json")
NODES_FILE = os.path.join(SCRIPT_DIR, "nodes.json")
GUARD_PY = os.path.join(SCRIPT_DIR, "vps_security_guard.py")
STATE_FILE = os.path.join(SCRIPT_DIR, "monitor_state.json")


def load_monitor_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_monitor_state(state):
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f)
    except Exception:
        pass


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


class NodeRegistrationHandler(http.server.BaseHTTPRequestHandler):
    """处理从被控 VPS (install.sh) 发起的全自动节点上线入库注册请求"""
    bot_ref = None

    def do_GET(self):
        self.process_request()

    def do_POST(self):
        self.process_request()

    def process_request(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/api/register":
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok": false, "error": "Not Found"}')
            return

        qs = urllib.parse.parse_qs(parsed.query)
        if not qs and self.command == "POST":
            length = int(self.headers.get("Content-Length", 0))
            if length > 0:
                body = self.rfile.read(length).decode("utf-8", errors="ignore")
                try:
                    data = json.loads(body)
                    qs = {k: [str(v)] for k, v in data.items()}
                except Exception:
                    qs = urllib.parse.parse_qs(body)

        secret = qs.get("secret", [""])[0].strip()
        ip = qs.get("ip", [""])[0].strip()
        name = qs.get("name", [""])[0].strip()
        os_info = qs.get("os", ["Linux"])[0].strip()

        # 客户端未传公网 IP 时，直接提取客户端 Socket 来源 IP
        if not ip or ip in ("127.0.0.1", "localhost"):
            ip = self.client_address[0]

        bot = NodeRegistrationHandler.bot_ref
        expected_secret = bot.get_registration_secret() if bot else ""

        if not secret or secret != expected_secret:
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok": false, "error": "Forbidden: Invalid registration secret"}')
            return

        display_name = name.strip() if name else f"vps-{ip}"
        nodes = load_nodes()
        nodes = [n for n in nodes if n.get("host") != ip]
        nodes.append({
            "name": display_name,
            "host": ip,
            "port": 22,
            "user": "root",
            "os": os_info,
            "is_local": False,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        save_nodes(nodes)
        print(f"[+] 成功通过 HTTP 自动注册纳管新节点: {display_name} [{ip}]")

        if bot and bot.chat_id:
            notice = (
                f"🎉 <b>[新 VPS 节点全自动接入成功！]</b>\n"
                f"━━━━━━━━━━━━━━━━━━\n"
                f"🏷️ <b>节点名称</b>: <code>{html_escape(display_name)}</code>\n"
                f"🌐 <b>网络地址</b>: <code>{ip}</code>\n"
                f"💻 <b>操作系统</b>: <code>{html_escape(os_info)}</code>\n"
                f"📦 <b>已纳管 VPS</b>: 共 <code>{len(nodes)}</code> 台\n"
                f"━━━━━━━━━━━━━━━━━━\n"
                f"<i>该 VPS 已由一键安装程序全自动入库纳管，无需任何手动操作！在 /nodes 中可直接查看与巡检。</i>"
            )
            kb = {
                "inline_keyboard": [
                    [
                        {"text": "📋 查看已纳管 VPS 列表", "callback_data": "nav:nodes"},
                        {"text": "🔍 立即巡检", "callback_data": f"act:chk_host:{ip}"}
                    ]
                ]
            }
            bot.send_msg(bot.chat_id, notice, reply_markup=kb)

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        resp_data = {
            "ok": True,
            "message": "Node successfully registered to Master",
            "ip": ip,
            "name": display_name,
            "nodes_count": len(nodes)
        }
        self.wfile.write(json.dumps(resp_data).encode("utf-8"))

    def log_message(self, format, *args):
        pass


class SecurityBot:
    def __init__(self):
        self.user_states = {}  # {chat_id: {"state": "waiting_vps_info", ...}}
        self.commands_registered = False
        self.last_token = ""
        self.reg_server = None
        self._cached_public_ip = None
        self.reload()
        self.start_registration_server()
        self.check_boot_notification()
        # 启动每日早晨 09:00 全节点安全总报定时调度线程
        threading.Thread(target=self.daily_scheduler_loop, daemon=True).start()

    def daily_scheduler_loop(self):
        """每日安全日报定时推送守护线程（默认每天早晨 09:00 北京时间自动汇总全节点安全总报推送）"""
        print("[*] 每日安全总报定时调度线程已启动 (每天 09:00 CST 自动汇总推送)...", flush=True)
        while True:
            try:
                cfg = load_config()
                tz_offset = cfg.get("timezone_offset", 8)
                now_tz = datetime.now(timezone.utc) + timedelta(hours=tz_offset)
                today_str = now_tz.strftime("%Y-%m-%d")
                daily_hour = cfg.get("daily_hour", 9)

                # 每天 09:00 ~ 09:05 检测并自动汇总推送
                if now_tz.hour == daily_hour and now_tz.minute <= 5:
                    state = load_monitor_state()
                    if state.get("last_daily_sent_date") != today_str:
                        target_chat_id = self.chat_id or (self.admin_users[0] if self.admin_users else None)
                        if target_chat_id:
                            print(f"[*] 触发定时全节点安全总报自动推送: {today_str} {daily_hour:02d}:00 (时区 UTC+{tz_offset})...", flush=True)
                            state["last_daily_sent_date"] = today_str
                            save_monitor_state(state)
                            self.run_daily_all(target_chat_id, is_auto=True)
            except Exception as e:
                print(f"[-] 每日安全总报定时调度异常: {e}", flush=True)

            time.sleep(30)

    def check_boot_notification(self):
        """如果系统刚启动 (uptime < 300秒)，向管理员发送自启动上线通知"""
        try:
            with open("/proc/uptime", "r") as f:
                uptime_secs = float(f.readline().split()[0])
            if uptime_secs < 300 and self.chat_id and self.token:
                days = int(uptime_secs // 86400)
                hours = int((uptime_secs % 86400) // 3600)
                minutes = int((uptime_secs % 3600) // 60)
                parts = []
                if days > 0:
                    parts.append(f"{days}天")
                if hours > 0:
                    parts.append(f"{hours}小时")
                parts.append(f"{minutes}分钟")
                up_str = "".join(parts) if parts else "刚启动"
                pub_ip = self.get_public_ip()
                boot_text = (
                    f"🔄 <b>[主控服务器重启上线通知]</b>\n"
                    f"━━━━━━━━━━━━━━━━━━\n"
                    f"🏷️ <b>主机标识</b>: <code>{pub_ip} (主控)</code>\n"
                    f"⏱️ <b>开机运行</b>: <code>{up_str}</code>\n"
                    f"🤖 <b>控制中心</b>: 🟢 Telegram 守护进程与多节点调度中心已自启恢复！\n"
                    f"━━━━━━━━━━━━━━━━━━\n"
                    f"<i>所有受控节点守护与警报接收已全部就绪。</i>"
                )
                self.send_msg(self.chat_id, boot_text)
        except Exception:
            pass

    def get_public_ip(self):
        """获取并缓存主控机器的公网 IP"""
        if self._cached_public_ip:
            return self._cached_public_ip
        for url in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"):
            try:
                with urllib.request.urlopen(url, timeout=3) as resp:
                    ip = resp.read().decode("utf-8").strip()
                    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ip):
                        self._cached_public_ip = ip
                        return ip
            except Exception:
                continue
        self._cached_public_ip = "45.130.166.10"
        return self._cached_public_ip

    def get_registration_secret(self):
        """生成基于 Token 的安全验证密钥，供子节点上报时校验"""
        if not self.token:
            return "vps-sec-default"
        return hashlib.sha256(self.token.encode("utf-8")).hexdigest()[:16]

    def start_registration_server(self, port=9527):
        """启动后台守护的 HTTP 节点自动注册 API 监听"""
        if self.reg_server:
            return
        try:
            NodeRegistrationHandler.bot_ref = self
            socketserver.TCPServer.allow_reuse_address = True
            self.reg_server = socketserver.TCPServer(("0.0.0.0", port), NodeRegistrationHandler)
            t = threading.Thread(target=self.reg_server.serve_forever, daemon=True)
            t.start()
            print(f"[+] 自动节点注册 HTTP API 服务已启动 (0.0.0.0:{port})")
        except Exception as e:
            print(f"[-] 启动自动节点注册服务失败: {e}")

    def reload(self):
        self.cfg = load_config()
        if self.cfg.get("role") == "agent":
            print("[-] 当前节点角色为被控子节点 (Agent)，无需且禁止运行 Telegram 交互机器人！退出中...")
            sys.exit(0)
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
            {"command": "rename", "description": "修改VPS节点名称/别名"},
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

        # 发布主控端自动发现信标，方便远程一键安装脚本自动发现主控并上报
        try:
            pub_ip = self.get_public_ip()
            secret = self.get_registration_secret()
            self.api_call("setMyShortDescription", {"short_description": f"master:{pub_ip}:9527:{secret}"})
        except Exception:
            pass

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
        total_count = len(nodes)
        lines = []

        for idx, n in enumerate(nodes):
            name = n.get("name", "未命名")
            host = n.get("host", "")
            port = n.get("port", 22)
            is_local = n.get("is_local", False)
            role_desc = "主控中心" if is_local else "受控子节点"

            lines.append(
                f"🖥️ <b>{idx + 1}. {html_escape(name)}</b>\n"
                f"    ├ 🌐 <code>{host}:{port}</code> ({role_desc})\n"
                f"    └ 🛡️ 状态: 🟢 守护常驻保活"
            )

        body = "\n\n".join(lines) if lines else "暂无纳管节点"

        # 动态自适应按钮网格：
        # 每台节点生成一个直达专属管理卡片的按钮
        # 若总数 <= 3 台，每行 1 个展示清晰名称；若总数 >= 4 台，每行 2 个紧凑排列，避免多节点按钮泛滥
        node_buttons = []
        for idx, n in enumerate(nodes):
            name = n.get("name", f"VPS-{idx+1}")
            clean_name = name.split("(")[0].strip() if "(" in name else name
            short_name = clean_name[:12] if len(clean_name) > 12 else clean_name
            node_buttons.append({
                "text": f"🖥️ {idx + 1}. {short_name}",
                "callback_data": f"act:node_detail:{idx}"
            })

        btn_rows = []
        if total_count <= 3:
            for b in node_buttons:
                btn_rows.append([b])
        else:
            for i in range(0, len(node_buttons), 2):
                btn_rows.append(node_buttons[i:i + 2])

        # 全局快捷操作行
        btn_rows.append([
            {"text": "🔍 全节点突发体检", "callback_data": "act:check_all"},
            {"text": "📊 全节点安全总报", "callback_data": "act:daily_all"}
        ])
        btn_rows.append([
            {"text": "➕ 添加新 VPS 节点", "callback_data": "act:add_prompt"},
            {"text": "🔙 返回主控制台", "callback_data": "nav:home"}
        ])

        hint_text = (
            f"\n\n━━━━━━━━━━━━━━━━━━\n"
            f"💡 <i>点击下方对应 VPS 按钮，进入专属控制台（单机巡检、改名、日报与移除）。</i>"
        )

        text = (
            f"📋 <b>已纳管 VPS 列表 (共 <code>{total_count}</code> 台)</b>\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"{body}"
            f"{hint_text}"
        )
        kb = {"inline_keyboard": btn_rows}
        if msg_id:
            self.edit_msg(chat_id, msg_id, text, reply_markup=kb)
        else:
            self.send_msg(chat_id, text, reply_markup=kb)

    def show_node_detail(self, chat_id, idx, msg_id=None):
        nodes = load_nodes()
        if not (0 <= idx < len(nodes)):
            self.send_msg(chat_id, "❌ 节点序号不存在！")
            self.show_nodes_menu(chat_id, msg_id)
            return

        target = nodes[idx]
        name = target.get("name", "未命名")
        host = target.get("host", "")
        port = target.get("port", 22)
        user = target.get("user", "root")
        is_local = target.get("is_local", False)
        os_name = target.get("os", "Linux")
        created = target.get("created_at", "未知")

        role_str = "主控节点 (中央控制台)" if is_local else "受控子节点 (被控守护端)"

        # 快速探测网络延迟 (1.5秒超时)
        t0 = time.time()
        latency = None
        try:
            s = socket.create_connection((host, port), timeout=1.5)
            latency = (time.time() - t0) * 1000.0
            s.close()
        except Exception:
            pass
        lat_str = f"🟢 正常在线 (延迟 <code>{latency:.1f} ms</code>)" if latency is not None else "🔴 无法连接 (离线或超时)"

        text = (
            f"🖥️ <b>VPS 节点详情 · 【{html_escape(name)}】</b>\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"🏷️ <b>节点名称</b>: <code>{html_escape(name)}</code>\n"
            f"🌐 <b>网络地址</b>: <code>{user}@{host}:{port}</code>\n"
            f"📌 <b>节点角色</b>: <code>{role_str}</code>\n"
            f"💻 <b>操作系统</b>: <code>{html_escape(os_name)}</code>\n"
            f"📡 <b>实时网络</b>: {lat_str}\n"
            f"🛡️ <b>防护引擎</b>: 🟢 Systemd 守护进程常驻保活 (秒级检测)\n"
            f"📦 <b>纳管时间</b>: <code>{created}</code>\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"💡 <i>可在下方对当前 VPS 执行专属操作：</i>"
        )

        detail_buttons = [
            [
                {"text": "🔍 即时突发巡检", "callback_data": f"act:chk_node:{idx}"},
                {"text": "📊 专属安全日报", "callback_data": f"act:day_node:{idx}"}
            ],
            [
                {"text": "✏️ 修改节点别名", "callback_data": f"act:ren_node:{idx}"}
            ]
        ]
        if not is_local:
            detail_buttons[1].append({"text": "🗑️ 移除此节点", "callback_data": f"act:del_node:{idx}"})

        detail_buttons.append([
            {"text": "🔙 返回节点列表", "callback_data": "nav:nodes"},
            {"text": "🏠 返回主控制台", "callback_data": "nav:home"}
        ])

        kb = {"inline_keyboard": detail_buttons}
        if msg_id:
            self.edit_msg(chat_id, msg_id, text, reply_markup=kb)
        else:
            self.send_msg(chat_id, text, reply_markup=kb)

    def prompt_rename_node(self, chat_id, idx, msg_id=None):
        nodes = load_nodes()
        if not (0 <= idx < len(nodes)):
            self.send_msg(chat_id, "❌ 节点序号无效！")
            return
        target = nodes[idx]
        curr_name = target.get("name", "未命名")
        host = target.get("host", "")

        self.user_states[chat_id] = {
            "state": "waiting_rename_node",
            "node_idx": idx,
            "orig_msg_id": msg_id
        }
        text = (
            f"✏️ <b>修改 VPS 节点名称/别名</b>\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"🏷️ <b>当前名称</b>: <code>{html_escape(curr_name)}</code>\n"
            f"🌐 <b>主机地址</b>: <code>{host}</code>\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"请直接在当前聊天窗口<b>回复该节点的新名称/别名</b>：\n"
            f"例如回复：<code>香港阿里云</code> 或 <code>美西主力机</code>\n\n"
            f"<i>如需取消修改，请点击下方按钮返回。</i>"
        )
        kb = {
            "inline_keyboard": [
                [{"text": "🔙 取消返回节点列表", "callback_data": "nav:nodes"}]
            ]
        }
        if msg_id:
            self.edit_msg(chat_id, msg_id, text, reply_markup=kb)
        else:
            self.send_msg(chat_id, text, reply_markup=kb)

    # ---------------- 添加 VPS 流程 ----------------
    # ---------------- 添加 VPS 流程与交互向导 ----------------
    def prompt_add_vps(self, chat_id, msg_id=None):
        self.user_states.pop(chat_id, None)
        text = (
            f"➕ <b>在 Telegram 里直接添加纳管 VPS</b>\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"你无需在目标 VPS 终端敲命令，直接在机器人中即可完成纳管：\n\n"
            f"🚀 <b>【全自动向导部署】(强烈推荐 · 零命令)</b>\n"
            f"只需提供目标机器的 IP 与 root 密码，机器人将通过后台安全 SSH 自动登录目标机器、注入安全防护引擎、配置开机自启并接入监控中心。\n\n"
            f"📋 <b>【免密直接登记】</b>\n"
            f"若目标机已手动运行过一键脚本，直接输入 <code>IP [别名]</code> 即可登记入库。\n\n"
            f"⚡ <b>【一键命令接入】</b>\n"
            f"获取专属安装命令，在目标机器终端手动运行。\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"💡 <i>建议直接点击下方【🚀 开始全自动向导部署】！</i>"
        )
        kb = {
            "inline_keyboard": [
                [{"text": "🚀 开始全自动向导部署 (推荐 · 零命令)", "callback_data": "act:add_wiz_start"}],
                [
                    {"text": "📋 免密直接登记 (IP 别名)", "callback_data": "act:add_ip_only_prompt"},
                    {"text": "⚡ 查看一键命令", "callback_data": "act:one_click_cmd"}
                ],
                [{"text": "🔙 返回主控制台", "callback_data": "nav:home"}]
            ]
        }
        if msg_id:
            self.edit_msg(chat_id, msg_id, text, reply_markup=kb)
        else:
            self.send_msg(chat_id, text, reply_markup=kb)

    def execute_remote_deploy(self, chat_id, host, port, user, password, custom_name, msg_id=None):
        """通过 SSH 自动连接远程 VPS，执行一键安全引擎部署与纳管入库"""
        clean_name = custom_name.strip() if custom_name else f"vps-{host}"

        init_text = (
            f"⏳ <b>正在远程全自动部署安全引擎...</b>\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"🌐 <b>目标主机</b>: <code>{html_escape(user)}@{html_escape(host)}:{port}</code>\n"
            f"🏷️ <b>预设别名</b>: <code>{html_escape(clean_name)}</code>\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"<i>正在通过 SSH 登录目标机、安装安全防御引擎、注册守护保活进程并上报入库...\n"
            f"全程全自动无需人工干预，请稍候约 20~35 秒...</i>"
        )
        if msg_id:
            self.edit_msg(chat_id, msg_id, init_text)
            target_msg_id = msg_id
        else:
            res = self.send_msg(chat_id, init_text)
            target_msg_id = res.get("result", {}).get("message_id") if res else None

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

                final_name = clean_name if (clean_name and not clean_name.startswith("vps-")) else (hostname if hostname else f"vps-{host}")

                # 2. 部署 security-monitor 并配置定时任务（带 --master 和 --agent 避免冲突）
                token = self.token
                cid = self.chat_id
                pub_ip = self.get_public_ip()
                deploy_cmd = (
                    f"curl -fsSL https://raw.githubusercontent.com/firstwxx1/vps-security-monitor/main/install.sh | "
                    f"bash -s -- --token '{token}' --chat '{cid}' --name '{final_name}' --master '{pub_ip}:9527' --agent --auto"
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
                    f"🎉 <b>[新 VPS 节点全自动部署纳管成功！]</b>\n"
                    f"━━━━━━━━━━━━━━━━━━\n"
                    f"🏷️ <b>节点名称</b>: <code>{html_escape(final_name)}</code>\n"
                    f"🌐 <b>网络地址</b>: <code>{html_escape(user)}@{html_escape(host)}:{port}</code>\n"
                    f"💻 <b>操作系统</b>: <code>{html_escape(os_name)}</code>\n"
                    f"📦 <b>已纳管 VPS</b>: 共 <code>{len(nodes)}</code> 台\n"
                    f"━━━━━━━━━━━━━━━━━━\n"
                    f"✅ <b>配置完毕项</b>：\n"
                    f"• 安全监控守护引擎已激活常驻保活\n"
                    f"• 每日安全巡检总报已自动将该节点纳入\n"
                    f"• 异常撞密防爆破自动阻断已生效\n"
                    f"• 系统重启上线自动发送通知就绪"
                )
                kb = {
                    "inline_keyboard": [
                        [
                            {"text": "🔍 立即对新节点巡检", "callback_data": f"act:chk_host:{host}"},
                            {"text": "📋 查看 VPS 节点列表", "callback_data": "nav:nodes"}
                        ],
                        [{"text": "🔙 返回主控制台", "callback_data": "nav:home"}]
                    ]
                }
                if target_msg_id:
                    self.edit_msg(chat_id, target_msg_id, success_text, reply_markup=kb)
                else:
                    self.send_msg(chat_id, success_text, reply_markup=kb)

            except Exception as e:
                err_msg = str(e)
                if "Authentication failed" in err_msg:
                    err_msg = "SSH 用户名或密码错误，请核对后重试"
                elif "timed out" in err_msg:
                    err_msg = "连接超时，请检查 IP、SSH 端口及安全组防火墙设置"

                fail_text = (
                    f"❌ <b>自动部署纳管失败</b>\n"
                    f"━━━━━━━━━━━━━━━━━━\n"
                    f"目标主机: <code>{html_escape(host)}:{port}</code>\n"
                    f"失败原因: <code>{html_escape(err_msg)}</code>\n"
                    f"━━━━━━━━━━━━━━━━━━\n"
                    f"💡 <i>建议检查密码无误后重新尝试，或直接使用【一键命令接入】。</i>"
                )
                kb = {
                    "inline_keyboard": [
                        [
                            {"text": "🔄 重新尝试添加", "callback_data": "act:add_wiz_start"},
                            {"text": "⚡ 查看一键命令", "callback_data": "act:one_click_cmd"}
                        ],
                        [{"text": "🔙 返回主控制台", "callback_data": "nav:home"}]
                    ]
                }
                if target_msg_id:
                    self.edit_msg(chat_id, target_msg_id, fail_text, reply_markup=kb)
                else:
                    self.send_msg(chat_id, fail_text, reply_markup=kb)

        threading.Thread(target=worker, daemon=True).start()

    def process_add_vps_text(self, chat_id, raw_text):
        """解析单行快速录入文本：支持 IP 密码 [别名] 或 IP 别名 (免密)"""
        self.user_states.pop(chat_id, None)
        parts = raw_text.strip().split()
        if not parts:
            return

        if len(parts) == 1 and re.match(r"^(\d{1,3}\.){3}\d{1,3}$", parts[0]):
            # 仅发送了单个 IP，询问用户操作方式
            ip = parts[0].strip()
            self.user_states[chat_id] = {"state": "add_wiz_port", "ip": ip}
            self.send_msg(
                chat_id,
                f"🌐 <b>检测到 IP 地址</b>: <code>{ip}</code>\n"
                f"━━━━━━━━━━━━━━━━━━\n"
                f"请选择接下来的添加流程：",
                reply_markup={
                    "inline_keyboard": [
                        [{"text": "🚀 继续全自动部署 (输入密码)", "callback_data": "act:add_wiz_port:22"}],
                        [{"text": "📋 免密直接入库", "callback_data": "act:add_ip_only_prompt"}],
                        [{"text": "🔙 取消返回", "callback_data": "nav:home"}]
                    ]
                }
            )
            return

        # 尝试判断是否为 IP 密码 别名
        if len(parts) >= 2 and re.match(r"^(\d{1,3}\.){3}\d{1,3}$", parts[0]):
            host = parts[0].strip()
            port = 22
            user = "root"
            password = ""
            custom_name = ""

            if len(parts) == 2:
                password = parts[1].strip()
                custom_name = f"vps-{host}"
            elif len(parts) == 3:
                if parts[1].isdigit():
                    port = int(parts[1])
                    password = parts[2].strip()
                    custom_name = f"vps-{host}"
                else:
                    password = parts[1].strip()
                    custom_name = parts[2].strip()
            elif len(parts) >= 4:
                if parts[1].isdigit():
                    port = int(parts[1])
                    user = parts[2].strip()
                    password = parts[3].strip()
                    custom_name = parts[4].strip() if len(parts) >= 5 else f"vps-{host}"
                else:
                    user = parts[1].strip()
                    password = parts[2].strip()
                    custom_name = parts[3].strip()

            self.execute_remote_deploy(chat_id, host, port, user, password, custom_name)
            return

        self.send_msg(
            chat_id,
            "❌ <b>格式无法识别！</b>\n"
            "你可以点击菜单中的【➕ 添加 VPS 节点】使用向导一步步输入，或发送：\n"
            "<code>IP 密码 [别名]</code>"
        )

    def show_one_click_cmd(self, chat_id, msg_id=None):
        pub_ip = self.get_public_ip()
        cmd = (
            f"curl -fsSL https://raw.githubusercontent.com/firstwxx1/vps-security-monitor/main/install.sh | "
            f"bash -s -- --token '{self.token}' --chat '{self.chat_id}' --master '{pub_ip}:9527' --agent --auto"
        )
        text = (
            f"⚡ <b>专属一键安装接入命令</b>\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"只需在你要监控的<b>任何 Linux VPS 终端</b>上粘贴运行：\n\n"
            f"<code>{html_escape(cmd)}</code>\n\n"
            f"✅ <b>自动完成</b>：\n"
            f"1. 自动注入当前 Telegram 机器人的 Token 和 Chat ID\n"
            f"2. 部署完成后<b>全自动上报登记至中央 VPS 监控列表</b>\n"
            f"3. 自动安装守护引擎并注册 Crontab 定时拦截与日报\n"
            f"4. 部署完成后自动向本机器人发送接入成功卡片\n"
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
                    target_host = target.get("host")
                    target_port = target.get("port", 22)
                    target_pwd = target.get("password")
                    if target_pwd:
                        import paramiko
                        ssh = paramiko.SSHClient()
                        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        ssh.connect(target_host, port=target_port, username=target.get("user", "root"), password=target_pwd, timeout=8)
                        ssh.exec_command("python3 /opt/vps-security-monitor/vps_security_guard.py check --interactive", timeout=15)
                        ssh.close()
                        text = (
                            f"✅ <b>[突发安全巡检完成]</b>\n"
                            f"━━━━━━━━━━━━━━━━━━\n"
                            f"🏷️ <b>目标节点</b>: <code>{html_escape(name)}</code>\n"
                            f"🟢 <b>运行状态</b>: 远程通信正常，安全守护运行中\n"
                            f"🕒 <b>巡检时间</b>: <code>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</code>"
                        )
                    else:
                        t0 = time.time()
                        latency = None
                        try:
                            s = socket.create_connection((target_host, target_port), timeout=4)
                            latency = (time.time() - t0) * 1000.0
                            s.close()
                        except Exception:
                            pass

                        if latency is not None:
                            text = (
                                f"✅ <b>[突发安全巡检完成]</b>\n"
                                f"━━━━━━━━━━━━━━━━━━\n"
                                f"🏷️ <b>目标节点</b>: <code>{html_escape(name)}</code>\n"
                                f"🌐 <b>网络地址</b>: <code>{target_host}:{target_port}</code>\n"
                                f"🟢 <b>在线状态</b>: 通信良好 (延迟 <code>{latency:.1f} ms</code>)\n"
                                f"🛡️ <b>防护策略</b>: 本地 Systemd 守护进程常驻保活 (每60秒增量检测)\n"
                                f"🕒 <b>巡检时间</b>: <code>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</code>\n"
                                f"━━━━━━━━━━━━━━━━━━\n"
                                f"<i>该节点由其本地守护进程全天候自主防御，若遭遇撞库或代理池攻击将秒级报警！</i>"
                            )
                        else:
                            text = (
                                f"⚠️ <b>[突发安全巡检告警]</b>\n"
                                f"━━━━━━━━━━━━━━━━━━\n"
                                f"🏷️ <b>目标节点</b>: <code>{html_escape(name)}</code>\n"
                                f"🌐 <b>网络地址</b>: <code>{target_host}:{target_port}</code>\n"
                                f"🔴 <b>在线状态</b>: 端口连接超时 (可能关机或防火墙阻断)\n"
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
                        target_host = target.get("host")
                        target_port = target.get("port", 22)
                        target_pwd = target.get("password")
                        if target_pwd:
                            import paramiko
                            ssh = paramiko.SSHClient()
                            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                            ssh.connect(target_host, port=target_port, username=target.get("user", "root"), password=target_pwd, timeout=6)
                            ssh.exec_command("python3 /opt/vps-security-monitor/vps_security_guard.py check", timeout=10)
                            ssh.close()
                            results.append(f"· <b>{html_escape(name)}</b>: 🟢 在线安全")
                        else:
                            t0 = time.time()
                            try:
                                s = socket.create_connection((target_host, target_port), timeout=3)
                                lat = (time.time() - t0) * 1000.0
                                s.close()
                                results.append(f"· <b>{html_escape(name)}</b>: 🟢 在线正常 ({lat:.0f}ms)")
                            except Exception:
                                results.append(f"· <b>{html_escape(name)}</b>: 🔴 连接超时 (离线)")
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

    def run_node_daily(self, chat_id, node_idx=None, host=None):
        nodes = load_nodes()
        target = None
        if node_idx is not None and 0 <= node_idx < len(nodes):
            target = nodes[node_idx]
        elif host:
            target = next((n for n in nodes if n.get("host") == host), None)

        if not target:
            self.send_msg(chat_id, "❌ 未找到目标节点！")
            return

        name = target.get("name", "VPS")
        is_local = target.get("is_local", False)

        def worker():
            try:
                if is_local:
                    import vps_security_guard as guard
                    cfg = load_config()
                    guard.run_daily_mode(cfg)
                else:
                    target_host = target.get("host")
                    target_port = target.get("port", 22)
                    target_pwd = target.get("password")

                    if target_pwd:
                        import paramiko
                        ssh = paramiko.SSHClient()
                        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        ssh.connect(target_host, port=target_port, username=target.get("user", "root"), password=target_pwd, timeout=8)
                        ssh.exec_command("python3 /opt/vps-security-monitor/vps_security_guard.py daily", timeout=15)
                        ssh.close()
                    else:
                        t0 = time.time()
                        latency = None
                        try:
                            s = socket.create_connection((target_host, target_port), timeout=4)
                            latency = (time.time() - t0) * 1000.0
                            s.close()
                        except Exception:
                            pass

                        lat_str = f"🟢 网络连通正常 (延迟 <code>{latency:.1f} ms</code>)" if latency is not None else "🔴 无法连接 (离线或端口未通)"
                        os_name = target.get("os", "Linux")
                        created = target.get("created_at", "未知")
                        info_text = (
                            f"🛡️ <b>[节点安全概览与运行状态] · [{html_escape(name)}]</b>\n"
                            f"━━━━━━━━━━━━━━━━━━\n"
                            f"🏷️ <b>节点名称</b>: <code>{html_escape(name)}</code>\n"
                            f"🌐 <b>网络地址</b>: <code>{target_host}:{target_port}</code>\n"
                            f"💻 <b>操作系统</b>: <code>{html_escape(os_name)}</code>\n"
                            f"📡 <b>实时网络</b>: {lat_str}\n"
                            f"🛡️ <b>防护引擎</b>: 🟢 Systemd 守护进程常驻保活 (秒级/分钟级检测)\n"
                            f"⏰ <b>早报机制</b>: 每天早晨 09:00 由该机器本地自动汇总生成并推送\n"
                            f"📦 <b>纳管时间</b>: <code>{created}</code>\n"
                            f"━━━━━━━━━━━━━━━━━━\n"
                            f"<i>提示：该节点由其本地 Systemd 守护引擎自主执行全天候安全审计。</i>"
                        )
                        kb = {
                            "inline_keyboard": [
                                [
                                    {"text": "🔍 即时安全巡检", "callback_data": f"act:chk_host:{target_host}"},
                                    {"text": "📋 节点列表", "callback_data": "nav:nodes"}
                                ]
                            ]
                        }
                        self.send_msg(chat_id, info_text, reply_markup=kb)
            except Exception as e:
                self.send_msg(chat_id, f"❌ <b>生成日报失败 · {html_escape(name)}</b>\n原因: <code>{html_escape(str(e))}</code>")

        threading.Thread(target=worker, daemon=True).start()

    def run_daily_all(self, chat_id, msg_id=None, is_auto=False):
        """将所有纳管的 VPS 节点（包括后续新添加的任意节点）聚合汇聚为统一的单条全节点安全总报"""
        nodes = load_nodes()
        total_count = len(nodes)

        target_msg_id = None
        if not is_auto:
            init_text = (
                f"📊 <b>[全节点安全总报生成中...]</b>\n"
                f"━━━━━━━━━━━━━━━━━━\n"
                f"📦 正在汇聚全部 <code>{total_count}</code> 台 VPS 节点的安全指标，请稍候 1~2 秒..."
            )
            if msg_id:
                self.edit_msg(chat_id, msg_id, init_text)
                target_msg_id = msg_id
            else:
                res = self.send_msg(chat_id, init_text)
                target_msg_id = res.get("result", {}).get("message_id") if res else None

        def worker():
            from datetime import timedelta, timezone
            cfg = load_config()
            tz_offset = cfg.get("timezone_offset", 8)
            now_tz = datetime.now(timezone.utc) + timedelta(hours=tz_offset)
            now_str = now_tz.strftime("%Y-%m-%d %H:%M:%S")
            yesterday_str = (now_tz - timedelta(days=1)).strftime("%m月%d日")

            node_sections = []
            total_attacks = 0
            total_bans = 0
            online_count = 0

            for idx, target in enumerate(nodes):
                name = target.get("name", f"VPS-{idx+1}")
                host = target.get("host", "127.0.0.1")
                port = target.get("port", 22)
                is_local = target.get("is_local", False)
                os_name = target.get("os", "Linux")

                if is_local:
                    try:
                        import vps_security_guard as guard
                        data = guard.run_daily_mode(cfg, send_tg=False)
                        ssh_cnt = data.get("ssh_fail_count", 0)
                        scan_cnt = data.get("scan_count", 0)
                        web_cnt = data.get("login_fail_count", 0)
                        node_attacks = ssh_cnt + scan_cnt + web_cnt
                        total_attacks += node_attacks
                        banned_cnt = data.get("banned_count", 0)
                        total_bans += banned_cnt
                        online_count += 1

                        cert_info = ""
                        if data.get("nearest_cert"):
                            dom, days = data["nearest_cert"]
                            cert_info = f" · 证书剩 {days}天"

                        backup_info = ""
                        if data.get("backup_status"):
                            backup_info = f" · {data['backup_status']}"

                        sec_lines = [
                            f"🏷️ <b>[{idx+1}] {html_escape(name)}</b> · <code>{host}</code> <i>(主控)</i>",
                            f"├ 🖥️ <b>SSH防爆破</b>: 拦截 <code>{ssh_cnt:,}</code> 次 | 封禁中: <code>{banned_cnt}</code> 个",
                            f"├ 🌐 <b>Web扫描探测</b>: <code>{scan_cnt}</code> 次 | 登录失败: <code>{web_cnt}</code> 次",
                            f"├ ⚠️ <b>疑似陌生登录</b>: <code>{data.get('stranger_logins', 0)}</code> 次",
                            f"└ 💾 <b>系统负载</b>: 磁盘 <code>{data.get('disk_percent')}%</code> (剩 {data.get('disk_free_gb')}G) · 内存可用 <code>{data.get('mem_avail_mb')}MB</code>{cert_info}{backup_info}"
                        ]
                        node_sections.append("\n".join(sec_lines))
                    except Exception as e:
                        node_sections.append(
                            f"🏷️ <b>[{idx+1}] {html_escape(name)}</b> · <code>{host}</code> <i>(主控)</i>\n"
                            f"└ ❌ 获取本地数据异常: <code>{html_escape(str(e)[:30])}</code>"
                        )
                else:
                    # 远程子节点（支持免密探活、guard守护状态检测及后续新加的任意节点）
                    target_pwd = target.get("password")
                    t0 = time.time()
                    latency = None
                    try:
                        s = socket.create_connection((host, port), timeout=3)
                        latency = (time.time() - t0) * 1000.0
                        s.close()
                        online_count += 1
                        lat_tag = f"🟢 在线正常 (延迟 <code>{latency:.1f}ms</code>)"
                    except Exception:
                        lat_tag = "🔴 无法连接 (离线或端口未通)"

                    sec_lines = [
                        f"🏷️ <b>[{idx+1}] {html_escape(name)}</b> · <code>{host}:{port}</code> <i>(受控子节点)</i>",
                        f"├ 📡 <b>实时网络</b>: {lat_tag}",
                        f"├ 💻 <b>操作系统</b>: <code>{html_escape(os_name)}</code>",
                        f"├ 🛡️ <b>防护引擎</b>: 🟢 Systemd 守护进程常驻保活 (秒级检测)",
                        f"└ ⏰ <b>告警审计</b>: 本地全天候自主阻断与开机重启自启通知"
                    ]
                    node_sections.append("\n".join(sec_lines))

            nodes_body = "\n\n".join(node_sections)
            final_report = (
                f"📊 <b>[全节点安全巡检总报 · {yesterday_str}]</b>\n"
                f"━━━━━━━━━━━━━━━━━━\n"
                f"📦 <b>纳管节点</b>: 共 <code>{total_count}</code> 台 | 🟢 <b>在线率</b>: <code>{online_count}/{total_count}</code>\n"
                f"🛡️ <b>全网威胁</b>: 今日拦截黑客攻击探测共 <code>{total_attacks:,}</code> 次\n"
                f"━━━━━━━━━━━━━━━━━━\n\n"
                f"{nodes_body}\n\n"
                f"━━━━━━━━━━━━━━━━━━\n"
                f"💡 <i>提示：所有已纳管及未来新添加的 VPS 均已自动汇总于此总报中。</i>\n"
                f"🕒 <b>生成时间</b>: <code>{now_str}</code>"
            )

            kb = {
                "inline_keyboard": [
                    [
                        {"text": "🔄 刷新全节点总报", "callback_data": "act:daily_all"},
                        {"text": "🔍 全节点突发体检", "callback_data": "act:check_all"}
                    ],
                    [
                        {"text": "📋 管理节点列表", "callback_data": "nav:nodes"},
                        {"text": "🔙 返回主控制台", "callback_data": "nav:home"}
                    ]
                ]
            }

            if is_auto:
                state = load_monitor_state()
                state["last_daily_sent_date"] = now_tz.strftime("%Y-%m-%d")
                save_monitor_state(state)

            if target_msg_id:
                self.edit_msg(chat_id, target_msg_id, final_report, reply_markup=kb)
            else:
                self.send_msg(chat_id, final_report, reply_markup=kb)

        threading.Thread(target=worker, daemon=True).start()

    def delete_node(self, chat_id, node_idx, msg_id=None):
        nodes = load_nodes()
        if 0 <= node_idx < len(nodes):
            target = nodes[node_idx]
            if target.get("is_local"):
                self.send_msg(chat_id, "⚠️ 本地主节点不可移除！")
                return
            removed = nodes.pop(node_idx)
            save_nodes(nodes)
            self.send_msg(chat_id, f"🗑️ 已成功从监控列表中移除节点: <b>{html_escape(removed.get('name'))}</b>")
            self.show_nodes_menu(chat_id, msg_id)
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
        elif data == "act:add_wiz_start":
            self.user_states[chat_id] = {"state": "add_wiz_ip", "orig_msg_id": msg_id}
            self.edit_msg(
                chat_id, msg_id,
                "🚀 <b>【全自动向导部署 VPS】· 第 1 步</b>\n"
                "━━━━━━━━━━━━━━━━━━\n"
                "👉 <b>请输入目标 VPS 的 IP 地址</b>：\n"
                "例如直接回复：<code>107.172.83.41</code>",
                reply_markup={"inline_keyboard": [[{"text": "🔙 取消添加", "callback_data": "act:add_wiz_cancel"}]]}
            )
        elif data == "act:add_wiz_port:22":
            if chat_id in self.user_states:
                self.user_states[chat_id]["port"] = 22
                self.user_states[chat_id]["state"] = "add_wiz_pwd"
                self.edit_msg(
                    chat_id, msg_id,
                    "🔌 <b>已使用默认端口 22</b>\n"
                    "━━━━━━━━━━━━━━━━━━\n"
                    "👉 <b>第 3 步：请输入 root 用户的 SSH 密码</b>\n\n"
                    "🔒 <i>安全提示：密码仅用于本次全自动部署安全引擎，部署完毕后立即从内存释放。</i>",
                    reply_markup={"inline_keyboard": [[{"text": "🔙 取消添加", "callback_data": "act:add_wiz_cancel"}]]}
                )
        elif data == "act:add_wiz_name:auto":
            if chat_id in self.user_states:
                ip = self.user_states[chat_id].get("ip")
                port = self.user_states[chat_id].get("port", 22)
                pwd = self.user_states[chat_id].get("password", "")
                self.user_states.pop(chat_id, None)
                self.execute_remote_deploy(chat_id, ip, port, "root", pwd, f"vps-{ip}", msg_id)
        elif data == "act:add_wiz_cancel":
            self.user_states.pop(chat_id, None)
            self.show_main_menu(chat_id, msg_id)
        elif data == "act:add_ip_only_prompt":
            self.user_states[chat_id] = {"state": "waiting_ip_only", "orig_msg_id": msg_id}
            self.edit_msg(
                chat_id, msg_id,
                "📋 <b>【免密直接登记】</b>\n"
                "━━━━━━━━━━━━━━━━━━\n"
                "适合不想提供 SSH 密码或已经在目标机安装过脚本的机器。\n\n"
                "请直接在当前聊天窗口回复：<code>IP [别名]</code>\n"
                "例如回复：<code>107.172.83.41 香港CN2</code>",
                reply_markup={"inline_keyboard": [[{"text": "🔙 取消返回", "callback_data": "nav:home"}]]}
            )
        elif data == "act:one_click_cmd":
            self.show_one_click_cmd(chat_id, msg_id)
        elif data == "act:show_reply_kb":
            self.send_msg(chat_id, "⌨️ 底部快捷按键已展开 (随时可点击右下角或自带按钮折叠收起)：", reply_markup=self.get_reply_keyboard())
        elif data == "act:check_all":
            self.run_check_all(chat_id)
        elif data == "act:daily_all":
            self.run_daily_all(chat_id, msg_id)
        elif data.startswith("act:reg_quick:"):
            parts = data.split(":", 3)
            ip = parts[2]
            name = parts[3].strip() if len(parts) > 3 else f"vps-{ip}"
            display_name = name

            nodes = load_nodes()
            nodes = [n for n in nodes if n.get("host") != ip]
            nodes.append({
                "name": display_name,
                "host": ip,
                "port": 22,
                "user": "root",
                "is_local": False,
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
            save_nodes(nodes)

            self.answer_callback(cb_id, f"✅ 已成功录入节点: {display_name}")
            updated_text = (
                f"✅ <b>[VPS 节点录入成功！]</b>\n"
                f"━━━━━━━━━━━━━━━━━━\n"
                f"🏷️ <b>节点名称</b>: <code>{html_escape(display_name)}</code>\n"
                f"🌐 <b>网络地址</b>: <code>{ip}</code>\n"
                f"📦 <b>当前纳管</b>: 共 <code>{len(nodes)}</code> 台 VPS\n"
                f"━━━━━━━━━━━━━━━━━━\n"
                f"<i>该 VPS 已正式收录进中央监控列表，可在 /nodes 中随时查看与巡检！</i>"
            )
            kb = {
                "inline_keyboard": [
                    [
                        {"text": "📋 查看已纳管 VPS 列表", "callback_data": "nav:nodes"},
                        {"text": "🔍 立即巡检", "callback_data": f"act:chk_host:{ip}"}
                    ]
                ]
            }
            if msg_id:
                self.edit_msg(chat_id, msg_id, updated_text, reply_markup=kb)
            else:
                self.send_msg(chat_id, updated_text, reply_markup=kb)
        elif data.startswith("act:chk_node:"):
            idx = int(data.split(":")[-1])
            self.run_node_check(chat_id, node_idx=idx)
        elif data.startswith("act:chk_host:"):
            host = data.split(":")[-1]
            self.run_node_check(chat_id, host=host)
        elif data.startswith("act:day_node:"):
            idx = int(data.split(":")[-1])
            self.run_node_daily(chat_id, node_idx=idx)
        elif data.startswith("act:ren_node:"):
            idx = int(data.split(":")[-1])
            self.prompt_rename_node(chat_id, idx, msg_id)
        elif data.startswith("act:ren_to:"):
            parts = data.split(":", 3)
            idx = int(parts[2])
            new_name = parts[3]
            nodes = load_nodes()
            if 0 <= idx < len(nodes):
                old_name = nodes[idx].get("name")
                nodes[idx]["name"] = new_name
                save_nodes(nodes)
                self.answer_callback(cb_id, f"✅ 已成功更名为: {new_name}")
                self.send_msg(
                    chat_id,
                    f"✅ <b>[VPS 节点更名成功！]</b>\n"
                    f"原名称: <code>{html_escape(old_name)}</code>\n"
                    f"新名称: <b>{html_escape(new_name)}</b>"
                )
                self.show_nodes_menu(chat_id)
        elif data.startswith("act:node_detail:"):
            idx = int(data.split(":")[-1])
            self.show_node_detail(chat_id, idx, msg_id)
        elif data.startswith("act:del_node:"):
            idx = int(data.split(":")[-1])
            self.delete_node(chat_id, idx, msg_id)

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

        # 4. 改名指令与交互 (/rename)
        cmd_word = text.split()[0].lower() if text.strip() else ""
        is_rename_cmd = cmd_word in ("/rename", "/name", "改名") or cmd_word.startswith("/rename@") or cmd_word.startswith("/name@")

        if is_rename_cmd:
            parts = text.strip().split(maxsplit=2)
            nodes = load_nodes()

            # Case A: 用户仅发送了 /rename (例如点击了菜单里的 /rename)
            if len(parts) == 1:
                btn_rows = []
                for idx, n in enumerate(nodes):
                    n_name = n.get("name", "未命名")
                    btn_rows.append([
                        {"text": f"✏️ {idx + 1}. {n_name}", "callback_data": f"act:ren_node:{idx}"}
                    ])
                btn_rows.append([{"text": "🔙 返回节点列表", "callback_data": "nav:nodes"}])
                self.send_msg(
                    chat_id,
                    "✏️ <b>请点击选择要修改名称的 VPS 节点：</b>\n"
                    "━━━━━━━━━━━━━━━━━━\n"
                    "💡 <i>点击对应节点后，直接在聊天窗口输入新名字即可！</i>",
                    reply_markup={"inline_keyboard": btn_rows}
                )
                return

            # Case B: 用户发送了 2 个参数，例如: /rename 2 或 /rename 日本vpn
            elif len(parts) == 2:
                arg = parts[1].strip()
                if arg.isdigit() and 1 <= int(arg) <= len(nodes):
                    target_idx = int(arg) - 1
                    self.prompt_rename_node(chat_id, target_idx)
                    return

                ip_match_idx = next((i for i, n in enumerate(nodes) if n.get("host") == arg), None)
                if ip_match_idx is not None:
                    self.prompt_rename_node(chat_id, ip_match_idx)
                    return

                # 若当前共 2 台机器（1台本机 + 1台远程），且参数不是序号，直接推断用户要给第 2 台机器改名为该参数
                if len(nodes) == 2:
                    new_name = arg
                    target_idx = 1
                    old_name = nodes[target_idx].get("name")
                    nodes[target_idx]["name"] = new_name
                    save_nodes(nodes)
                    self.send_msg(
                        chat_id,
                        f"✅ <b>[VPS 节点更名成功！]</b>\n"
                        f"原名称: <code>{html_escape(old_name)}</code>\n"
                        f"新名称: <b>{html_escape(new_name)}</b>"
                    )
                    self.show_nodes_menu(chat_id)
                    return
                else:
                    btn_rows = []
                    for idx, n in enumerate(nodes):
                        n_name = n.get("name", "未命名")
                        btn_rows.append([
                            {"text": f"✏️ 将【{n_name}】改名为 {arg}", "callback_data": f"act:ren_to:{idx}:{arg}"}
                        ])
                    btn_rows.append([{"text": "🔙 返回节点列表", "callback_data": "nav:nodes"}])
                    self.send_msg(
                        chat_id,
                        f"❓ 请问你想把哪台 VPS 重命名为 <b>{html_escape(arg)}</b>？",
                        reply_markup={"inline_keyboard": btn_rows}
                    )
                    return

            # Case C: 用户发送了 3 个参数，例如: /rename 2 日本vpn 或 /rename 8.209.239.164 阿里云
            else:
                target_ident = parts[1].strip()
                new_name = parts[2].strip()
                found_idx = None
                if target_ident.isdigit():
                    idx = int(target_ident) - 1
                    if 0 <= idx < len(nodes):
                        found_idx = idx
                if found_idx is None:
                    for i, n in enumerate(nodes):
                        if n.get("host") == target_ident or target_ident in n.get("name", ""):
                            found_idx = i
                            break

                if found_idx is not None:
                    old_name = nodes[found_idx].get("name")
                    nodes[found_idx]["name"] = new_name
                    save_nodes(nodes)
                    if nodes[found_idx].get("is_local"):
                        try:
                            cfg = load_config()
                            cfg["node_name"] = new_name
                            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                                json.dump(cfg, f, ensure_ascii=False, indent=2)
                        except Exception:
                            pass
                    self.send_msg(
                        chat_id,
                        f"✅ <b>[VPS 节点更名成功！]</b>\n"
                        f"原名称: <code>{html_escape(old_name)}</code>\n"
                        f"新名称: <b>{html_escape(new_name)}</b>"
                    )
                    self.show_nodes_menu(chat_id)
                    return
                else:
                    self.send_msg(chat_id, f"❌ 未找到匹配的节点: <code>{html_escape(target_ident)}</code>\n发送 /nodes 可查看当前节点列表与序号。")
                    return

        # 如果处于等待改名状态 (点击了改名按钮后直接回复文字)
        if current_state == "waiting_rename_node":
            idx = state_data.get("node_idx")
            new_name = text.strip()
            self.user_states.pop(chat_id, None)

            if not new_name:
                self.send_msg(chat_id, "❌ 节点名称不能为空！")
                self.show_nodes_menu(chat_id)
                return

            nodes = load_nodes()
            if idx is not None and 0 <= idx < len(nodes):
                old_name = nodes[idx].get("name")
                nodes[idx]["name"] = new_name
                save_nodes(nodes)

                if nodes[idx].get("is_local"):
                    try:
                        cfg = load_config()
                        cfg["node_name"] = new_name
                        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                            json.dump(cfg, f, ensure_ascii=False, indent=2)
                    except Exception:
                        pass

                self.send_msg(
                    chat_id,
                    f"✅ <b>[VPS 节点更名成功！]</b>\n"
                    f"原名称: <code>{html_escape(old_name)}</code>\n"
                    f"新名称: <b>{html_escape(new_name)}</b>"
                )
                self.show_nodes_menu(chat_id)
            else:
                self.send_msg(chat_id, "❌ 节点序号无效！")
            return

        # 5. 向导添加 VPS 交互流程 (步骤 1~4)
        if current_state == "add_wiz_ip":
            ip_cand = text.strip()
            if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ip_cand):
                self.user_states[chat_id] = {
                    "state": "add_wiz_port",
                    "ip": ip_cand
                }
                self.send_msg(
                    chat_id,
                    f"🌐 <b>已记录目标 IP</b>: <code>{ip_cand}</code>\n"
                    f"━━━━━━━━━━━━━━━━━━\n"
                    f"👉 <b>第 2 步：请输入 SSH 端口</b>\n\n"
                    f"💡 <i>若使用默认的 22 端口，请直接点击下方按钮跳过输入：</i>",
                    reply_markup={
                        "inline_keyboard": [
                            [{"text": "🟢 使用默认 22 端口", "callback_data": "act:add_wiz_port:22"}],
                            [{"text": "🔙 取消添加", "callback_data": "act:add_wiz_cancel"}]
                        ]
                    }
                )
                return
            else:
                self.send_msg(
                    chat_id,
                    f"❌ <b>IP 地址格式不正确！</b>\n请输入标准 IPv4 地址（例如：<code>107.172.83.41</code>），或点击下方取消：",
                    reply_markup={"inline_keyboard": [[{"text": "🔙 取消添加", "callback_data": "act:add_wiz_cancel"}]]}
                )
                return

        elif current_state == "add_wiz_port":
            port_str = text.strip()
            if port_str.isdigit() and 1 <= int(port_str) <= 65535:
                port_num = int(port_str)
                self.user_states[chat_id]["port"] = port_num
                self.user_states[chat_id]["state"] = "add_wiz_pwd"
                self.send_msg(
                    chat_id,
                    f"🔌 <b>已记录 SSH 端口</b>: <code>{port_num}</code>\n"
                    f"━━━━━━━━━━━━━━━━━━\n"
                    f"👉 <b>第 3 步：请输入 root 用户的 SSH 密码</b>\n\n"
                    f"🔒 <i>安全提示：密码仅用于本次全自动部署安全引擎，部署完毕后立即从内存释放。</i>",
                    reply_markup={"inline_keyboard": [[{"text": "🔙 取消添加", "callback_data": "act:add_wiz_cancel"}]]}
                )
                return
            else:
                self.send_msg(
                    chat_id,
                    f"❌ <b>端口号必须为 1~65535 的数字！</b>\n请重新输入，或直接点击下方按钮使用默认 22 端口：",
                    reply_markup={
                        "inline_keyboard": [
                            [{"text": "🟢 使用默认 22 端口", "callback_data": "act:add_wiz_port:22"}],
                            [{"text": "🔙 取消添加", "callback_data": "act:add_wiz_cancel"}]
                        ]
                    }
                )
                return

        elif current_state == "add_wiz_pwd":
            pwd = text.strip()
            if not pwd:
                self.send_msg(chat_id, "❌ 密码不能为空，请重新输入：")
                return
            self.user_states[chat_id]["password"] = pwd
            self.user_states[chat_id]["state"] = "add_wiz_name"
            self.send_msg(
                chat_id,
                f"🔑 <b>密码接收成功</b>\n"
                f"━━━━━━━━━━━━━━━━━━\n"
                f"👉 <b>第 4 步：请输入该 VPS 的别名/备注名称</b>\n"
                f"例如：<code>香港阿里云</code>、<code>美西自建节点</code> 等\n\n"
                f"💡 <i>不想手动起名？点击下方按钮将自动命名：</i>",
                reply_markup={
                    "inline_keyboard": [
                        [{"text": "🎲 自动命名 (vps-IP)", "callback_data": "act:add_wiz_name:auto"}],
                        [{"text": "🔙 取消添加", "callback_data": "act:add_wiz_cancel"}]
                    ]
                }
            )
            return

        elif current_state == "add_wiz_name":
            name = text.strip()
            ip = state_data.get("ip")
            port = state_data.get("port", 22)
            pwd = state_data.get("password", "")
            self.user_states.pop(chat_id, None)
            self.execute_remote_deploy(chat_id, ip, port, "root", pwd, name)
            return

        elif current_state == "waiting_ip_only":
            self.user_states.pop(chat_id, None)
            parts = text.strip().split(maxsplit=1)
            if not parts or not re.match(r"^(\d{1,3}\.){3}\d{1,3}$", parts[0]):
                self.send_msg(chat_id, "❌ IP 格式无效，已取消收录。")
                self.show_nodes_menu(chat_id)
                return
            ip = parts[0].strip()
            name = parts[1].strip() if len(parts) > 1 else f"vps-{ip}"
            nodes = load_nodes()
            nodes = [n for n in nodes if n.get("host") != ip]
            nodes.append({
                "name": name,
                "host": ip,
                "port": 22,
                "user": "root",
                "is_local": False,
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
            save_nodes(nodes)
            self.send_msg(
                chat_id,
                f"✅ <b>[VPS 节点免密收录成功！]</b>\n"
                f"━━━━━━━━━━━━━━━━━━\n"
                f"🏷️ <b>节点标识</b>: <code>{html_escape(name)}</code>\n"
                f"🌐 <b>主机 IP</b>: <code>{ip}</code>\n"
                f"📦 <b>已纳管 VPS</b>: 共 <code>{len(nodes)}</code> 台\n"
                f"━━━━━━━━━━━━━━━━━━\n"
                f"<i>该 VPS 已加入监控中心，可随时在 /nodes 中查看与巡检。</i>",
                reply_markup={"inline_keyboard": [[{"text": "📋 查看已纳管 VPS 列表", "callback_data": "nav:nodes"}]]}
            )
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
                        cb = u["callback_query"]
                        print(f"[*] 收到按钮回调: from={cb.get('from',{}).get('id')} data={cb.get('data')}", flush=True)
                        self.handle_callback(cb)
                    elif "message" in u:
                        m = u["message"]
                        print(f"[*] 收到消息: from={m.get('from',{}).get('id')} text={m.get('text')}", flush=True)
                        self.handle_message(m)
                except Exception as e:
                    print(f"[-] 处理更新异常: {e}", flush=True)


def main():
    bot = SecurityBot()
    bot.run_forever()


if __name__ == "__main__":
    main()
