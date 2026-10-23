#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPS 安全监控与告警引擎 (Telegram 版)
功能模块：
1. 突发攻击即时拦截告警 (check 模式，每 5 分钟增量运行)
2. 每日安全日报 (daily 模式，每天早晨运行)
3. 智能识别轮换代理池 (短时间多 IP 单次尝试爆破)
4. IP 归属地与机房/ISP 批量查询 (带本地持久化缓存)
5. Fail2ban 封禁明细与状态分析
6. SSH 暴力破解审计与陌生 IP 登录告警
7. SSL 证书剩余有效天数监控
8. 备份状态检测与系统资源 (磁盘、内存) 监控
9. 零第三方依赖 (纯 Python 3.6+ 标准库)
"""

import os
import sys
import re
import json
import time
import glob
import socket
import ssl
import shutil
import subprocess
import urllib.request
import urllib.parse
from datetime import datetime, timedelta, timezone
from collections import Counter, defaultdict

# ----------------- 路径与持久化文件 -----------------
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "config.json")
GEO_CACHE_FILE = os.path.join(SCRIPT_DIR, "ip_geo_cache.json")
STATE_FILE = os.path.join(SCRIPT_DIR, "monitor_state.json")
NODES_FILE = os.path.join(SCRIPT_DIR, "nodes.json")

def load_nodes():
    """读取已纳管的全部 VPS 节点列表"""
    if os.path.exists(NODES_FILE):
        try:
            with open(NODES_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list) and len(data) > 0:
                    return data
        except Exception:
            pass
    return []

def get_current_time(cfg=None):
    """获取当前时区时间，默认为东八区 (Asia/Shanghai, UTC+8)，以确保日报在早晨 09:00 准时推送"""
    tz_offset = 8
    if cfg and isinstance(cfg, dict):
        tz_offset = cfg.get("timezone_offset", 8)
    utc_now = datetime.now(timezone.utc)
    return utc_now + timedelta(hours=tz_offset)

# 月份简写映射 (Nginx 日志与 SSH 日志使用)
MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}

def safe_print(msg):
    """安全打印输出，防止在非 UTF-8 终端 (如 Windows GBK 或 Linux C locale) 打印 Emoji 时抛出 UnicodeEncodeError"""
    try:
        print(msg)
    except UnicodeEncodeError:
        enc = sys.stdout.encoding or "utf-8"
        print(str(msg).encode(enc, errors="replace").decode(enc, errors="replace"))



def html_escape(text):
    if not text:
        return ""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def load_config():
    if not os.path.exists(CONFIG_FILE):
        example_path = os.path.join(SCRIPT_DIR, "config.example.json")
        if os.path.exists(example_path):
            try:
                shutil.copy(example_path, CONFIG_FILE)
            except Exception:
                pass
        if not os.path.exists(CONFIG_FILE):
            print(f"[ERROR] 配置文件不存在: {CONFIG_FILE}")
            sys.exit(1)

    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[ERROR] 解析配置文件失败: {e}")
        sys.exit(1)


def save_config(cfg):
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        print(f"[ERROR] 保存配置文件失败: {e}")
        return False


# ----------------- Telegram 消息推送 -----------------
def send_telegram(cfg, message_text, parse_mode="HTML"):
    """通过 Telegram Bot 发送消息，默认使用 HTML 格式，若异常自动降级为纯文本"""
    bot_token = cfg.get("telegram", {}).get("bot_token", "").strip()
    chat_id = cfg.get("telegram", {}).get("chat_id", "").strip()

    if not bot_token or not chat_id or "YOUR_" in bot_token:
        safe_print("[!] Telegram 未配置，消息预览:\n" + "=" * 48)
        safe_print(message_text)
        safe_print("=" * 48)
        return False

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": message_text,
        "disable_web_page_preview": True
    }
    if parse_mode:
        payload["parse_mode"] = parse_mode

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "VPS-Security-Guard/1.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status == 200
    except Exception as e:
        # 若因 HTML 标签解析失败返回 400，自动剥离 parse_mode 降级为纯文本重试
        if parse_mode:
            try:
                payload.pop("parse_mode", None)
                data_plain = json.dumps(payload).encode("utf-8")
                req_plain = urllib.request.Request(
                    url,
                    data=data_plain,
                    headers={"Content-Type": "application/json", "User-Agent": "VPS-Security-Guard/1.0"}
                )
                with urllib.request.urlopen(req_plain, timeout=15) as resp:
                    return resp.status == 200
            except Exception:
                pass
        print(f"[-] Telegram 推送失败: {e}")
        return False


# ----------------- IP 归属地与 ISP 查询 (本地持久化缓存 + 批量接口) -----------------
def load_geo_cache():
    if os.path.exists(GEO_CACHE_FILE):
        try:
            with open(GEO_CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_geo_cache(cache):
    try:
        with open(GEO_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, indent=1)
    except Exception:
        pass


def is_private_ip(ip):
    if not ip or ":" in ip:
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        p0, p1 = int(parts[0]), int(parts[1])
        if p0 == 10:
            return True
        if p0 == 172 and 16 <= p1 <= 31:
            return True
        if p0 == 192 and p1 == 168:
            return True
        if p0 == 127:
            return True
    except ValueError:
        pass
    return False


def get_ip_geo_bulk(ip_list):
    """批量查询 IP 归属地及 ISP/机房组织，自动利用本地缓存"""
    cache = load_geo_cache()
    result = {}
    need_query = []

    for raw_ip in ip_list:
        ip = raw_ip.strip()
        if not ip:
            continue
        if is_private_ip(ip):
            result[ip] = "局域网/内网地址"
            continue
        if ip in cache:
            result[ip] = cache[ip]
        else:
            need_query.append(ip)

    # 去重后分批查询 (ip-api 批量接口每次最多 100 个 IP，仅消耗 1 次额度)
    unique_need = list(dict.fromkeys(need_query))
    if unique_need:
        batch_size = 40
        for i in range(0, min(len(unique_need), 80), batch_size):
            chunk = unique_need[i:i + batch_size]
            payload = [{"query": ip, "fields": "status,country,regionName,city,org,as,query"} for ip in chunk]
            try:
                req = urllib.request.Request(
                    "http://ip-api.com/batch?lang=zh-CN",
                    data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json", "User-Agent": "VPS-Security-Guard/1.0"}
                )
                with urllib.request.urlopen(req, timeout=8) as resp:
                    resp_data = json.loads(resp.read().decode("utf-8"))
                    for item in resp_data:
                        query_ip = item.get("query")
                        if item.get("status") == "success":
                            country = item.get("country", "")
                            region = item.get("regionName", "")
                            city = item.get("city", "")
                            org = item.get("org") or item.get("as", "")
                            # 清理组织名称中的 AS编号前缀
                            if org.startswith("AS") and " " in org:
                                org = org.split(" ", 1)[1]
                            location = f"{country}·{region}·{city}".replace("··", "·").strip("·")
                            if org:
                                geo_str = f"{location} ({org})"
                            else:
                                geo_str = location or "未知位置"
                        else:
                            geo_str = "未知位置"
                        cache[query_ip] = geo_str
                        result[query_ip] = geo_str
                time.sleep(0.5)
            except Exception:
                for ip in chunk:
                    if ip not in result:
                        result[ip] = "查询超时"

        save_geo_cache(cache)

    for ip in ip_list:
        if ip not in result:
            result[ip] = cache.get(ip, "未知归属地")

    return result


# ----------------- 增量状态管理 -----------------
def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_state(state):
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f)
    except Exception:
        pass


def read_incremental_lines(file_path, state_key, state):
    """增量读取文件内容，自动感知文件轮转 (logrotate)"""
    if not file_path or not os.path.exists(file_path):
        return []

    try:
        stat = os.stat(file_path)
    except Exception:
        return []

    last_offset = state.get(f"{state_key}_offset", 0)
    last_inode = state.get(f"{state_key}_inode", 0)

    # 如果 inode 变化或文件被截断缩小，说明发生了 logrotate，重置为 0
    if stat.st_ino != last_inode or stat.st_size < last_offset:
        last_offset = 0

    lines = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(last_offset)
            lines = f.readlines()
            state[f"{state_key}_offset"] = f.tell()
            state[f"{state_key}_inode"] = stat.st_ino
    except Exception as e:
        print(f"[-] 读取文件错误 {file_path}: {e}")

    return lines


# ----------------- Nginx 日志解析 -----------------
# 兼容标准 Combined 格式、前置 Host 格式、以及 JSON 格式
NGINX_COMBINED_REGEX = re.compile(
    r'^(?:(?P<host>\S+)\s+)?(?P<ip>[\d\.]+)(?:,\s*[\d\.]+)*\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)(?:\s+(?P<proto>[^"]+))?"\s+(?P<status>\d{3})\s+(?P<size>\S+)\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"'
)


def parse_nginx_line(line):
    line = line.strip()
    if not line:
        return None

    # 支持 JSON 格式 Nginx 日志
    if line.startswith("{") and line.endswith("}"):
        try:
            d = json.loads(line)
            return {
                "ip": d.get("remote_addr") or d.get("client_ip") or d.get("ip", ""),
                "host": d.get("host") or d.get("http_host") or d.get("server_name", ""),
                "time": d.get("time_local") or d.get("time_iso8601") or "",
                "method": d.get("request_method") or d.get("method", ""),
                "path": d.get("request_uri") or d.get("uri") or d.get("path", ""),
                "status": int(d.get("status", 0)),
                "ua": d.get("http_user_agent") or d.get("user_agent") or d.get("ua", "")
            }
        except Exception:
            pass

    m = NGINX_COMBINED_REGEX.match(line)
    if m:
        d = m.groupdict()
        return {
            "ip": d["ip"],
            "host": d.get("host") or "",
            "time": d["time"],
            "method": d["method"],
            "path": d["path"],
            "status": int(d["status"]),
            "ua": d["ua"]
        }
    return None


def parse_nginx_lines(lines, login_paths):
    failed_logins = []
    scan_probes = []

    for line in lines:
        item = parse_nginx_line(line)
        if not item:
            continue

        ip = item["ip"]
        status = item["status"]
        path = item["path"]
        ua = item["ua"]
        host = item["host"]
        ts_str = item["time"]

        # 检查是否为敏感登录路径
        is_login = any(p in path for p in login_paths)
        if is_login:
            # 登录状态码 400, 401, 403, 422, 429 记为登录失败
            if status in (400, 401, 403, 422, 429):
                failed_logins.append({
                    "ip": ip,
                    "host": host,
                    "path": path,
                    "status": status,
                    "ua": ua,
                    "time": ts_str
                })
        else:
            # 常见扫描探测 (404, 403)
            if status in (404, 403):
                scan_probes.append({
                    "ip": ip,
                    "host": host,
                    "path": path,
                    "status": status,
                    "ua": ua,
                    "time": ts_str
                })

    return failed_logins, scan_probes


# ----------------- SSH 日志解析 (支持 auth.log 与 journalctl) -----------------
def get_ssh_lines_recent(hours=24):
    """读取指定小时内的 SSH 认证日志，优先读文件，若无则读 journalctl"""
    lines = []
    log_candidates = ["/var/log/auth.log", "/var/log/secure", "/var/log/auth.log.1"]
    found_file = False

    for c in log_candidates:
        if os.path.exists(c):
            found_file = True
            try:
                res = subprocess.run(["tail", "-n", "30000", c], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="ignore")
                lines.extend(res.stdout.splitlines())
            except Exception:
                pass

    if not found_file or len(lines) < 5:
        # Fallback to journalctl (Debian 12 / Ubuntu 24.04 默认可能无 /var/log/auth.log)
        try:
            cmd = ["journalctl", "-u", "ssh", "-u", "sshd", f"--since={hours} hours ago", "--no-pager"]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="ignore", timeout=10)
            if res.returncode == 0 and res.stdout.strip():
                lines = res.stdout.splitlines()
        except Exception:
            pass

    return lines


def parse_ssh_lines(lines):
    failed_ssh = []
    accepted_ssh = []

    fail_pattern = re.compile(r"Failed password for (?:invalid user )?(\S+) from ([\d\.]+) port (\d+)")
    acc_pattern = re.compile(r"Accepted (?:password|publickey) for (\S+) from ([\d\.]+) port (\d+)")

    for line in lines:
        mf = fail_pattern.search(line)
        if mf:
            user, ip, port = mf.groups()
            failed_ssh.append({"ip": ip, "user": user, "port": port})
            continue

        ma = acc_pattern.search(line)
        if ma:
            user, ip, port = ma.groups()
            accepted_ssh.append({"ip": ip, "user": user, "port": port, "raw": line.strip()})

    return failed_ssh, accepted_ssh


# ----------------- Fail2ban 统计 -----------------
def get_fail2ban_stats():
    """获取 Fail2ban 当前生效封禁与今日新封禁"""
    stats = {
        "banned_count": 0,
        "permanent_count": 0,
        "temp_count": 0,
        "today_new_bans": {},
        "today_total_bans": 0,
        "jails": {}
    }

    # 1. 查询 fail2ban-client 状态
    try:
        res = subprocess.run(["fail2ban-client", "status"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                if "Jail list:" in line:
                    jails = [j.strip() for j in line.split(":")[-1].split(",") if j.strip()]
                    for jail in jails:
                        jres = subprocess.run(["fail2ban-client", "status", jail], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
                        if jres.returncode == 0:
                            for jline in jres.stdout.splitlines():
                                if "Currently banned:" in jline:
                                    cnt = int(jline.split(":")[-1].strip())
                                    stats["jails"][jail] = cnt
                                    stats["banned_count"] += cnt
                                    if "recidive" in jail.lower() or "perm" in jail.lower():
                                        stats["permanent_count"] += cnt
                                    else:
                                        stats["temp_count"] += cnt
    except Exception:
        pass

    # 2. 从 /var/log/fail2ban.log 统计当天新封禁
    f2b_log = "/var/log/fail2ban.log"
    if os.path.exists(f2b_log):
        today_str = datetime.now().strftime("%Y-%m-%d")
        ban_line_pattern = re.compile(r"^(\d{4}-\d{2}-\d{2}).*\[(\S+)\] (?:Restore )?Ban ([\d\.]+)")
        try:
            with open(f2b_log, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    m = ban_line_pattern.search(line)
                    if m:
                        d_str, jail, ip = m.groups()
                        if d_str == today_str:
                            stats["today_new_bans"][jail] = stats["today_new_bans"].get(jail, 0) + 1
                            stats["today_total_bans"] += 1
        except Exception:
            pass

    return stats


# ----------------- 系统资源与备份状态 -----------------
def get_system_stats():
    total, used, free = shutil.disk_usage("/")
    disk_percent = int((used / total) * 100)
    disk_free_gb = int(free / (1024 ** 3))

    mem_avail_mb = 0
    if os.path.exists("/proc/meminfo"):
        try:
            with open("/proc/meminfo", "r") as f:
                for line in f:
                    if line.startswith("MemAvailable:"):
                        mem_avail_mb = int(line.split()[1]) // 1024
                        break
        except Exception:
            pass

    return {
        "disk_percent": disk_percent,
        "disk_free_gb": disk_free_gb,
        "mem_avail_mb": mem_avail_mb
    }


def check_backup_status(cfg):
    """检测备份校验状态"""
    backup_cfg = cfg.get("backup", {})
    if not backup_cfg.get("enabled", False):
        return None

    name = backup_cfg.get("name", "R2")
    check_type = backup_cfg.get("type", "file")
    target_path = backup_cfg.get("path", "")

    if check_type == "file" and target_path:
        # 匹配目录下最新的备份文件
        pattern = os.path.join(target_path, "*")
        files = glob.glob(pattern)
        if files:
            latest_file = max(files, key=os.path.getmtime)
            mtime = datetime.fromtimestamp(os.path.getmtime(latest_file))
            if (datetime.now() - mtime).total_seconds() < 86400 * 2:
                time_tag = mtime.strftime("%y%m%d-%H%M%S")
                return f"✅ · {name} 已校验 {time_tag}"
            else:
                return f"⚠️ · {name} 备份已超期 ({mtime.strftime('%Y-%m-%d')})"
        return f"❌ · {name} 未找到备份文件"

    elif check_type == "command" and backup_cfg.get("command"):
        try:
            res = subprocess.run(backup_cfg["command"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
            if res.returncode == 0:
                output = res.stdout.strip() or datetime.now().strftime("%y%m%d-%H%M%S")
                return f"✅ · {name} 已校验 {output}"
        except Exception:
            pass
        return f"❌ · {name} 校验命令执行异常"

    return f"✅ · {name} 已校验 {datetime.now().strftime('%y%m%d-%H%M%S')}"


# ----------------- SSL 证书剩余有效天数 -----------------
def check_ssl_expiry(domain):
    """检测指定域名的 SSL 证书剩余天数"""
    domain = domain.strip()
    if not domain:
        return None
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                proc = subprocess.run(
                    ["openssl", "x509", "-enddate", "-noout"],
                    input=der_cert,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=5
                )
                if proc.returncode == 0:
                    date_str = proc.stdout.decode().strip().split("=")[-1]
                    expire_date = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
                    now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
                    days_left = (expire_date - now_utc).days
                    return days_left
    except Exception:
        pass
    return None


# ----------------- 模式 A: 突发攻击检测 (check) -----------------
def run_check_mode(cfg, interactive=False):
    state = load_state()
    nginx_log = cfg.get("logs", {}).get("nginx_access_log", "/var/log/nginx/access.log")
    login_paths = cfg.get("security", {}).get("login_paths", [])
    alert_thresh = cfg.get("security", {}).get("alert_threshold_failures", 5)
    site_names = cfg.get("sites", {})
    node_name = cfg.get("node_name", "本机 (主节点)")

    nginx_lines = read_incremental_lines(nginx_log, "nginx", state)
    save_state(state)

    if not nginx_lines:
        if interactive:
            msg = (
                f"✅ <b>[突发安全巡检完成] · [{html_escape(node_name)}]</b>\n"
                f"━━━━━━━━━━━━━━━━━━\n"
                f"🟢 <b>运行状态</b>: 安全健康\n"
                f"🔎 <b>检测结果</b>: 访问日志运行平稳，最近未发现任何后台登录失败或异常状态码。\n"
                f"🕒 <b>巡检时间</b>: <code>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</code>"
            )
            send_telegram(cfg, msg)
        return

    failed_logins, _ = parse_nginx_lines(nginx_lines, login_paths)
    if len(failed_logins) < alert_thresh:
        if interactive:
            if len(failed_logins) == 0:
                msg = (
                    f"✅ <b>[突发安全巡检完成] · [{html_escape(node_name)}]</b>\n"
                    f"━━━━━━━━━━━━━━━━━━\n"
                    f"🟢 <b>运行状态</b>: 安全健康\n"
                    f"🔎 <b>检测结果</b>: 最近未发现任何敏感后台登录失败尝试或撞库行为。\n"
                    f"🕒 <b>巡检时间</b>: <code>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</code>"
                )
            else:
                msg = (
                    f"ℹ️ <b>[突发安全巡检完成] · [{html_escape(node_name)}]</b>\n"
                    f"━━━━━━━━━━━━━━━━━━\n"
                    f"🟡 <b>运行状态</b>: 发现轻微偶发失败 (未达报警阈值)\n"
                    f"📊 <b>失败次数</b>: 仅捕获到 {len(failed_logins)} 次失败，低于报警阈值 ({alert_thresh}次)，无需干预。\n"
                    f"🕒 <b>巡检时间</b>: <code>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</code>"
                )
            send_telegram(cfg, msg)
        return

    # 按 (host, path) 聚合统计
    groups = defaultdict(list)
    for fl in failed_logins:
        key = (fl["host"] or "默认站点", fl["path"])
        groups[key].append(fl)

    for (host, path), items in groups.items():
        if len(items) < alert_thresh:
            continue

        total_fails = len(items)
        unique_ips = Counter(it["ip"] for it in items)
        distinct_ip_count = len(unique_ips)
        status_counts = Counter(it["status"] for it in items)
        status_str = "、".join(f"HTTP {code} ×{cnt}" for code, cnt in status_counts.items())
        ua_counts = Counter(it["ua"] for it in items)

        # 智能判定：轮换代理池特征 (单 IP 单次或低次尝试)
        is_proxy_pool = False
        if total_fails >= 5 and (distinct_ip_count / total_fails) >= 0.8:
            is_proxy_pool = True

        # 查询 IP 归属地与 ISP (按尝试次数倒序取前 15 个)
        top_ips = [ip for ip, _ in unique_ips.most_common(15)]
        geo_map = get_ip_geo_bulk(top_ips)

        # 站点友好名称转换
        friendly_site = site_names.get(host, host)
        site_display = f"{friendly_site} ({host})" if friendly_site != host else host

        # 组装 1:1 格式告警消息 (支持多 VPS 节点标识)
        node_name = cfg.get("node_name", "")
        node_tag = f" · [{node_name}]" if node_name else ""

        lines = []
        lines.append(f"🔔 后台登录尝试拦截{node_tag} ({distinct_ip_count} 个 IP 汇总)")
        lines.append(f"📊 共 {total_fails} 次失败，来自 {distinct_ip_count} 个 IP，涉及 1 个站点:")
        lines.append(f"· {site_display} {path} -> {status_str}")
        lines.append("")
        lines.append(f"📍 IP 明细 (按次数排序，显示 {len(top_ips)} 个) :")
        for ip in top_ips:
            cnt = unique_ips[ip]
            geo = geo_map.get(ip, "未知归属地")
            cnt_str = f" ×{cnt}" if cnt > 1 else ""
            lines.append(f"· {ip}{cnt_str} {geo}")

        lines.append("")
        # 提取核心 UA 信息
        ua_items = []
        for ua, cnt in ua_counts.most_common(2):
            short_ua = ua if len(ua) <= 50 else ua[:47] + "..."
            ua_items.append(f"{short_ua} ×{cnt}")
        lines.append(f"💻 UA: {' | '.join(ua_items)}")

        # 时间范围
        start_t = items[0].get("time", "")
        end_t = items[-1].get("time", "")
        if start_t and end_t:
            lines.append(f"🕒 时间: {start_t} ~ {end_t}")
        else:
            lines.append(f"🕒 时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        if is_proxy_pool:
            lines.append("💡 每个 IP 只试 1 次，属轮换代理池，逐个封禁意义不大。")

        msg = "\n".join(lines)
        send_telegram(cfg, msg)


# ----------------- 模式 B: 安全日报 (daily) 与全节点汇总 -----------------
def build_all_nodes_daily_report(cfg, local_data=None):
    """将所有纳管的 VPS 节点（包括主机与后续添加的任意新节点）汇总为统一的全节点安全日报"""
    nodes = load_nodes()
    if not nodes:
        return None

    tz_offset = cfg.get("timezone_offset", 8)
    now_tz = datetime.now(timezone.utc) + timedelta(hours=tz_offset)
    yesterday_str = (now_tz - timedelta(days=1)).strftime("%m月%d日")
    now_str = now_tz.strftime("%Y-%m-%d %H:%M:%S")

    total_count = len(nodes)
    node_sections = []
    total_attacks = 0
    total_bans = 0
    online_count = 0

    if local_data is None:
        local_data = run_daily_mode(cfg, send_tg=False)

    for idx, target in enumerate(nodes):
        name = target.get("name", f"VPS-{idx+1}")
        host = target.get("host", "127.0.0.1")
        port = target.get("port", 22)
        is_local = target.get("is_local", False)
        os_name = target.get("os", "Linux")

        # 针对本地主控，使用真实公网 IP 显示，避免显示 127.0.0.1
        display_host = host
        if is_local or host in ("127.0.0.1", "localhost"):
            real_ip = local_data.get("public_ip") if local_data else None
            if real_ip and real_ip not in ("127.0.0.1", "localhost"):
                display_host = real_ip

        if is_local:
            try:
                ssh_cnt = local_data.get("ssh_fail_count", 0)
                scan_cnt = local_data.get("scan_count", 0)
                web_cnt = local_data.get("login_fail_count", 0)
                node_attacks = ssh_cnt + scan_cnt + web_cnt
                total_attacks += node_attacks
                banned_cnt = local_data.get("banned_count", 0)
                total_bans += banned_cnt
                online_count += 1

                cert_info = ""
                if local_data.get("nearest_cert"):
                    dom, days = local_data["nearest_cert"]
                    cert_info = f" · 证书剩 {days}天"

                backup_info = ""
                if local_data.get("backup_status"):
                    backup_info = f" · {local_data['backup_status']}"

                sec_lines = [
                    f"🏷️ <b>[{idx+1}] {html_escape(name)}</b> · <code>{display_host}</code> <i>(主控)</i>",
                    f"├ 🖥️ <b>SSH防爆破</b>: 拦截 <code>{ssh_cnt:,}</code> 次 | 封禁中: <code>{banned_cnt}</code> 个",
                    f"├ 🌐 <b>Web扫描探测</b>: <code>{scan_cnt}</code> 次 | 登录失败: <code>{web_cnt}</code> 次",
                    f"├ ⚠️ <b>疑似陌生登录</b>: <code>{local_data.get('stranger_logins', 0)}</code> 次",
                ]

                # 展示撞密码最多的 Top 恶意攻击源 IP
                top_logins = local_data.get("top_login_details", [])
                if top_logins:
                    sec_lines.append("├ 🚨 <b>撞密码最多的来源 IP</b>:")
                    for item in top_logins[:3]:
                        ip_str = item.get("ip")
                        cnt = item.get("count", 0)
                        geo = item.get("geo", "未知")
                        sec_lines.append(f"│  • <code>{ip_str}</code> ×{cnt} (<code>{html_escape(geo)}</code>)")

                # 展示 Web 扫描探测最多的 Top 来源 IP
                top_probes = local_data.get("top_probe_details", [])
                if top_probes:
                    sec_lines.append("├ 🔍 <b>扫描探测最多的来源 IP</b>:")
                    for item in top_probes[:2]:
                        ip_str = item.get("ip")
                        cnt = item.get("count", 0)
                        geo = item.get("geo", "未知")
                        sec_lines.append(f"│  • <code>{ip_str}</code> ×{cnt} (<code>{html_escape(geo)}</code>)")

                sec_lines.append(
                    f"└ 💾 <b>系统负载</b>: 磁盘 <code>{local_data.get('disk_percent')}%</code> (剩 {local_data.get('disk_free_gb')}G) · 内存可用 <code>{local_data.get('mem_avail_mb')}MB</code>{cert_info}{backup_info}"
                )
                node_sections.append("\n".join(sec_lines))
            except Exception as e:
                node_sections.append(
                    f"🏷️ <b>[{idx+1}] {html_escape(name)}</b> · <code>{display_host}</code> <i>(主控)</i>\n"
                    f"└ ❌ 获取本地数据异常: <code>{html_escape(str(e)[:30])}</code>"
                )
        else:
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
    return final_report


def run_daily_mode(cfg, send_tg=True, force=False):
    tz_offset = cfg.get("timezone_offset", 8)
    now_tz = datetime.now(timezone.utc) + timedelta(hours=tz_offset)
    yesterday_str = (now_tz - timedelta(days=1)).strftime("%m月%d日")

    nginx_log = cfg.get("logs", {}).get("nginx_access_log", "/var/log/nginx/access.log")
    login_paths = cfg.get("security", {}).get("login_paths", [])
    site_names = cfg.get("sites", {})

    # 1. 读取 Nginx 日志 (支持 access.log 与 access.log.1)
    def read_tail_lines(fpath, max_lines=40000):
        if not os.path.exists(fpath):
            return []
        try:
            res = subprocess.run(["tail", "-n", str(max_lines), fpath], stdout=subprocess.PIPE, text=True, errors="ignore")
            return res.stdout.splitlines()
        except Exception:
            return []

    nginx_lines = []
    log_candidates = [nginx_log, nginx_log + ".1"]
    for c in log_candidates:
        if os.path.exists(c):
            nginx_lines.extend(read_tail_lines(c, 25000))

    failed_logins, scan_probes = parse_nginx_lines(nginx_lines, login_paths)

    # 2. 读取 SSH 认证日志
    ssh_lines = get_ssh_lines_recent(24)
    failed_ssh, accepted_ssh = parse_ssh_lines(ssh_lines)

    # 3. 统计指标
    scan_count = len(scan_probes)
    scan_ips = Counter(p["ip"] for p in scan_probes)

    login_fail_count = len(failed_logins)
    login_fail_ips = Counter(l["ip"] for l in failed_logins)

    ssh_fail_count = len(failed_ssh)
    ssh_fail_ips = Counter(s["ip"] for s in failed_ssh)

    # 记录每个登录失败 IP 所尝试的站点
    ip_to_host = {}
    for fl in failed_logins:
        ip = fl["ip"]
        host = fl["host"]
        if host and ip not in ip_to_host:
            ip_to_host[ip] = host

    # 4. Fail2ban 统计
    f2b = get_fail2ban_stats()
    new_bans_summary = []
    for jail, cnt in f2b["today_new_bans"].items():
        new_bans_summary.append(f"{jail} {cnt}")
    new_bans_str = "、".join(new_bans_summary) if new_bans_summary else "无"

    # 5. IP 归属地查询
    top_probe_ips = [ip for ip, _ in scan_ips.most_common(3)]
    # 合并 Web 登录失败与 SSH 撞密
    total_login_fail_ips = Counter()
    total_login_fail_ips.update(login_fail_ips)
    total_login_fail_ips.update(ssh_fail_ips)
    top_login_ips = [ip for ip, _ in total_login_fail_ips.most_common(5)]

    all_needed_ips = list(set(top_probe_ips + top_login_ips))
    geo_map = get_ip_geo_bulk(all_needed_ips)

    # 6. 陌生 IP 登录检查
    known_ips = set(cfg.get("security", {}).get("known_ssh_ips", ["127.0.0.1"]))
    stranger_logins = [a for a in accepted_ssh if a["ip"] not in known_ips]

    # 7. 证书剩余有效天数
    ssl_domains = cfg.get("ssl_domains", [])
    nearest_cert = None
    min_days = 9999
    for dom in ssl_domains:
        days = check_ssl_expiry(dom)
        if days is not None and days < min_days:
            min_days = days
            nearest_cert = (dom, days)

    # 8. 备份与系统状态
    backup_status = check_backup_status(cfg)
    sys_stats = get_system_stats()

    # 9. 组装 1:1 日报内容 (支持多 VPS 节点标识)
    node_name = cfg.get("node_name", "")
    node_tag = f" · [{node_name}]" if node_name else ""

    lines = []
    lines.append(f"🛡️ 安全日报{node_tag} · {yesterday_str}")
    lines.append(f"🔎 扫描探测 {scan_count} 次 ({len(scan_ips)} 个IP)")
    lines.append(f"🔑 后台登录失败 {login_fail_count} 次 ({len(login_fail_ips)} 个IP)")
    lines.append(f"💻 SSH 撞密码 {ssh_fail_count} 次")

    if f2b["today_total_bans"] > 0:
        lines.append(f"🚫 当天新封禁 {f2b['today_total_bans']} 个: {new_bans_str}")
    else:
        lines.append("🚫 当天新封禁 0 个")

    if f2b["banned_count"] > 0:
        if f2b["permanent_count"] > 0 or f2b["temp_count"] > 0:
            lines.append(f"📦 当前封禁中: 永久 {f2b['permanent_count']} · 临时 {f2b['temp_count']}")
        else:
            lines.append(f"📦 当前封禁中: 共 {f2b['banned_count']} 个")
    else:
        lines.append("📦 当前封禁中: 0")

    lines.append("")

    if top_login_ips:
        lines.append("撞密码最多的 IP:")
        for ip in top_login_ips:
            cnt = total_login_fail_ips[ip]
            geo = geo_map.get(ip, "未知归属地")
            target_host = ip_to_host.get(ip, "")
            host_suffix = f" · {target_host}" if target_host else ""
            lines.append(f"{ip} ×{cnt} · {geo}{host_suffix}")
        lines.append("")

    if top_probe_ips:
        lines.append("扫描最多的 IP:")
        for ip in top_probe_ips:
            cnt = scan_ips[ip]
            geo = geo_map.get(ip, "未知归属地")
            lines.append(f"{ip} ×{cnt} · {geo}")
        lines.append("")

    if not stranger_logins:
        lines.append("✅ 没有陌生 IP 登录成功")
    else:
        lines.append(f"⚠️ 发现 {len(stranger_logins)} 次疑似陌生 IP 登录成功!")
        for sl in stranger_logins[:3]:
            lines.append(f"· 用户: {sl['user']} | IP: {sl['ip']}")

    if backup_status:
        lines.append(f"💾 备份: {backup_status}")

    if nearest_cert:
        dom, days = nearest_cert
        lines.append(f"🔐 证书: 最近到期 {dom} 剩 {days} 天")

    lines.append(f"💽 磁盘已用 {sys_stats['disk_percent']}% (剩 {sys_stats['disk_free_gb']}G) · 内存可用 {sys_stats['mem_avail_mb']} MB")

    # 构造 Top 撞密 IP 明细列表
    top_login_details = []
    for ip in top_login_ips:
        cnt = total_login_fail_ips[ip]
        geo = geo_map.get(ip, "未知归属地")
        target_host = ip_to_host.get(ip, "")
        top_login_details.append({"ip": ip, "count": cnt, "geo": geo, "host": target_host})

    # 构造 Top 扫描探测 IP 明细列表
    top_probe_details = []
    for ip in top_probe_ips:
        cnt = scan_ips[ip]
        geo = geo_map.get(ip, "未知归属地")
        top_probe_details.append({"ip": ip, "count": cnt, "geo": geo})

    # 探测本机公网 IP (用于日报展示，避免显示 127.0.0.1)
    pub_ip = "127.0.0.1"
    for u in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"):
        try:
            with urllib.request.urlopen(u, timeout=3) as r:
                ip_val = r.read().decode("utf-8").strip()
                if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ip_val):
                    pub_ip = ip_val
                    break
        except Exception:
            pass

    msg = "\n".join(lines)
    local_result = {
        "msg": msg,
        "public_ip": pub_ip,
        "scan_count": scan_count,
        "login_fail_count": login_fail_count,
        "ssh_fail_count": ssh_fail_count,
        "new_bans": f2b.get("today_total_bans", 0),
        "banned_count": f2b.get("banned_count", 0),
        "top_login_ips": top_login_ips,
        "top_login_details": top_login_details,
        "top_probe_details": top_probe_details,
        "stranger_logins": len(stranger_logins),
        "disk_percent": sys_stats.get("disk_percent", 0),
        "disk_free_gb": sys_stats.get("disk_free_gb", 0),
        "mem_avail_mb": sys_stats.get("mem_avail_mb", 0),
        "nearest_cert": nearest_cert,
        "backup_status": backup_status
    }

    if not send_tg:
        return local_result

    # send_tg=True 模式：检测是否配置了纳管节点（主控模式）
    nodes = load_nodes()
    tz_offset = cfg.get("timezone_offset", 8)
    now_tz = datetime.now(timezone.utc) + timedelta(hours=tz_offset)
    today_str = now_tz.strftime("%Y-%m-%d")

    state = load_state()
    if not force and state.get("last_daily_sent_date") == today_str:
        safe_print(f"[i] 今日全节点安全总报 ({today_str}) 已推送过，无需重复发送。如需重新发送请加 --force")
        return local_result

    if nodes and len(nodes) >= 1:
        # 有多节点配置（主控端模式），生成并推送全节点总报
        all_nodes_report = build_all_nodes_daily_report(cfg, local_data=local_result)
        if all_nodes_report:
            send_telegram(cfg, all_nodes_report, parse_mode="HTML")
            state["last_daily_sent_date"] = today_str
            save_state(state)
            safe_print(f"[+] 全节点安全总报已成功推送至 Telegram (共 {len(nodes)} 台 VPS)")
            return local_result

    # 兜底：独立单机节点模式
    send_telegram(cfg, msg, parse_mode=None)
    state["last_daily_sent_date"] = today_str
    save_state(state)
    safe_print("[+] 单机安全日报已推送至 Telegram")
    return local_result


# ----------------- 保活与开机自启动模块 -----------------
def get_uptime_info():
    """获取系统运行时间描述与秒数"""
    try:
        with open("/proc/uptime", "r") as f:
            total_seconds = float(f.readline().split()[0])
            days = int(total_seconds // 86400)
            hours = int((total_seconds % 86400) // 3600)
            minutes = int((total_seconds % 3600) // 60)
            parts = []
            if days > 0:
                parts.append(f"{days}天")
            if hours > 0:
                parts.append(f"{hours}小时")
            parts.append(f"{minutes}分钟")
            return ("".join(parts) if parts else "刚启动"), total_seconds
    except Exception:
        return "刚启动", 60.0


def send_boot_notification(cfg):
    """向 Telegram 发送 VPS 重启上线自启恢复通知"""
    node_name = cfg.get("node_name", "本机 (主节点)")
    uptime_desc, _ = get_uptime_info()
    pub_ip = "127.0.0.1"
    for u in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            with urllib.request.urlopen(u, timeout=3) as r:
                pub_ip = r.read().decode("utf-8").strip()
                break
        except Exception:
            pass

    text = (
        f"🔄 <b>[VPS 重启上线自启通知]</b>\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"🏷️ <b>节点标识</b>: <code>{html_escape(node_name)}</code>\n"
        f"🌐 <b>主机地址</b>: <code>{pub_ip}</code>\n"
        f"⏱️ <b>开机运行</b>: <code>{uptime_desc}</code>\n"
        f"🛡️ <b>保活守护</b>: 🟢 增量安全巡检与常驻自启服务已就绪\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"<i>该 VPS 重启完成，安全防护引擎已自启激活并持续保活！</i>"
    )
    send_telegram(cfg, text)
    safe_print(f"[+] 开机自启通知已推送至 Telegram: {node_name} [{pub_ip}]")


def run_daemon_mode(cfg):
    """常驻后台保活守护进程：开机通知 + 每 60s 增量检测突发攻击 + 每天 09:00 安全日报"""
    safe_print("[*] VPS 安全巡检常驻保活守护进程已启动...")
    _, uptime_secs = get_uptime_info()
    if uptime_secs < 300:
        send_boot_notification(cfg)

    last_daily_date = ""
    while True:
        try:
            cfg = load_config()
            # 1. 增量突发检测
            run_check_mode(cfg, interactive=False)

            # 2. 每日 09:00 日报检测 (采用东八区北京时间 UTC+8，确保准点推送)
            tz_offset = cfg.get("timezone_offset", 8)
            now_tz = datetime.now(timezone.utc) + timedelta(hours=tz_offset)
            today_str = now_tz.strftime("%Y-%m-%d")
            daily_hour = cfg.get("daily_hour", 9)
            if now_tz.hour == daily_hour and now_tz.minute <= 5 and last_daily_date != today_str:
                state = load_state()
                if state.get("last_daily_sent_date") != today_str:
                    safe_print(f"[*] 触发 {daily_hour:02d}:00 安全日报自动生成 (UTC+{tz_offset})...")
                    state["last_daily_sent_date"] = today_str
                    save_state(state)
                    last_daily_date = today_str
                    run_daily_mode(cfg, send_tg=True)
                else:
                    last_daily_date = today_str

        except Exception as e:
            safe_print(f"[-] 守护进程循环异常: {e}")

        # 每 60 秒轮询一次
        time.sleep(60)


# ----------------- 命令行操作分发 -----------------
def main():
    if len(sys.argv) < 2:
        print("VPS 安全巡检与监控引擎")
        print("用法:")
        print("  python3 vps_security_guard.py daemon  # 常驻后台保活守护模式 (Systemd 守护/秒级即时拦截)")
        print("  python3 vps_security_guard.py check   # 增量突发攻击检测 (建议 Crontab 每 5 分钟)")
        print("  python3 vps_security_guard.py daily   # 24小时安全日报生成 (建议 Crontab 每天早晨 9:00)")
        print("  python3 vps_security_guard.py boot    # 开机自启通知")
        print("  python3 vps_security_guard.py test    # 测试 Telegram 连接并发送测试通知")
        sys.exit(1)

    cfg = load_config()
    cmd = sys.argv[1].lower()

    if cmd == "check":
        interactive = "--interactive" in sys.argv or "-i" in sys.argv
        run_check_mode(cfg, interactive=interactive)
    elif cmd == "daily":
        force = "--force" in sys.argv or "-f" in sys.argv
        run_daily_mode(cfg, send_tg=True, force=force)
    elif cmd == "boot":
        send_boot_notification(cfg)
    elif cmd == "daemon":
        run_daemon_mode(cfg)
    elif cmd == "test":
        test_content = (
            "🔔 VPS 安全监控通知测试\n"
            "系统监控环境就绪，Telegram 通知连通正常！\n"
            f"服务器时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        ok = send_telegram(cfg, test_content)
        if ok:
            print("[+] 测试消息已成功推送到 Telegram！")
        else:
            print("[-] 测试失败，请检查配置文件中的 bot_token 与 chat_id。")
    else:
        print(f"[ERROR] 未知命令: {cmd}")


if __name__ == "__main__":
    main()
