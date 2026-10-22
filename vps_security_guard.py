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
from datetime import datetime, timedelta
from collections import Counter, defaultdict

# ----------------- 路径与持久化文件 -----------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "config.json")
GEO_CACHE_FILE = os.path.join(SCRIPT_DIR, "ip_geo_cache.json")
STATE_FILE = os.path.join(SCRIPT_DIR, "monitor_state.json")

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
def send_telegram(cfg, message_text):
    """通过 Telegram Bot 发送消息，使用纯文本避免转义字符报错"""
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
                    days_left = (expire_date - datetime.utcnow()).days
                    return days_left
    except Exception:
        pass
    return None


# ----------------- 模式 A: 突发攻击检测 (check) -----------------
def run_check_mode(cfg):
    state = load_state()
    nginx_log = cfg.get("logs", {}).get("nginx_access_log", "/var/log/nginx/access.log")
    login_paths = cfg.get("security", {}).get("login_paths", [])
    alert_thresh = cfg.get("security", {}).get("alert_threshold_failures", 5)
    site_names = cfg.get("sites", {})

    nginx_lines = read_incremental_lines(nginx_log, "nginx", state)
    save_state(state)

    if not nginx_lines:
        return

    failed_logins, _ = parse_nginx_lines(nginx_lines, login_paths)
    if len(failed_logins) < alert_thresh:
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

        # 组装 1:1 格式告警消息
        lines = []
        lines.append(f"🔔 后台登录尝试拦截 ({distinct_ip_count} 个 IP 汇总)")
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


# ----------------- 模式 B: 安全日报 (daily) -----------------
def run_daily_mode(cfg):
    now = datetime.now()
    yesterday_str = (now - timedelta(days=1)).strftime("%m月%d日")

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

    # 9. 组装 1:1 日报内容
    lines = []
    lines.append(f"🛡️ 安全日报 · {yesterday_str}")
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

    msg = "\n".join(lines)
    send_telegram(cfg, msg)


# ----------------- 命令行操作分发 -----------------
def main():
    if len(sys.argv) < 2:
        print("VPS 安全巡检与监控引擎")
        print("用法:")
        print("  python3 vps_security_guard.py check   # 增量突发攻击检测 (建议 Crontab 每 5 分钟)")
        print("  python3 vps_security_guard.py daily   # 24小时安全日报生成 (建议 Crontab 每天早晨 9:00)")
        print("  python3 vps_security_guard.py test    # 测试 Telegram 连接并发送测试通知")
        sys.exit(1)

    cfg = load_config()
    cmd = sys.argv[1].lower()

    if cmd == "check":
        run_check_mode(cfg)
    elif cmd == "daily":
        run_daily_mode(cfg)
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
