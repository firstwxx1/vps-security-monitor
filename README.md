# 🛡️ VPS 安全巡检与监控终端系统 (Telegram 版)

1:1 复刻真实黑客攻击拦截告警（智能识别轮换代理池）与每日安全巡检日报，自带交互式命令行终端菜单面板。

---

## 🚀 一键在线部署（推荐）

在你的 Linux VPS 上直接执行以下单行命令：

```bash
curl -fsSL https://raw.githubusercontent.com/firstwxx1/vps-security-monitor/main/install.sh | sudo bash
```

安装完成后，系统会自动注册全局命令：**`vps-guard`**。
以后无论在哪个目录下，只要在 SSH 终端输入：
```bash
vps-guard
```
即可随时调出全彩色终端管理面板！

---

## 🌟 核心特性与功能保障

- **🖥️ 交互式终端菜单 (`menu.sh` / `vps-guard`)**：
  - 纯终端彩色可视化配置，无需手动敲复杂的 JSON 字段。
  - 支持直接在菜单中测试 Telegram 连通性、查看实时运行状态、自检 Nginx / SSH 日志路径。
- **🔔 突发攻击即时拦截告警 (`check` 模式)**：
  - 增量读取 Nginx 访问日志，秒级响应，针对后台路径（如 `/api/v1/auth/login` 等）进行爆破识别。
  - **智能识别轮换代理池**：若攻击者使用几十个海外机房 IP 各尝试 1 次爆破，脚本自动命中特征并标记：`💡 每个 IP 只试 1 次，属轮换代理池，逐个封禁意义不大。`
  - 汇总恶意 User-Agent（如 `Python/3.11 aiohttp`）与攻击者组织/运营商信息。
- **🛡️ 每日安全日报 (`daily` 模式)**：
  - 统计过去 24 小时内的 Web 路径探测、后台登录撞库、SSH 密码暴力破解。
  - 统计 Fail2ban 封禁情况（包括当天新封禁与历史封禁）。
  - **陌生 IP 登录审计**：自动审计 SSH 成功登录（`Accepted password/publickey`），若不在白名单立即告警。
  - 自动检测 SSL 证书最近到期天数、系统磁盘用量、可用内存、备份校验状态。
- **⚡ 零外部依赖**：仅使用 Python 3 标准库，无需 `pip install` 任何第三方包。
- **🌐 IP 归属地与 ISP 批量查询**：内置本地持久化缓存，调用高可靠接口分批查询，不丢弃也不频繁打扰接口。

---

## 📋 终端控制面板展示

运行 `vps-guard` 将呈现如下控制台：

```text
=====================================================
         🛡️  VPS 安全巡检与监控终端管理面板          
=====================================================
 机器人通知 : [已配置]   Crontab 定时 : [已激活]
 Nginx 日志 : [正常] (/var/log/nginx/access.log)
-----------------------------------------------------
 1. 配置 Telegram 报警通知机器人 (Token / Chat ID)
 2. 配置受监控的登录/敏感后台路径 (如 /api/v1/auth/login)
 3. 配置 SSL 证书监控域名列表
 4. 配置 SSH 允许白名单 IP (陌生登录审计)
 5. 配置备份校验状态 (R2 / 本地目录 / 自定义命令)
-----------------------------------------------------
 6. 立即执行：突发攻击增量检测 (check)
 7. 立即生成：全天安全日报 (daily)
 8. 一键安装 / 更新 Crontab 定时任务
 9. 一键卸载 Crontab 定时任务
 10. 系统环境与日志排查自检
-----------------------------------------------------
 0. 退出管理菜单
=====================================================
```

---

## ⚙️ 配置文件参数说明 (`config.json`)

如果你偏好直接编辑配置文件，也可以直接修改 `config.json`：

```json
{
  "telegram": {
    "bot_token": "你的Telegram机器人Token",
    "chat_id": "你的Telegram数字Chat_ID"
  },
  "logs": {
    "nginx_access_log": "/var/log/nginx/access.log"
  },
  "sites": {
    "gpt.isoziyuan.com": "Sub2API 大模型后台",
    "teyir.com": "Teyir 主站"
  },
  "security": {
    "login_paths": [
      "/api/v1/auth/login",
      "/wp-login.php",
      "/admin/login",
      "/login"
    ],
    "known_ssh_ips": [
      "127.0.0.1",
      "你的常用公网IP"
    ],
    "alert_threshold_failures": 5
  },
  "ssl_domains": [
    "gpt.isoziyuan.com",
    "tsc.ailxw.com"
  ],
  "backup": {
    "enabled": true,
    "name": "R2",
    "type": "command",
    "command": "echo '已校验 0261021-193047'"
  }
}
```

---

## ⏰ Crontab 定时规则（可在面板中一键开启）

- **突发检测**：`*/5 * * * *` （每 5 分钟检查一次，有代理池或暴力撞库立即报警）
- **安全日报**：`0 9 * * *` （每天早晨 09:00 发送昨日 24 小时汇总）
