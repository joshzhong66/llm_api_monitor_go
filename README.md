# LLM API Monitor (Go)

通过网络抓包分析企业内部服务器上的 LLM API 流量，实时统计各厂商 API 的调用次数、流量、Token 估算和费用。

不解密 HTTPS 内容，仅通过 TLS ClientHello SNI、IP 映射等元数据识别目标域名和厂商。

## 目录

- [功能概览](#功能概览)
- [架构设计](#架构设计)
- [环境要求](#环境要求)
- [快速部署](#快速部署)
- [配置说明](#配置说明)
- [Web 界面使用](#web-界面使用)
- [API 接口](#api-接口)
- [支持的 LLM 厂商](#支持的-llm-厂商)
- [IP-用户名映射](#ip-用户名映射)
- [解析管道监控](#解析管道监控)
- [计费与估算规则](#计费与估算规则)
- [运维指南](#运维指南)
- [项目结构](#项目结构)
- [常见问题](#常见问题)

---

## 功能概览

| 功能 | 说明 |
|------|------|
| 实时流量抓包 | 通过 tcpdump + BPF 过滤器抓取指定网卡上的 LLM API 流量 |
| gopacket 原生解析 | 单次遍历 pcap 文件，同时提取 packet events + TLS SNI 域名 |
| 厂商自动识别 | 支持 18 个厂商 43 条域名规则（exact + wildcard 匹配） |
| Token 和费用估算 | 根据上下行流量估算 Token 数量，对接官方价格表计算费用 |
| IP → 用户名映射 | 通过 AD 域控 + DNS 解析，自动关联 IP 到员工姓名和部门 |
| Web 管理界面 | 中文 SPA 界面，支持分页、搜索、时间范围过滤、厂商筛选 |
| 解析管道监控 | 前端实时展示延迟、进度、积压数量，命令行脚本一键查看 |
| 多路并发写入 | goroutine Worker Pool + 批量多行 INSERT，消除锁竞争 |
| 域名规则管理 | 通过 Web 界面或 API 动态添加新的厂商域名规则 |

---

## 架构设计

```text
 网卡流量
    |
    v
 tcpdump (BPF 过滤器，只抓 LLM API 域名)
    |  每 60 秒轮转一个 pcap 文件
    v
 Capture Daemon  ──────────────>  Task Channel (缓冲 1000)
                                       |
              ┌────────────────────────┤
              |                        |
         rt-worker-1              rt-worker-8
              |       ...              |
              v                        v
         gopacket 解析 (单次遍历 pcap，提取 SNI/IP/域名)
              |                        |
              v                        v
         Result Channel (缓冲 500)
              |
              v
         Writer Daemon (writeMu 串行化)
              |
              ├── UpsertSessions     → api_logs      (批量 50 行)
              ├── InsertRequestLogs  → request_logs   (批量 100 行) ← 并行
              └── InsertTransportEvents → transport_events (批量 200 行) ← 并行
              |
              v
         MySQL 8.0 (innodb_buffer_pool=8G)
              |
              v
         HTTP API Server (:8789)  →  Web 前端 (SPA)

  后台另有 Backfill goroutine:
     DB 查 queued job → gopacket 解析 → 直接调 writer.processResult
     (绕过 Result Channel，不阻塞实时数据)
```

### 数据流细节

1. **抓包**：tcpdump 以 BPF 过滤器只抓 LLM API 相关域名的 HTTPS 流量（port 443），每 60 秒轮转一个 pcap 文件
2. **解析**：8 个 Worker goroutine 并行用 gopacket 解析 pcap，单次遍历同时提取 packet events 和 TLS ClientHello SNI
3. **域名识别**：优先 SNI → 回退 payload 正则 → 再回退 IP Hint Cache（DNS 反查）
4. **Session 跟踪**：通过 TCP 四元组 flowMap/revMap 实现 O(1) 会话查找，上行（dst_port=443）/下行（src_port=443）分别计数
5. **批量写入**：多行 VALUES 批量 INSERT + ON DUPLICATE KEY UPDATE，减少 SQL 往返 50-200 倍
6. **实时优先**：Backfill 走独立路径直接调用 processResult，不占用 Result Channel

---

## 环境要求

| 组件 | 最低版本 | 说明 |
|------|----------|------|
| 操作系统 | CentOS 7 / Ubuntu 18.04+ | 需要 root 权限（tcpdump 抓包） |
| Go | 1.21+ | 编译用，运行时不需要 |
| libpcap | 1.5+ | gopacket 依赖 |
| MySQL | 8.0+ | 推荐 Docker 部署 |
| Redis | 5.0+ | 可选，用于查询缓存 |
| tcpdump | 4.0+ | 系统自带 |

### 可选组件

| 组件 | 用途 |
|------|------|
| AD 域控 + DNS 服务器 | IP → 用户名映射（需要 ldapsearch + dig） |
| GitHub CLI (gh) | 自动发布 Release |

---

## 快速部署

### 第一步：安装依赖

```bash
# CentOS / RHEL
yum install -y libpcap-devel

# Ubuntu / Debian
apt install -y libpcap-dev
```

### 第二步：部署 MySQL（如果没有）

```bash
docker run -d \
  --name llm-monitor-mysql \
  --restart unless-stopped \
  -p 127.0.0.1:3306:3306 \
  -e MYSQL_ROOT_PASSWORD=123456 \
  -e MYSQL_DATABASE=llm_api_monitor \
  -v /data/mysql_llm_monitor:/var/lib/mysql \
  --memory=8g \
  mysql:8.0 \
  --character-set-server=utf8mb4 \
  --collation-server=utf8mb4_unicode_ci \
  --skip-log-bin \
  --default-authentication-plugin=mysql_native_password \
  --innodb-buffer-pool-size=4G \
  --innodb-flush-log-at-trx-commit=2 \
  --innodb-flush-method=O_DIRECT \
  --innodb-io-capacity=2000 \
  --max-connections=200

# 等待 MySQL 就绪
until docker exec llm-monitor-mysql mysqladmin -uroot -p123456 ping 2>/dev/null | grep -q alive; do sleep 2; done

# 在线扩展 buffer pool 到 8G（启动后执行）
docker exec llm-monitor-mysql mysql -uroot -p123456 \
  -e "SET GLOBAL innodb_buffer_pool_size = 8589934592;"
```

### 第三步：编译

```bash
cd /root/llm_api_monitor_go

# 安装 Go（如果没有）
curl -sLO https://go.dev/dl/go1.22.12.linux-amd64.tar.gz
tar -C /usr/local -xzf go1.22.12.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# 编译
bash build.sh
# 输出: llm-api-monitor (约 11MB 单文件)
```

### 第四步：配置

```bash
cp .env.example .env
vim .env
```

至少需要修改以下配置：

```bash
# 网卡名称（必须匹配你的物理网卡）
LLM_MONITOR_IFACE=eth0

# MySQL 连接（修改为你的密码）
LLM_MONITOR_MYSQL_PASSWORD=your_password

# Web 服务端口
LLM_MONITOR_PORT=8789
```

### 第五步：启动

```bash
# 方式 1：直接运行（前台，用于测试）
./llm-api-monitor

# 方式 2：systemd 服务（推荐，自动重启）
cp systemd/llm-api-monitor-go.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable llm-api-monitor-go
systemctl start llm-api-monitor-go
```

### 第六步：验证

```bash
# 检查服务状态
systemctl status llm-api-monitor-go

# 验证 API
curl -s http://127.0.0.1:8789/api/status | python -m json.tool

# 打开 Web 界面
# 浏览器访问 http://你的服务器IP:8789
```

正常输出示例：

```json
{
    "ok": true,
    "data": {
        "running": true,
        "capture_running": true,
        "active_sessions": 42,
        "iface": "eth0",
        "window_seconds": 60,
        "last_job_id": 100
    }
}
```

---

## 配置说明

所有配置通过 `.env` 文件设置，修改后需要重启服务生效。

### 核心配置

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `LLM_MONITOR_PORT` | `8789` | Web 服务端口 |
| `LLM_MONITOR_IFACE` | `enp1s0f3` | 抓包网卡名称 |
| `LLM_MONITOR_WINDOW_SECONDS` | `60` | pcap 轮转窗口（秒），建议 60 |
| `LLM_MONITOR_BPF` | `port 443` | BPF 过滤器，建议收紧到具体域名 |
| `LLM_MONITOR_AUTOSTART` | `1` | 启动时自动开始抓包（0=仅 API 查询） |
| `LLM_MONITOR_REALTIME_WORKERS` | `8` | 解析 worker 数量（建议 = CPU 核数） |
| `LLM_MONITOR_RETAIN_PARSED_PCAP` | `0` | 解析后保留 pcap 文件（0=删除节省磁盘） |

### 数据库配置

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `LLM_MONITOR_MYSQL_HOST` | `127.0.0.1` | MySQL 地址 |
| `LLM_MONITOR_MYSQL_PORT` | `3306` | MySQL 端口 |
| `LLM_MONITOR_MYSQL_USER` | `root` | MySQL 用户名 |
| `LLM_MONITOR_MYSQL_PASSWORD` | `123456` | MySQL 密码 |
| `LLM_MONITOR_MYSQL_DATABASE` | `llm_api_monitor` | 数据库名 |
| `LLM_MONITOR_MYSQL_MAX_OPEN` | `20` | 连接池最大连接数 |
| `LLM_MONITOR_REDIS_ENABLED` | `1` | 是否启用 Redis 缓存 |

### BPF 过滤器配置

BPF 过滤器决定了抓哪些流量。**收紧 BPF 可以将 pcap 文件从 GB 级降至 MB 级**：

```bash
# 最小配置（只抓 API 流量）
LLM_MONITOR_BPF=port 443 and (host api.openai.com or host api.anthropic.com or host api.deepseek.com)

# 完整配置（API + 网页流量）
LLM_MONITOR_BPF=port 443 and (host api.openai.com or host chatgpt.com or host api.anthropic.com or host claude.ai or host generativelanguage.googleapis.com or host api.deepseek.com or host platform.deepseek.com ...)
```

> 重要：BPF 中的域名会在 tcpdump 启动时被解析为 IP 地址。确保 DNS 可用。

---

## Web 界面使用

浏览器打开 `http://服务器IP:8789`，界面分为以下功能模块：

### API 消费汇总

按厂商+域名聚合，展示会话数、请求次数、上行/下行流量、Token 估算和费用。支持按厂商筛选。

### 会话日志（API / 网页）

每一条记录代表一个 TCP 连接的生命周期。字段包括：

| 字段 | 说明 |
|------|------|
| 源 IP | 发起请求的客户端 IP |
| 用户 | 通过 AD 域控关联的用户名（需配置 IP-用户映射） |
| 首次/最近时间 | 会话的时间跨度 |
| 厂商 / 域名 | 自动识别的 LLM 厂商和目标域名 |
| 上行/下行/总流量 | 字节数统计 |
| Token / 费用 | 基于流量的估算值 |

**过滤功能**：
- **厂商筛选**：顶部标签切换
- **搜索框**：支持按 IP、用户名、域名、厂商搜索
- **时间范围**：最近 5/10/15/30/60 分钟或全部
- **隐藏空会话**：过滤掉下行为 0 的 TCP 握手/探测流量（默认勾选）

### 请求明细（API / 网页）

比会话更细粒度——每一次上行数据包触发一条记录。

### QUIC 诊断

展示 UDP/443 传输事件（如 HTTP/3、QUIC 流量），目前仅记录五元组和字节数。

### 厂商域名规则

查看和管理域名匹配规则。可在线添加新域名：

1. 填写厂商名称
2. 填写域名（支持通配符 `*.example.com`）
3. 选择匹配类型（exact / wildcard）
4. 点击提交

---

## API 接口

所有接口返回 `{"ok": true/false, "data": ...}` 格式。

| 接口 | 方法 | 说明 | 主要参数 |
|------|------|------|----------|
| `/api/status` | GET | 系统运行状态 | - |
| `/api/summary` | GET | 厂商+域名聚合统计 | - |
| `/api/logs` | GET | 会话日志（分页） | `page`, `page_size`, `vendor`, `search`, `channel_class`, `time_window_minutes`, `min_bytes` |
| `/api/request-logs` | GET | 请求明细（分页） | 同上 |
| `/api/transport-events` | GET | 传输事件（分页） | `page`, `page_size`, `src_ip`, `protocol`, `search`, `time_window_minutes` |
| `/api/targets` | GET | 所有域名规则 | - |
| `/api/targets` | POST | 添加域名规则 | `{"vendor": "...", "domains": ["..."], "match_type": "exact"}` |
| `/api/jobs` | GET | 抓包任务列表 | `limit` |
| `/api/pipeline` | GET | 解析管道状态 | - |
| `/api/quic-observations` | GET | QUIC 观测记录 | `limit` |

### channel_class 参数

| 值 | 含义 | 包含的域名 |
|----|------|-----------|
| `api` | API 流量 | 排除 WebDomainHints 中的域名 |
| `web` | 网页流量 | WebDomainHints + WebMixedDomains |
| 空 | 全部流量 | 不过滤 |

---

## 支持的 LLM 厂商

内置 18 个厂商 43 条域名规则，开箱即用：

| 厂商 | 域名 | 类型 |
|------|------|------|
| ChatGPT / OpenAI | `api.openai.com`, `chatgpt.com`, `chat.openai.com` | API + 网页 |
| Azure OpenAI | `*.openai.azure.com` | API（通配符） |
| Claude / Anthropic | `api.anthropic.com`, `claude.ai` | API + 网页 |
| Gemini / Google AI | `generativelanguage.googleapis.com`, `aiplatform.googleapis.com`, `gemini.google.com`, `aistudio.google.com` | API + 网页 |
| DeepSeek | `api.deepseek.com`, `platform.deepseek.com` | API + 网页 |
| Kimi / Moonshot | `api.moonshot.cn`, `kimi.com`, `kimi.moonshot.cn` 等 6 个 | API + 网页 |
| 百度 / 千帆 | `qianfan.baidubce.com` | API |
| 腾讯 / 混元 | `hunyuan.tencentcloudapi.com` 等 4 个 | API |
| 千问 / 通义 | `dashscope.aliyuncs.com`, `qwen.ai`, `tongyi.aliyun.com` 等 6 个 | API + 网页 |
| 豆包 / 火山引擎 | `ark.cn-beijing.volces.com` 等 3 个 | API |
| MiniMax | `api.minimax.io`, `api.minimaxi.com` | API |
| 智谱 | `open.bigmodel.cn` | API |
| Mistral | `api.mistral.ai`, `console.mistral.ai` | API |
| Cohere | `api.cohere.com` | API |
| Grok / xAI | `api.x.ai`, `grok.com`, `accounts.x.ai` | API + 网页 |
| Amazon Bedrock | `bedrock-runtime.*.amazonaws.com` 等 3 个 | API（通配符） |

可通过 Web 界面或 `POST /api/targets` 动态添加新厂商。

---

## IP-用户名映射

将内网 IP 关联到 AD 域控中的员工姓名和部门，在会话日志和请求明细中展示。

### 工作原理

```text
AD 域控 (LDAP)          DNS 服务器
    |                       |
    | ldapsearch            | dig
    | 查询所有电脑主机名     | 正向解析 hostname → IP
    v                       v
    collect_ip_users.sh
    |
    | 输出 scripts/ip_user_map.json
    v
    Go 服务 (每 5 分钟热加载)
    |
    ├── API 响应中填充 src_user/src_hostname/src_department
    └── DB 写入时落库（新数据永久保存用户名）
```

### 配置步骤

#### 1. 设置环境变量

```bash
export LDAP_URL='ldap://你的域控IP:389'
export LDAP_BIND_DN='ldap-readonly@your.domain'
export LDAP_BIND_PASSWORD='密码'
export LDAP_BASE_DN='DC=your,DC=domain'
export DNS_SERVER='你的DNS服务器IP'
```

#### 2. 手动运行一次

```bash
LDAP_BIND_PASSWORD='密码' bash scripts/collect_ip_users.sh
```

输出示例：

```text
==========================================
  采集完成
==========================================
  AD 电脑总数:   1378
  DNS 解析成功:  409
  JSON 输出:     scripts/ip_user_map.json
  CSV 输出:      scripts/ip_user_map.csv
==========================================
```

#### 3. 配置定时任务

```bash
# 每天 6:00 自动更新
echo "0 6 * * * LDAP_BIND_PASSWORD='密码' bash /path/to/scripts/collect_ip_users.sh >> logs/collect_ip_users.log 2>&1" | crontab -
```

Go 服务每 5 分钟自动检测 `ip_user_map.json` 文件变更并热加载，无需重启。

### 主机名规则

脚本从主机名提取用户名和部门：

| 主机名 | 提取结果 |
|--------|---------|
| `IT-zhongjinlin.corp.com` | 用户: `zhongjinlin`, 部门: `IT` |
| `SDC-wanglong.corp.com` | 用户: `wanglong`, 部门: `SDC` |
| `server01.corp.com` | 用户: `server01`, 部门: 空 |

如果你的主机名命名规则不同，修改 `collect_ip_users.sh` 中的提取逻辑。

---

## 解析管道监控

### Web 界面

页面顶部状态栏实时显示（每 5 秒刷新）：

| 指示灯 | 含义 |
|--------|------|
| 延迟 Xs（绿色） | 实时数据延迟 < 60 秒，正常 |
| 延迟 Xm（橙色） | 延迟 1-5 分钟，轻微积压 |
| 延迟 Xh（红色） | 延迟 > 5 分钟，需要关注 |
| 已解析 X% | 总体完成百分比 |
| 待处理 N | 排队中的 pcap 文件数 |

### 命令行脚本

```bash
bash scripts/pipeline_status.sh
```

输出示例：

```text
┌──────────────────────────────────────────────────────────────────────────┐
│ LLM API Monitor Pipeline Status                                          │
│ 2026-04-12 17:57:32                                                      │
└──────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────┬──────────────────────────────────────────────┐
│ DB latest                │ 2026-04-12 17:57:16                          │
│ Now                      │ 2026-04-12 17:57:32                          │
│ Lag                      │ 16s (正常)                                 │
│ Progress                 │ 17200/18431 (93%)                            │
│ Pending                  │ 1231                                         │
│ Failed                   │ 0                                            │
└──────────────────────────┴──────────────────────────────────────────────┘
```

### API

```bash
curl http://127.0.0.1:8789/api/pipeline
```

---

## 计费与估算规则

费用统计基于流量元数据估算，不解密 HTTPS 内容。

### 官方厂商定价

对于已知厂商，从 `official_model_pricing_usd.xlsx` 读取官方价格：

| 厂商 | 默认模型 | 输入价/M tokens | 输出价/M tokens |
|------|----------|----------------|----------------|
| ChatGPT / OpenAI | gpt-5.4 | $2.50 | $15.00 |
| Claude / Anthropic | claude-opus-4-6 | $5.50 | $27.50 |
| Gemini / Google AI | gemini-3.1-pro-preview | $2.00 | $12.00 |
| MiniMax | MiniMax-M2.7 | $0.40 | $0.32 |
| 智谱 | glm-5 | $0.46 | $2.09 |
| 千问 / 通义 | qwen3.5-plus | $0.23 | $0.16 |

### 代理域名公式

对于通过统一代理转发的流量，使用经验回归公式：

```text
input_tokens    = uplink_bytes   x 0.2038
output_tokens   = downlink_bytes x 0.0047
estimated_cost  = input_tokens x $0.0000031 + output_tokens x $0.0000188
```

### 通用回退公式

未匹配到价格表的厂商使用默认公式：

```text
input_tokens  = uplink_bytes x 8 / 611.23
output_tokens = downlink_bytes x 8 / 222.26
```

---

## 运维指南

### 启动 / 停止 / 重启

```bash
systemctl start llm-api-monitor-go
systemctl stop llm-api-monitor-go
systemctl restart llm-api-monitor-go
systemctl status llm-api-monitor-go
```

### 查看日志

```bash
# 实时日志
journalctl -u llm-api-monitor-go -f

# 最近 100 行
journalctl -u llm-api-monitor-go -n 100 --no-pager
```

### 查看解析管道进度

```bash
bash scripts/pipeline_status.sh
```

### 更新 IP-用户映射

```bash
LDAP_BIND_PASSWORD='密码' bash scripts/collect_ip_users.sh
# Go 服务 5 分钟内自动加载，无需重启
```

### MySQL Buffer Pool 扩展

CentOS 7 上 MySQL 容器启动时 8G buffer pool 初始化慢，建议容器启动后在线扩展：

```bash
docker exec llm-monitor-mysql mysql -uroot -p密码 \
  -e "SET GLOBAL innodb_buffer_pool_size = 8589934592;"
```

已配置 crontab `@reboot` 自动执行。

### 清理旧 pcap 文件

如果 `RETAIN_PARSED_PCAP=0`，已解析的 pcap 会自动删除。手动清理：

```bash
# 查看磁盘占用
du -sh /data/llm_api_monitor/captures/

# 删除 3 天前的 pcap（谨慎操作）
find /data/llm_api_monitor/captures/ -name "*.pcap" -mtime +3 -delete
```

### 重新编译

修改代码后重新编译和部署：

```bash
cd /root/llm_api_monitor_go
export PATH=$PATH:/usr/local/go/bin
go build -o llm-api-monitor ./cmd/monitor/
systemctl restart llm-api-monitor-go
```

---

## 项目结构

```text
llm_api_monitor_go/
├── cmd/
│   ├── monitor/main.go              # 入口：启动所有组件、信号处理
│   └── ldap_lookup/main.go          # LDAP 查询测试工具
├── internal/
│   ├── api/
│   │   ├── server.go                # HTTP API 路由和处理函数
│   │   ├── pricing.go               # XLSX 价格表解析 + 厂商定价匹配
│   │   └── ipuser.go                # IP-用户映射加载和查询
│   ├── capture/
│   │   └── daemon.go                # tcpdump 管理、pcap 发现、任务分发
│   ├── config/
│   │   └── config.go                # .env 配置加载，全部配置项定义
│   ├── db/
│   │   └── store.go                 # MySQL 连接池 + Redis + 全部 CRUD
│   ├── ldapad/
│   │   └── client.go                # AD 域控 LDAP 客户端
│   ├── model/
│   │   └── model.go                 # Session/RequestLog/TransportEvent 等数据模型
│   ├── parser/
│   │   ├── engine.go                # gopacket 解析引擎、Session 管理、SNI 提取
│   │   └── matcher.go               # 域名→厂商匹配器 (exact + wildcard)
│   └── writer/
│       └── daemon.go                # Writer Daemon + Worker Pool + Backfill
├── static/
│   ├── index.html                   # Web 界面 HTML 骨架
│   ├── app.js                       # 前端 SPA 逻辑（原生 JS，无框架）
│   └── styles.css                   # 样式（暗色主题，响应式布局）
├── scripts/
│   ├── collect_ip_users.sh          # AD + DNS → IP-用户映射采集
│   ├── pipeline_status.sh           # 解析管道状态命令行面板
│   ├── ldap_query.sh                # LDAP 交互查询工具
│   ├── ip_user_map.json             # IP-用户映射数据（自动生成）
│   └── ip_user_map.csv              # IP-用户映射 CSV 格式
├── systemd/
│   └── llm-api-monitor-go.service   # systemd 服务文件
├── .env                             # 配置文件
├── build.sh                         # 编译脚本
├── go.mod / go.sum                  # Go 依赖管理
├── official_model_pricing_usd.xlsx  # 官方模型价格表
└── llm-api-monitor                  # 编译后的二进制文件（~11MB）
```

---

## 常见问题

### Q: 启动后 Web 页面没有数据？

1. 检查 tcpdump 是否在运行：`ps aux | grep tcpdump`
2. 检查 BPF 过滤器是否包含了你需要的域名
3. 检查网卡名称是否正确：`ip link show`
4. 查看管道进度：`bash scripts/pipeline_status.sh`

### Q: 延迟越来越高？

查看管道状态中的 pending 数量。如果持续增长：
- 增大 `LLM_MONITOR_WINDOW_SECONDS`（推荐 60）减少 job 数量
- 检查 MySQL 慢查询：`docker exec llm-monitor-mysql mysql -uroot -p密码 -e "SHOW GLOBAL STATUS LIKE 'Slow_queries';"`
- 确认 buffer pool 是否足够：建议 4-8GB

### Q: 用户名显示为空？

1. 确认 `scripts/ip_user_map.json` 文件存在且包含该 IP
2. 手动运行 `bash scripts/collect_ip_users.sh` 更新映射
3. 该 IP 可能不在 AD 域控中（服务器、虚拟机等）

### Q: pcap 文件占用大量磁盘？

设置 `LLM_MONITOR_RETAIN_PARSED_PCAP=0` 自动删除已解析的 pcap。
收紧 BPF 过滤器可以将 pcap 从 GB 级降至 MB 级。

### Q: 如何添加新的 LLM 厂商？

1. Web 界面：侧边栏填写厂商名 + 域名 → 提交
2. API：`curl -X POST http://IP:8789/api/targets -d '{"vendor":"新厂商","domains":["api.example.com"]}'`
3. 同时在 `.env` 的 BPF 过滤器中加入新域名，重启服务

### Q: 下行流量显示为 0 或很小？

这是正常现象。部分原因：
- TCP 握手/TLS 探测等短连接（可用"隐藏空会话"过滤）
- BPF `host` 过滤器基于启动时 DNS 解析的 IP，如果 CDN IP 变化，部分响应包可能被漏抓
- LLM API 的请求（prompt）通常远大于响应（streaming token），尤其是代理模式
