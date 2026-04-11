# LLM API Monitor Go v0.1.0

LLM API Monitor 从 Python 2.7 完全重构为 Go 语言版本。

## 项目背景

原 Python 2.7 版本在高流量环境下存在严重性能瓶颈：
- 单个 pcap 文件可达 2 GB（10 秒窗口），解析耗时数分钟
- 12 核 CPU 仅利用 25%（GIL + 多进程模型限制）
- 每个 pcap 需要调用 2 次 tcpdump 子进程
- 无数据库连接池，每次操作新建 TCP 连接
- WriterDaemon 单实例瓶颈
- Pickle 序列化 + fsync 磁盘 I/O 开销

## 核心改进

### 架构层面
| 维度 | Python 2.7 版 | Go 版 | 提升 |
|------|--------------|-------|------|
| pcap 解析 | 调用 tcpdump 子进程（每个文件 2 次） | gopacket 原生解析（单次遍历） | 60x |
| 并发模型 | 多进程 + GIL 限制 | goroutine 原生并发（8 worker） | 全核利用 |
| 数据传递 | pickle 序列化 → 文件系统 spool | Go channel 内存传递 | 消除 I/O |
| DB 连接 | 每次新建 TCP 连接 | 内置连接池（sql.DB，20 连接） | 连接复用 |
| 部署方式 | 需要 Python 环境 + vendor 依赖 | 单二进制（~11MB） | 零依赖 |
| 代码量 | 4,151 行 | 2,973 行 | 28% 精简 |

### 性能预估

| 指标 | Python 2 (原始) | Go 版 (预估) | 提升倍数 |
|------|----------------|-------------|----------|
| pcap 解析（单 worker） | 30-300s/文件 | 0.5-5s/文件 | 60x |
| 解析吞吐（8 worker） | ~2000/小时 | ~50000+/小时 | 25x |
| 内存占用（per worker） | 60-100 MB | 5-15 MB | 6-10x |
| DB 写入 | 单条逐写 | 批量事务写入 | 10-30x |
| HTTP 查询响应 | 200-500ms | 10-50ms | 10x |
| 启动时间 | 5-10s | <1s | 10x |

## 已实现功能

- [x] gopacket 原生 pcap 解析（含 TLS ClientHello SNI 提取）
- [x] TCP session 跟踪与管理
- [x] 域名→厂商匹配（exact + wildcard，45 条内置规则）
- [x] IP hint 缓存（DNS 反查 + TTL 缓存）
- [x] MySQL 连接池 + 全表 CRUD
- [x] Redis 连接池 + 缓存
- [x] 完全兼容 Python 版前端的 HTTP API
- [x] goroutine Worker Pool（可配置数量）
- [x] Writer Daemon（channel 通信）
- [x] Capture Daemon（tcpdump 管理）
- [x] Token/费用预估（兼容 Python 版算法）
- [x] 45 个 LLM 厂商域名内置支持
- [x] systemd 服务文件
- [x] .env 配置兼容

## 支持的 LLM 厂商

OpenAI / ChatGPT, Claude / Anthropic, Gemini / Google AI, DeepSeek,
Kimi / Moonshot, 百度 / 千帆, 腾讯 / 混元, 千问 / 通义, 豆包 / 火山引擎,
MiniMax, 智谱, Mistral, Cohere, Grok / xAI, Amazon Bedrock, Azure OpenAI

## API 接口

| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/status` | GET | 系统状态 |
| `/api/logs` | GET | 会话日志（分页） |
| `/api/summary` | GET | 厂商汇总 |
| `/api/request-logs` | GET | 请求明细（分页） |
| `/api/transport-events` | GET | 传输事件（分页） |
| `/api/targets` | GET/POST | 域名规则管理 |
| `/api/jobs` | GET | 抓包任务列表 |

## 项目结构

```
├── cmd/monitor/main.go          # 入口（176 行）
├── internal/
│   ├── api/server.go            # HTTP API（412 行）
│   ├── capture/daemon.go        # 抓包管理（243 行）
│   ├── config/config.go         # 配置加载（204 行）
│   ├── db/store.go              # 数据层（789 行）
│   ├── model/model.go           # 数据模型（185 行）
│   ├── parser/engine.go         # 解析引擎（613 行）
│   ├── parser/matcher.go        # 域名匹配（120 行）
│   └── writer/daemon.go         # Worker + Writer（231 行）
├── static/                      # 前端文件（复用 Python 版）
├── systemd/                     # systemd 服务
├── .env                         # 配置
└── build.sh                     # 编译脚本
```

## 技术栈

| 功能 | 库 |
|------|-----|
| pcap 解析 | google/gopacket |
| MySQL | go-sql-driver/mysql（内置连接池） |
| Redis | redis/go-redis/v9 |
| 配置 | joho/godotenv |
| HTTP | net/http (标准库) |

## 快速开始

```bash
# 安装 libpcap 开发库
yum install -y libpcap-devel

# 编译
bash build.sh

# 修改配置
vim .env

# 运行
./llm-api-monitor
```

## 验证结果（2026-04-11 实测）

```
$ ./llm-api-monitor
LLM API Monitor (Go) starting...
config: iface=enp1s0f3 window=30s workers=8 bpf="port 443 and ..."
config: mysql=127.0.0.1:3306/llm_api_monitor redis=127.0.0.1:6379
loaded 45 target rules (40 exact, 5 wildcard)
[parser] restored 345 open sessions
[parser] rebuilt IP hint cache: 118 IPs from 45 rules
all components started, serving on 0.0.0.0:8789
[api] listening on 0.0.0.0:8789
[workers] starting 8 parser workers
[writer] started
```

- MySQL 连接成功，加载 45 条 target rules
- 恢复 345 个 open sessions
- IP hint 缓存 118 个地址
- 8 个 parser worker + 1 个 writer 全部启动
- HTTP API 正常返回 JSON 数据
