# LLM API Monitor (Go)

LLM API Monitor 的 Go 语言重构版本，用于监控服务器上的 LLM API 流量（OpenAI、Anthropic、Google、DeepSeek 等）。

通过抓包分析 HTTPS 流量的元数据（不解密内容），实时统计各厂商 API 的调用次数、流量、预估 Token 数和费用。

## 相比 Python 版本的改进

| 维度 | Python 2.7 版 | Go 版 |
|------|--------------|-------|
| pcap 解析 | 调用 tcpdump 子进程（每个文件 2 次） | gopacket 原生解析（单次遍历） |
| 并发模型 | 多进程 + GIL 限制 | goroutine 原生并发 |
| 数据传递 | pickle 序列化 → 文件系统 spool | Go channel 内存传递 |
| DB 连接 | 每次新建 TCP 连接 | 内置连接池（sql.DB） |
| 部署 | 需要 Python 环境 + vendor 依赖 | 单二进制（~11MB） |
| 代码量 | 4,151 行 | 2,973 行 |

## 快速开始

```bash
# 1. 安装依赖
yum install -y libpcap-devel   # CentOS/RHEL
# apt install -y libpcap-dev   # Ubuntu/Debian

# 2. 编译
bash build.sh

# 3. 修改配置
vim .env

# 4. 运行
./llm-api-monitor
```

## 配置说明

通过 `.env` 文件配置，主要参数：

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `LLM_MONITOR_PORT` | 8789 | HTTP 服务端口 |
| `LLM_MONITOR_IFACE` | enp1s0f3 | 抓包网卡 |
| `LLM_MONITOR_WINDOW_SECONDS` | 30 | pcap 轮转窗口（秒） |
| `LLM_MONITOR_BPF` | port 443 | BPF 过滤器 |
| `LLM_MONITOR_REALTIME_WORKERS` | 8 | 解析 worker 数量 |
| `LLM_MONITOR_AUTOSTART` | 0 | 是否自动启动抓包 |
| `LLM_MONITOR_MYSQL_*` | - | MySQL 连接配置 |
| `LLM_MONITOR_REDIS_*` | - | Redis 连接配置 |

## API 接口

完全兼容 Python 版本的前端：

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
.
├── cmd/monitor/main.go          # 入口
├── internal/
│   ├── api/server.go            # HTTP API 服务
│   ├── capture/daemon.go        # tcpdump 抓包管理
│   ├── config/config.go         # 配置加载
│   ├── db/store.go              # MySQL + Redis 数据层
│   ├── model/model.go           # 数据模型
│   ├── parser/
│   │   ├── engine.go            # gopacket 解析引擎
│   │   └── matcher.go           # 域名匹配器
│   └── writer/daemon.go         # Worker Pool + 写入守护
├── static/                      # 前端文件
├── systemd/                     # systemd 服务文件
├── .env                         # 配置文件
└── build.sh                     # 编译脚本
```

## systemd 部署

```bash
cp systemd/llm-api-monitor-go.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable llm-api-monitor-go
systemctl start llm-api-monitor-go
```

## 支持的 LLM 厂商

OpenAI / ChatGPT, Claude / Anthropic, Gemini / Google AI, DeepSeek, Kimi / Moonshot,
百度 / 千帆, 腾讯 / 混元, 千问 / 通义, 豆包 / 火山引擎, MiniMax, 智谱,
Mistral, Cohere, Grok / xAI, Amazon Bedrock, Azure OpenAI 等。
