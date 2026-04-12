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

## 计费与估算规则

当前版本的费用统计仍然基于流量元数据估算，不解密 HTTPS 内容。对于代理域名流量，项目使用专门校准过的流量转 Token 公式；对于官方厂商域名，项目按默认模型从 `official_model_pricing_usd.xlsx` 中选择价格规则。

### 代理域名流量转 Token 公式

适用对象：

- `LLM API Proxy`
- 其他被识别为统一代理转发的代理域名流量

当前默认公式：

```text
input_total_tokens    = uplink_bytes   × 0.203806889514
cache_read_tokens     = uplink_bytes   × 0.168743644119
uncached_input_tokens = uplink_bytes   × 0.035063245394
output_tokens         = downlink_bytes × 0.004718444333
```

当前默认价格：

```text
input_token_cost_usd  = 0.000003138268266
cache_multiplier      = 1.0
output_token_cost_usd = 0.000018829609595
```

金额计算方式：

```text
billable_input_tokens = uncached_input_tokens + cache_read_tokens × 1.0
estimated_cost_usd    = billable_input_tokens × 0.000003138268266
                      + output_tokens × 0.000018829609595
```

说明：

- 当前缓存按 `1.0` 计费，也就是缓存 Token 按普通输入 Token 全价计算。
- 这组代理常量定义在 `internal/config/config.go` 的 `Proxy*` 默认值中。

### 官方厂商域名的默认模型映射

项目会先识别流量所属厂商，再按下面的默认模型去价格表中查找单价：

| 厂商分组 | 默认模型 |
|------|------|
| `ChatGPT / OpenAI` | `gpt-5.4` |
| `Azure OpenAI` | `gpt-5.4` |
| `Claude / Anthropic` | `claude-opus-4-6` |
| `Gemini / Google AI` | `gemini-3.1-pro-preview` |
| `MiniMax` | `MiniMax-M2.7` |
| `智谱` | `glm-5` |
| `千问 / 通义` | `qwen3.5-plus` |

说明：

- 这组映射定义在 `internal/api/pricing.go` 的 `DefaultPricingSelections`。
- 最终价格以项目内 `official_model_pricing_usd.xlsx` 命中的行记录为准。
- 如果某个厂商命中了多个阶梯价格，当前实现会优先取输入单价更低的一条。


#### 各模型实际定价
  五、各模型实际定价标准                                                                                                                                                                                
                                                                                                                                                                                                        
  下面按你给的常用模型价格，直接列出这次用于比较的“新默认模型计费标准”。                                                                                                                                
                                                                                                                                                                                                        
  ┌──────────────────────────────┬─────────────────────┬─────────────────────┐                                                                                                                          
  │            模型              │ 输入价 / M          │ 输出价 / M          │                                                                                                                          
  ├──────────────────────────────┼─────────────────────┼─────────────────────┤                                                                                                                          
  │ deepseek-r1                  │ $0.7600             │ $1.1552             │                                                                                                                          
  ├──────────────────────────────┼─────────────────────┼─────────────────────┤                                                                                                                          
  │ glm-5                        │ $0.4644             │ $2.0897             │                                                                                                                          
  ├──────────────────────────────┼─────────────────────┼─────────────────────┤                                                                                                                          
  │ kimi/kimi-k2.5               │ $0.7600             │ $1.5200             │                                                                                                                          
  ├──────────────────────────────┼─────────────────────┼─────────────────────┤                                                                                                                          
  │ MiniMax/MiniMax-M2.7         │ $0.4000             │ $0.3200             │                                                                                                                          
  ├──────────────────────────────┼─────────────────────┼─────────────────────┤                                                                                                                          
  │ qwen3.5-plus                 │ $0.2340             │ $0.1638             │                                                                                                                          
  ├──────────────────────────────┼─────────────────────┼─────────────────────┤                                                                                                                          
  │ gpt-5.4                      │ $2.5000             │ $15.0000            │                                                                                                                          
  ├──────────────────────────────┼─────────────────────┼─────────────────────┤                                                                                                                          
  │ claude-opus-4-6              │ $5.5000             │ $27.5000            │                                                                                                                          
  ├──────────────────────────────┼─────────────────────┼─────────────────────┤                                                                                                                          
  │ gemini-3.1-pro-preview       │ $2.0000             │ $12.0000            │                                                                                                                          
  └──────────────────────────────┴─────────────────────┴─────────────────────┘                                                                                                                          
                                                                                  


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

```text
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
