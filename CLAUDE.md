# CLAUDE.md

## 项目概览

LLM API Monitor (Go) — 企业级 LLM API 流量监控系统。通过网络抓包（gopacket 原生解析 pcap）识别 TLS ClientHello SNI，实时统计 18 个厂商的 API 调用次数、流量、Token 和费用。**不解密 HTTPS 内容**。

详细的功能列表、架构图、部署步骤、配置说明见 [README.md](README.md)。

## 技术栈

| 层 | 选型 | 说明 |
|---|---|---|
| 语言 | Go 1.21 | 单二进制，编译后 ~11MB |
| 抓包 | gopacket + libpcap | 替代 Python 版 tcpdump 子进程 |
| HTTP | `net/http` 标准库 | 无框架 |
| 数据库 | MySQL 8.0 | `database/sql` + `go-sql-driver/mysql` |
| 缓存 | Redis 5.0+ | `go-redis/v9`，可选，优雅降级 |
| LDAP | `go-ldap/ldap/v3` | AD 域控查询，IP → 用户映射 |
| 配置 | `joho/godotenv` | `.env` 文件，`LLM_MONITOR_` 前缀 |
| 前端 | 原生 JS + HTML + CSS | 单文件 SPA，无框架无构建工具 |
| 部署 | systemd | `systemctl start llm-api-monitor-go` |

Go 代理设置：`GOPROXY=https://goproxy.cn,direct`（中国镜像）。

## 快速命令

```bash
# 编译
bash build.sh
# 或手动
export PATH=$PATH:/usr/local/go/bin
go build -o llm-api-monitor ./cmd/monitor/

# 运行（前台）
./llm-api-monitor

# systemd 管理
systemctl start|stop|restart|status llm-api-monitor-go

# 查看日志
journalctl -u llm-api-monitor-go -f

# 管道进度
bash scripts/pipeline_status.sh

# 更新 IP-用户映射
LDAP_BIND_PASSWORD='...' bash scripts/collect_ip_users.sh
```

## 项目结构

```
cmd/monitor/main.go          # 入口，组件组装和启动顺序
cmd/ldap_lookup/main.go       # LDAP 查询 CLI 工具
internal/
  api/server.go               # HTTP 路由 + 处理函数（10 个端点）
  api/pricing.go              # XLSX 价格表解析（无外部依赖）
  api/ipuser.go               # IP-用户映射热加载（5 分钟 TTL）
  capture/daemon.go           # tcpdump 管理，pcap 文件发现和分发
  config/config.go            # .env 配置加载
  db/store.go                 # MySQL CRUD，批量 INSERT，动态 WHERE
  model/model.go              # 数据模型定义
  parser/engine.go            # gopacket 解析，SNI 提取，Session 跟踪
  parser/matcher.go           # 域名→厂商匹配（exact + wildcard）
  writer/daemon.go            # Writer Daemon，Worker Pool，Backfill
static/                       # 前端 SPA（app.js / index.html / styles.css）
scripts/                      # 运维脚本（LDAP、管道监控）
```

## 架构关键决策

以下是项目演进中做出的重要技术决策和原因。

### 1. gopacket 单次遍历替代 tcpdump 文本解析

**决策**：用 gopacket 原生解析 pcap，一次遍历同时提取 packet events + TLS SNI。
**原因**：Python 版用 tcpdump 子进程解析再正则提取，性能瓶颈严重（单核串行）。gopacket 直接操作二进制包头，8 worker 并行处理。

### 2. Backfill 绕过 resultCh 直接调 processResult

**决策**：Backfill（历史数据重解析）不走 resultCh 通道，直接调用 `writer.processResult`。
**原因**：早期 backfill 和实时共用 resultCh（缓冲 500），backfill 量大时挤占实时通道，导致 21 分钟延迟。分离后实时延迟恢复到 <60 秒。

### 3. writeMu 串行化 + 并行子写入

**决策**：`processResult` 用 `writeMu` 互斥锁串行化入口，内部 UpsertSessions 完成后并行写 request_logs 和 transport_events。
**原因**：无锁并发写导致 MySQL 死锁。串行化入口消除了锁竞争，内部并行保持了吞吐量。

### 4. 批量多行 INSERT

**决策**：api_logs 批量 50 行、request_logs 批量 100 行、transport_events 批量 200 行的多行 VALUES INSERT。
**原因**：逐行 INSERT 时 SQL 往返是瓶颈。批量后写入速度提升 50-200 倍。

### 5. 60 秒 pcap 轮转窗口

**决策**：从 30 秒改为 60 秒。
**原因**：30 秒窗口产生过多 job（每分钟 2 个），job 调度和文件 I/O 开销大。60 秒减半 job 数量，单 job 数据量适中，解析效率更高。

### 6. 写入失败重置为 queued 而非 failed

**决策**：`UpsertSessions` 失败时将 job 状态从 merging 重置为 queued，而不是标记为 failed。
**原因**：早期有 335 个 job 因临时 MySQL 超时被标记为 failed 而永久丢失。重置为 queued 允许自动重试。

### 7. 时间戳用 VARCHAR 存储 UTC+8 格式化字符串

**决策**：所有时间戳用 `VARCHAR(19)` 存储 `"2006-01-02 15:04:05"` 格式的 UTC+8 时间。
**原因**：与 Python 版数据库兼容，避免迁移时时区转换问题。前端直接显示无需转换。

### 8. WebDomainHints + WebMixedDomains 域名分类

**决策**：`channel_class=web` 包含 WebDomainHints + WebMixedDomains，`channel_class=api` 仅排除 WebDomainHints。
**原因**：部分域名（如 `generativelanguage.googleapis.com`）同时承载 API 和网页流量，不能简单二分。WebMixedDomains 在两个视图中都出现。

### 9. page_size 服务端上限 10000

**决策**：所有分页查询 handler 中 `pageSize` 上限 10000。
**原因**：前端"显示全部"可能触发无限返回，导致 MySQL 全表扫描 + 巨量 JSON 序列化。上限保护服务端稳定性。

## 代码风格约定

### Go 后端

- **日志格式**：`log.Printf("[component] message: %v", val)` — 组件标签用方括号，如 `[capture]`、`[writer]`、`[parser]`、`[api]`、`[backfill]`
- **错误处理**：`fmt.Errorf("context: %w", err)` 包装返回；启动失败用 `log.Fatalf`；运行时错误 log + 继续
- **Import 顺序**：标准库 → 空行 → 第三方库 → 空行 → 内部包（`llm_api_monitor/internal/...`）
- **命名**：文件 `snake_case.go`，包名单词小写，结构体方法接收者单字母（`s *Store`、`e *Engine`）
- **SQL**：所有查询用 `?` 占位符参数化，禁止字符串拼接值。动态 WHERE 用 `clauses []string` + `args []interface{}` 模式构建
- **配置**：`.env` 文件，变量名 `LLM_MONITOR_SCREAMING_SNAKE_CASE`，用 `envStr/envInt/envFloat` 读取带默认值
- **并发**：goroutine + channel 通信，共享状态用 `sync.Mutex`/`sync.RWMutex`
- **Commit 消息**：`type: 中文描述`，type 用 `feat`/`fix`/`perf`/`docs`

### 前端

- 原生 JS，**无框架**、无 npm、无构建工具
- 全局 `state` 对象管理状态
- DOM 操作用 `document.getElementById` + `innerHTML`
- API 调用用 `fetch()` + 10 秒超时
- 中文 UI 文本
- 函数命名 `camelCase`，常量 `SCREAMING_SNAKE_CASE`

## 数据库注意事项

- Schema 通过 `store.InitDB()` 里的 `CREATE TABLE IF NOT EXISTS` 管理，**无迁移工具**
- 新增列用 `ALTER TABLE ... ADD COLUMN` 手动执行或在 InitDB 中追加
- 连接池：MaxOpen=20，MaxIdle=10，ConnMaxLifetime=5m
- MySQL 容器启动用 4G buffer pool，启动后在线扩展到 8G（CentOS 7 内核 3.10 大内存初始化慢）
- `interpolateParams=true` 用于连接字符串
- 批量 INSERT 用 `strings.Builder` 拼装多行 VALUES + `ON DUPLICATE KEY UPDATE`

## 运行环境

- CentOS 7 / Linux 3.10（生产环境）
- 12 核 i7-8700，62GB RAM
- 需要 root 权限（tcpdump 抓包）
- 依赖系统包：`libpcap-devel`
- MySQL 8.0 Docker 容器（数据目录 `/data/mysql_llm_monitor`）
- pcap 文件目录：`/data/llm_api_monitor/captures/`

## Git 提交规范

### Commit 消息格式

```
type: 中文描述

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
```

**type 前缀**（必选）：

| type | 用途 | 示例 |
|------|------|------|
| `feat` | 新功能 | `feat: 前端新增"隐藏空会话"过滤开关` |
| `fix` | Bug 修复 | `fix: 回退 GPT 的破坏性改动 + 正确实现网页流量域名补全` |
| `perf` | 性能优化 | `perf: 批量 INSERT 优化 + merging 失败重试` |
| `docs` | 文档变更 | `docs: 重写 README.md 完整部署运维文档` |
| `refactor` | 重构（不改功能） | `refactor: 提取 applyDateRange 公共过滤函数` |
| `style` | 代码格式 | `style: 统一 import 分组顺序` |
| `chore` | 构建/工具/依赖 | `chore: 升级 go-redis 到 v9.7.0` |

### 提交时机

以下情况应该提交代码：

- **新功能完成**：前后端联调通过，服务重启验证正常
- **Bug 修复**：问题已复现、修复、验证
- **性能优化**：改动已上线，延迟/吞吐指标确认改善
- **文档更新**：README.md、CLAUDE.md 等重要文档变更
- **配置变更**：`.env` 模板、systemd 服务文件、BPF 过滤器等

### 提交原则

- 一个 commit 对应一个完整的改动单元，不要把不相关的改动混在一起
- 涉及前后端联动的功能改动放在同一个 commit（如 API 新增参数 + 前端对接）
- 编译通过 + 服务正常启动后再提交，不提交有编译错误的代码
- 不提交敏感信息（`.env` 中的真实密码、`scripts/.ldap_env`）
- 发版（GitHub Release）在重大功能里程碑完成后进行，用 `create_release.sh`

## 注意事项

- **不要手动删除 MySQL InnoDB redo log 文件**（`ib_logfile*`），会导致数据库崩溃，需要 `innodb_force_recovery` 恢复
- **BPF 过滤器中的域名在 tcpdump 启动时 DNS 解析为 IP**，CDN IP 变化可能导致部分响应包漏抓
- 修改 `.env` 后需要 `systemctl restart llm-api-monitor-go` 生效
- `scripts/ip_user_map.json` 由 Go 服务每 5 分钟热加载，无需重启
- 解析后的 pcap 默认自动删除（`RETAIN_PARSED_PCAP=0`），节省磁盘
- Grok 使用 QUIC/HTTP3（UDP/443），目前只记录到 transport_events，不进入 api_logs
