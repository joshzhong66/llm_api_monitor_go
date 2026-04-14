package config

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Host          string
	Port          int
	Iface         string
	WindowSeconds int
	BPFFilter     string
	Snaplen       int
	Autostart     bool

	DataDir    string
	LogDir     string
	CaptureDir string
	StaticDir  string

	RetainParsedPcap bool
	MaxPendingSegs   int

	RealtimeWorkers         int
	BackfillWorkers         int
	BackfillPauseOnRealtime bool

	MySQL MySQLConfig
	Redis RedisConfig

	QueuePollSeconds   float64
	IdleSessionSeconds int
	TaskPollSeconds    float64
	ResultPollSeconds  float64

	SummaryCacheTTL    time.Duration
	TargetsCacheTTL    time.Duration
	StatusCacheTTL     time.Duration
	IPHintsCacheTTL    time.Duration
	IftopCacheTTL      time.Duration
	IftopSampleSeconds int
	IftopMaxFlows      int
	IftopBinary        string

	InputTokenBits     float64
	OutputTokenBits    float64
	InputTokenCostCNY  float64
	OutputTokenCostCNY float64
	USDCNYRate         float64

	ProxyInputTotalTokensPerUplinkByte    float64
	ProxyCacheReadTokensPerUplinkByte     float64
	ProxyUncachedInputTokensPerUplinkByte float64
	ProxyOutputTokensPerDownlinkByte      float64
	ProxyInputTokenCostUSD                float64
	ProxyCacheReadBillingMultiplier       float64
	ProxyOutputTokenCostUSD               float64

	PricingXLSXPath string

	WebDomainHints map[string]bool
}

type MySQLConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	Database string
	Charset  string
	MaxOpen  int
	MaxIdle  int
}

type RedisConfig struct {
	Host     string
	Port     int
	Password string
	DB       int
	Enabled  bool
}

func Load(envPath string) *Config {
	_ = godotenv.Load(envPath)

	c := &Config{
		Host:          envStr("LLM_MONITOR_HOST", "0.0.0.0"),
		Port:          envInt("LLM_MONITOR_PORT", 8787),
		Iface:         envStr("LLM_MONITOR_IFACE", "enp1s0f3"),
		WindowSeconds: envInt("LLM_MONITOR_WINDOW_SECONDS", 10),
		BPFFilter:     envStr("LLM_MONITOR_BPF", "port 443"),
		Snaplen:       envInt("LLM_MONITOR_SNAPLEN", 0),
		Autostart:     envStr("LLM_MONITOR_AUTOSTART", "1") == "1",

		DataDir:    envStr("LLM_MONITOR_DATA_DIR", "data"),
		LogDir:     envStr("LLM_MONITOR_LOG_DIR", "logs"),
		CaptureDir: envStr("LLM_MONITOR_CAPTURE_DIR", ""),
		StaticDir:  envStr("LLM_MONITOR_STATIC_DIR", "static"),

		RetainParsedPcap: envStr("LLM_MONITOR_RETAIN_PARSED_PCAP", "1") == "1",
		MaxPendingSegs:   envInt("LLM_MONITOR_MAX_PENDING_SEGMENTS", 0),

		RealtimeWorkers:         envInt("LLM_MONITOR_REALTIME_WORKERS", 8),
		BackfillWorkers:         envInt("LLM_MONITOR_BACKFILL_WORKERS", 2),
		BackfillPauseOnRealtime: envStr("LLM_MONITOR_BACKFILL_PAUSE_ON_REALTIME", "1") == "1",

		MySQL: MySQLConfig{
			Host:     envStr("LLM_MONITOR_MYSQL_HOST", "127.0.0.1"),
			Port:     envInt("LLM_MONITOR_MYSQL_PORT", 3306),
			User:     envStr("LLM_MONITOR_MYSQL_USER", "root"),
			Password: envStr("LLM_MONITOR_MYSQL_PASSWORD", "123456"),
			Database: envStr("LLM_MONITOR_MYSQL_DATABASE", "llm_api_monitor"),
			Charset:  "utf8mb4",
			MaxOpen:  envInt("LLM_MONITOR_MYSQL_MAX_OPEN", 20),
			MaxIdle:  envInt("LLM_MONITOR_MYSQL_MAX_IDLE", 10),
		},
		Redis: RedisConfig{
			Host:     envStr("LLM_MONITOR_REDIS_HOST", "127.0.0.1"),
			Port:     envInt("LLM_MONITOR_REDIS_PORT", 6379),
			Password: envStr("LLM_MONITOR_REDIS_PASSWORD", "123456"),
			DB:       envInt("LLM_MONITOR_REDIS_DB", 0),
			Enabled:  envStr("LLM_MONITOR_REDIS_ENABLED", "1") == "1",
		},

		QueuePollSeconds:   envFloat("LLM_MONITOR_QUEUE_POLL_SECONDS", 1),
		IdleSessionSeconds: envInt("LLM_MONITOR_IDLE_SESSION_SECONDS", 300),
		TaskPollSeconds:    envFloat("LLM_MONITOR_TASK_POLL_SECONDS", 1),
		ResultPollSeconds:  envFloat("LLM_MONITOR_RESULT_POLL_SECONDS", 1),

		SummaryCacheTTL:    time.Duration(envFloat("LLM_MONITOR_SUMMARY_CACHE_TTL_SECONDS", 300) * float64(time.Second)),
		TargetsCacheTTL:    time.Duration(envFloat("LLM_MONITOR_TARGETS_CACHE_TTL_SECONDS", 15) * float64(time.Second)),
		StatusCacheTTL:     time.Duration(envFloat("LLM_MONITOR_STATUS_CACHE_TTL_SECONDS", 2) * float64(time.Second)),
		IPHintsCacheTTL:    time.Duration(envFloat("LLM_MONITOR_TARGET_IP_HINTS_CACHE_TTL_SECONDS", 3600) * float64(time.Second)),
		IftopCacheTTL:      time.Duration(envFloat("LLM_MONITOR_IFTOP_CACHE_TTL_SECONDS", 2) * float64(time.Second)),
		IftopSampleSeconds: envInt("LLM_MONITOR_IFTOP_SAMPLE_SECONDS", 2),
		IftopMaxFlows:      envInt("LLM_MONITOR_IFTOP_MAX_FLOWS", 20),
		IftopBinary:        envStr("LLM_MONITOR_IFTOP_BIN", "/usr/sbin/iftop"),

		InputTokenBits:     611.23,
		OutputTokenBits:    222.26,
		InputTokenCostCNY:  0.000002,
		OutputTokenCostCNY: 0.000003,
		USDCNYRate:         envFloat("LLM_MONITOR_USD_CNY_RATE", 6.89),

		ProxyInputTotalTokensPerUplinkByte:    envFloat("LLM_PROXY_INPUT_TOTAL_TOKENS_PER_UPLINK_BYTE", 0.203806889514),
		ProxyCacheReadTokensPerUplinkByte:     envFloat("LLM_PROXY_CACHE_READ_TOKENS_PER_UPLINK_BYTE", 0.168743644119),
		ProxyUncachedInputTokensPerUplinkByte: envFloat("LLM_PROXY_UNCACHED_INPUT_TOKENS_PER_UPLINK_BYTE", 0.035063245394),
		ProxyOutputTokensPerDownlinkByte:      envFloat("LLM_PROXY_OUTPUT_TOKENS_PER_DOWNLINK_BYTE", 0.004718444333),
		ProxyInputTokenCostUSD:                envFloat("LLM_PROXY_INPUT_TOKEN_COST_USD", 0.000003138268266),
		ProxyCacheReadBillingMultiplier:       envFloat("LLM_PROXY_CACHE_READ_BILLING_MULTIPLIER", 0.45),
		ProxyOutputTokenCostUSD:               envFloat("LLM_PROXY_OUTPUT_TOKEN_COST_USD", 0.000018829609595),

		PricingXLSXPath: envStr("LLM_MONITOR_PRICING_XLSX", "official_model_pricing_usd.xlsx"),

		WebDomainHints: map[string]bool{
			"claude.ai":             true,
			"gemini.google.com":     true,
			"aistudio.google.com":   true,
			"kimi.com":              true,
			"kimi.moonshot.cn":      true,
			"platform.deepseek.com": true,
			"qwen.ai":               true,
			"tongyi.aliyun.com":     true,
			"grok.com":              true,
		},
	}

	if c.CaptureDir == "" {
		c.CaptureDir = c.DataDir + "/captures"
	}

	return c
}

func envStr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return def
}

func envFloat(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
			return f
		}
	}
	return def
}
