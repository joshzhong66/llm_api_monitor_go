package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"llm_api_monitor/internal/config"
	"llm_api_monitor/internal/db"
	"llm_api_monitor/internal/parser"
)

// Server holds the HTTP API server state.
type Server struct {
	cfg     *config.Config
	store   *db.Store
	engine  *parser.Engine
	ipUsers *IPUserMap
	started time.Time
	mux     *http.ServeMux
}

// NewServer creates a new API server.
func NewServer(cfg *config.Config, store *db.Store, engine *parser.Engine) *Server {
	// IP-user map file: look in scripts/ directory relative to working dir
	ipMapPath := filepath.Join("scripts", "ip_user_map.json")
	s := &Server{
		cfg:     cfg,
		store:   store,
		engine:  engine,
		ipUsers: NewIPUserMap(ipMapPath),
		started: time.Now(),
		mux:     http.NewServeMux(),
	}
	s.registerRoutes()
	return s
}

// LookupIP returns the IPUserEntry for an IP.
func (s *Server) LookupIP(ip string) *IPUserEntry {
	return s.ipUsers.Lookup(ip)
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("/api/status", s.handleStatus)
	s.mux.HandleFunc("/api/logs", s.handleLogs)
	s.mux.HandleFunc("/api/summary", s.handleSummary)
	s.mux.HandleFunc("/api/request-logs", s.handleRequestLogs)
	s.mux.HandleFunc("/api/transport-events", s.handleTransportEvents)
	s.mux.HandleFunc("/api/targets", s.handleTargets)
	s.mux.HandleFunc("/api/jobs", s.handleJobs)
	s.mux.HandleFunc("/api/interface-traffic", s.handleInterfaceTraffic)

	// Static files
	staticDir := s.cfg.StaticDir
	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/" || path == "" {
			s.serveFile(w, filepath.Join(staticDir, "index.html"), "text/html; charset=utf-8")
			return
		}
		if path == "/app.js" {
			s.serveFile(w, filepath.Join(staticDir, "app.js"), "application/javascript; charset=utf-8")
			return
		}
		if path == "/styles.css" {
			s.serveFile(w, filepath.Join(staticDir, "styles.css"), "text/css; charset=utf-8")
			return
		}
		http.NotFound(w, r)
	})
}

// ListenAndServe starts the HTTP server.
func (s *Server) ListenAndServe() error {
	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
	log.Printf("[api] listening on %s", addr)
	srv := &http.Server{
		Addr:         addr,
		Handler:      s.mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	return srv.ListenAndServe()
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	uptime := time.Since(s.started).Truncate(time.Second).String()
	data := map[string]interface{}{
		"running":           true,
		"capture_running":   true,
		"parser_running":    true,
		"iface":             s.cfg.Iface,
		"window_seconds":    s.cfg.WindowSeconds,
		"bpf_filter":        s.cfg.BPFFilter,
		"pending_segments":  0,
		"retain_parsed_pcap": s.cfg.RetainParsedPcap,
		"last_job_id":       s.engine.LastJobID(),
		"active_sessions":   s.engine.ActiveSessions(),
		"uptime":            uptime,
		"started_at":        s.started.UTC().Add(8 * time.Hour).Format("2006-01-02 15:04:05"),
	}
	s.jsonResponse(w, map[string]interface{}{"ok": true, "data": data}, 200)
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	q := r.URL.Query()
	page := queryInt(q, "page", 1)
	pageSize := queryInt(q, "page_size", queryInt(q, "limit", 50))
	vendor := q.Get("vendor")
	search := q.Get("search")
	channelClass := q.Get("channel_class")
	timeWindow := queryInt(q, "time_window_minutes", 0)

	result, err := s.store.QueryLogs(vendor, search, channelClass, timeWindow, page, pageSize)
	if err != nil {
		log.Printf("[api] query logs error: %v", err)
		s.jsonResponse(w, map[string]interface{}{"ok": false, "error": err.Error()}, 500)
		return
	}

	// Enrich with token/cost estimates + IP user mapping
	if items, ok := result.Items.([]map[string]interface{}); ok {
		for _, item := range items {
			enrichUsageMetrics(item, s.cfg)
			s.ipUsers.EnrichRow(item)
		}
	}

	s.jsonResponse(w, map[string]interface{}{"ok": true, "data": result}, 200)
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	data, err := s.store.QuerySummary()
	if err != nil {
		log.Printf("[api] query summary error: %v", err)
		s.jsonResponse(w, map[string]interface{}{"ok": false, "error": err.Error()}, 500)
		return
	}

	// Enrich each vendor summary
	for _, item := range data {
		enrichUsageMetrics(item, s.cfg)
	}

	s.jsonResponse(w, map[string]interface{}{"ok": true, "data": data}, 200)
}

func (s *Server) handleRequestLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	q := r.URL.Query()
	page := queryInt(q, "page", 1)
	pageSize := queryInt(q, "page_size", queryInt(q, "limit", 50))
	vendor := q.Get("vendor")
	search := q.Get("search")
	channelClass := q.Get("channel_class")
	timeWindow := queryInt(q, "time_window_minutes", 0)

	result, err := s.store.QueryRequestLogs(vendor, search, channelClass, timeWindow, page, pageSize)
	if err != nil {
		log.Printf("[api] query request logs error: %v", err)
		s.jsonResponse(w, map[string]interface{}{"ok": false, "error": err.Error()}, 500)
		return
	}

	if items, ok := result.Items.([]map[string]interface{}); ok {
		for _, item := range items {
			enrichUsageMetrics(item, s.cfg)
			s.ipUsers.EnrichRow(item)
		}
	}

	s.jsonResponse(w, map[string]interface{}{"ok": true, "data": result}, 200)
}

func (s *Server) handleTransportEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	q := r.URL.Query()
	page := queryInt(q, "page", 1)
	pageSize := queryInt(q, "page_size", queryInt(q, "limit", 50))
	srcIP := q.Get("src_ip")
	protocol := q.Get("protocol")
	search := q.Get("search")
	timeWindow := queryInt(q, "time_window_minutes", 0)

	result, err := s.store.QueryTransportEvents(srcIP, protocol, search, timeWindow, page, pageSize)
	if err != nil {
		log.Printf("[api] query transport events error: %v", err)
		s.jsonResponse(w, map[string]interface{}{"ok": false, "error": err.Error()}, 500)
		return
	}
	s.jsonResponse(w, map[string]interface{}{"ok": true, "data": result}, 200)
}

func (s *Server) handleTargets(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		data, err := s.store.QueryAllTargetRules()
		if err != nil {
			s.jsonResponse(w, map[string]interface{}{"ok": false, "error": err.Error()}, 500)
			return
		}
		s.jsonResponse(w, map[string]interface{}{"ok": true, "data": data}, 200)

	case http.MethodPost:
		var body struct {
			Vendor    string   `json:"vendor"`
			Domains   []string `json:"domains"`
			Domain    string   `json:"domain"`
			MatchType string   `json:"match_type"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			s.jsonResponse(w, map[string]interface{}{"ok": false, "message": "invalid body"}, 400)
			return
		}
		if body.Vendor == "" {
			s.jsonResponse(w, map[string]interface{}{"ok": false, "message": "vendor is required"}, 400)
			return
		}
		domains := body.Domains
		if len(domains) == 0 && body.Domain != "" {
			domains = strings.Split(body.Domain, ",")
		}
		if len(domains) == 0 {
			s.jsonResponse(w, map[string]interface{}{"ok": false, "message": "domains is required"}, 400)
			return
		}
		matchType := body.MatchType
		if matchType == "" {
			matchType = "exact"
		}
		if err := s.store.AddTargetRules(body.Vendor, domains, matchType); err != nil {
			s.jsonResponse(w, map[string]interface{}{"ok": false, "message": err.Error()}, 500)
			return
		}
		// Reload matcher
		rules, _ := s.store.LoadTargetRules()
		s.engine.SetMatcher(parser.NewTargetMatcher(rules))

		data, _ := s.store.QueryAllTargetRules()
		s.jsonResponse(w, map[string]interface{}{"ok": true, "message": "added", "data": data}, 200)

	default:
		http.Error(w, "method not allowed", 405)
	}
}

func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	limit := queryInt(r.URL.Query(), "limit", 50)
	data, err := s.store.QueryJobs(limit)
	if err != nil {
		s.jsonResponse(w, map[string]interface{}{"ok": false, "error": err.Error()}, 500)
		return
	}
	s.jsonResponse(w, map[string]interface{}{"ok": true, "data": data}, 200)
}

func (s *Server) handleInterfaceTraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	// Placeholder: iftop integration
	s.jsonResponse(w, map[string]interface{}{"ok": true, "data": map[string]interface{}{
		"flows": []interface{}{},
		"iface": s.cfg.Iface,
	}}, 200)
}

func (s *Server) jsonResponse(w http.ResponseWriter, payload interface{}, status int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(payload)
}

func (s *Server) serveFile(w http.ResponseWriter, path, contentType string) {
	data, err := os.ReadFile(path)
	if err != nil {
		http.NotFound(w, nil)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Write(data)
}

func queryInt(q map[string][]string, key string, def int) int {
	if v, ok := q[key]; ok && len(v) > 0 {
		if n, err := strconv.Atoi(v[0]); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// enrichUsageMetrics adds token/cost estimates to a row (mirrors Python's enrich_usage_metrics).
func enrichUsageMetrics(row map[string]interface{}, cfg *config.Config) {
	uplinkBytes := toInt64(row["uplink_bytes"])
	downlinkBytes := toInt64(row["downlink_bytes"])
	vendor := toString(row["vendor"])
	domain := strings.ToLower(toString(row["domain"]))

	var inputTokens, outputTokens, cacheReadTokens, uncachedInputTokens int64
	var billableInputTokens float64
	var estimatedCostUSD float64
	var pricingModel, pricingSource, formula string
	var pricingInputPer1M, pricingOutputPer1M float64

	if vendor == "LLM API Proxy" || domain == "llm-api-proxy.hnfunny.com" {
		inputTokens = int64(float64(uplinkBytes) * cfg.ProxyInputTotalTokensPerUplinkByte)
		cacheReadTokens = int64(float64(uplinkBytes) * cfg.ProxyCacheReadTokensPerUplinkByte)
		uncachedInputTokens = int64(float64(uplinkBytes) * cfg.ProxyUncachedInputTokensPerUplinkByte)
		outputTokens = int64(float64(downlinkBytes) * cfg.ProxyOutputTokensPerDownlinkByte)
		billableInputTokens = float64(uncachedInputTokens) + float64(cacheReadTokens)*cfg.ProxyCacheReadBillingMultiplier
		estimatedCostUSD = billableInputTokens*cfg.ProxyInputTokenCostUSD + float64(outputTokens)*cfg.ProxyOutputTokenCostUSD
		pricingModel = "llm_proxy_empirical"
		pricingSource = "proxy empirical regression"
		pricingInputPer1M = cfg.ProxyInputTokenCostUSD * 1e6
		pricingOutputPer1M = cfg.ProxyOutputTokenCostUSD * 1e6
		formula = "llm_proxy_empirical_v1"
	} else {
		inputTokens = int64(float64(uplinkBytes) * 8.0 / cfg.InputTokenBits)
		outputTokens = int64(float64(downlinkBytes) * 8.0 / cfg.OutputTokenBits)
		uncachedInputTokens = inputTokens
		billableInputTokens = float64(inputTokens)

		// Try official pricing from XLSX
		pricingRule := SelectPricingRule(vendor, domain)
		if pricingRule != nil {
			pricingModel = pricingRule.Model
			pricingSource = pricingRule.SourceURL
			pricingInputPer1M = pricingRule.InputPer1M
			pricingOutputPer1M = pricingRule.OutputPer1M
			estimatedCostUSD = float64(inputTokens)*pricingInputPer1M/1e6 + float64(outputTokens)*pricingOutputPer1M/1e6
			formula = "official_pricing_xlsx_v1"
		} else {
			pricingModel = "default-generic"
			pricingSource = "legacy token formula converted from CNY"
			pricingInputPer1M = (cfg.InputTokenCostCNY / cfg.USDCNYRate) * 1e6
			pricingOutputPer1M = (cfg.OutputTokenCostCNY / cfg.USDCNYRate) * 1e6
			estimatedCostUSD = (float64(inputTokens)*cfg.InputTokenCostCNY + float64(outputTokens)*cfg.OutputTokenCostCNY) / cfg.USDCNYRate
			formula = "default_bits_usd_v1"
		}
	}

	row["input_tokens"] = inputTokens
	row["cache_read_tokens"] = cacheReadTokens
	row["uncached_input_tokens"] = uncachedInputTokens
	row["billable_input_tokens"] = billableInputTokens
	row["output_tokens"] = outputTokens
	row["total_tokens"] = inputTokens + outputTokens
	row["estimation_formula"] = formula
	row["pricing_model"] = pricingModel
	row["pricing_source"] = pricingSource
	row["pricing_input_per_1m_usd"] = pricingInputPer1M
	row["pricing_output_per_1m_usd"] = pricingOutputPer1M
	row["estimated_cost_usd"] = estimatedCostUSD
	row["estimated_cost_cny"] = estimatedCostUSD * cfg.USDCNYRate
	row["estimated_cost_currency"] = "USD"
	row["exchange_rate_usd_cny"] = cfg.USDCNYRate

	// Channel type classification
	channelType := "api"
	if cfg.WebDomainHints[domain] {
		channelType = "web"
	}
	note := toString(row["note"])
	if strings.Contains(strings.ToLower(toString(row["protocol"])), "udp") || strings.Contains(note, "quic") {
		if channelType == "api" {
			channelType = "api_quic"
		} else {
			channelType = "web_quic"
		}
	}
	row["channel_type"] = channelType
}

func toInt64(v interface{}) int64 {
	switch val := v.(type) {
	case int64:
		return val
	case int:
		return int64(val)
	case float64:
		return int64(val)
	case string:
		n, _ := strconv.ParseInt(val, 10, 64)
		return n
	}
	return 0
}

func toString(v interface{}) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}
