package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"llm_api_monitor/internal/config"
	"llm_api_monitor/internal/db"
	"llm_api_monitor/internal/model"
	"llm_api_monitor/internal/parser"
)

// Server holds the HTTP API server state.
type Server struct {
	cfg     *config.Config
	store   *db.Store
	engine  *parser.Engine
	ipUsers *IPUserMap
	started      time.Time
	mux          *http.ServeMux
	summaryCache struct {
		mu      sync.Mutex
		data    []map[string]interface{}
		updated time.Time
	}
}

const maxPageSize = 10000

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
	s.mux.HandleFunc("/api/pipeline", s.handlePipeline)
	s.mux.HandleFunc("/api/quic-observations", s.handleQUICObservations)
	s.mux.HandleFunc("/api/interface-traffic", s.handleInterfaceTraffic)
	s.mux.HandleFunc("/api/export-csv", s.handleExportCSV)
	s.mux.HandleFunc("/api/user-summary", s.handleUserSummary)
	s.mux.HandleFunc("/api/user-total", s.handleUserTotal)

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
		"running":            true,
		"capture_running":    true,
		"parser_running":     true,
		"iface":              s.cfg.Iface,
		"window_seconds":     s.cfg.WindowSeconds,
		"bpf_filter":         s.cfg.BPFFilter,
		"pending_segments":   0,
		"retain_parsed_pcap": s.cfg.RetainParsedPcap,
		"last_job_id":        s.engine.LastJobID(),
		"active_sessions":    s.engine.ActiveSessions(),
		"uptime":             uptime,
		"started_at":         s.started.UTC().Add(8 * time.Hour).Format("2006-01-02 15:04:05"),
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
	if pageSize > maxPageSize {
		pageSize = maxPageSize
	}
	vendor := q.Get("vendor")
	search := q.Get("search")
	channelClass := q.Get("channel_class")
	timeWindow := queryInt(q, "time_window_minutes", 0)
	minBytes := queryInt(q, "min_bytes", 0)
	startDate := q.Get("start_date")
	endDate := q.Get("end_date")

	result, err := s.store.QueryLogs(vendor, search, channelClass, timeWindow, page, pageSize, minBytes, startDate, endDate)
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
	q := r.URL.Query()
	startDate := q.Get("start_date")
	endDate := q.Get("end_date")

	// Use in-memory cache for default (no date range) queries
	if startDate == "" && endDate == "" {
		s.summaryCache.mu.Lock()
		if s.summaryCache.data != nil && time.Since(s.summaryCache.updated) < s.cfg.SummaryCacheTTL {
			cached := s.summaryCache.data
			s.summaryCache.mu.Unlock()
			s.jsonResponse(w, map[string]interface{}{"ok": true, "data": cached}, 200)
			return
		}
		s.summaryCache.mu.Unlock()
	}

	data, err := s.store.QuerySummary(startDate, endDate)
	if err != nil {
		log.Printf("[api] query summary error: %v", err)
		s.jsonResponse(w, map[string]interface{}{"ok": false, "error": err.Error()}, 500)
		return
	}

	// Enrich each vendor summary
	for _, item := range data {
		enrichUsageMetrics(item, s.cfg)
	}
	sortSummaryRowsByConsumption(data)

	// Cache default query results
	if startDate == "" && endDate == "" {
		s.summaryCache.mu.Lock()
		s.summaryCache.data = data
		s.summaryCache.updated = time.Now()
		s.summaryCache.mu.Unlock()
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
	if pageSize > maxPageSize {
		pageSize = maxPageSize
	}
	vendor := q.Get("vendor")
	search := q.Get("search")
	channelClass := q.Get("channel_class")
	timeWindow := queryInt(q, "time_window_minutes", 0)
	minBytes := queryInt(q, "min_bytes", 0)
	startDate := q.Get("start_date")
	endDate := q.Get("end_date")

	result, err := s.store.QueryRequestLogs(vendor, search, channelClass, timeWindow, page, pageSize, minBytes, startDate, endDate)
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

func sortSummaryRowsByConsumption(rows []map[string]interface{}) {
	sort.SliceStable(rows, func(i, j int) bool {
		leftCost := toFloat64(rows[i]["estimated_cost_usd"])
		rightCost := toFloat64(rows[j]["estimated_cost_usd"])
		if leftCost != rightCost {
			return leftCost > rightCost
		}

		leftBytes := toFloat64(rows[i]["total_bytes"])
		rightBytes := toFloat64(rows[j]["total_bytes"])
		if leftBytes != rightBytes {
			return leftBytes > rightBytes
		}

		leftTokens := toFloat64(rows[i]["total_tokens"])
		rightTokens := toFloat64(rows[j]["total_tokens"])
		if leftTokens != rightTokens {
			return leftTokens > rightTokens
		}

		leftSeen := toString(rows[i]["latest_seen"])
		rightSeen := toString(rows[j]["latest_seen"])
		if leftSeen != rightSeen {
			return leftSeen > rightSeen
		}

		leftVendor := toString(rows[i]["vendor"])
		rightVendor := toString(rows[j]["vendor"])
		if leftVendor != rightVendor {
			return leftVendor < rightVendor
		}

		return toString(rows[i]["domain"]) < toString(rows[j]["domain"])
	})
}

func (s *Server) handleTransportEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	q := r.URL.Query()
	page := queryInt(q, "page", 1)
	pageSize := queryInt(q, "page_size", queryInt(q, "limit", 50))
	if pageSize > maxPageSize {
		pageSize = maxPageSize
	}
	srcIP := q.Get("src_ip")
	protocol := q.Get("protocol")
	search := q.Get("search")
	timeWindow := queryInt(q, "time_window_minutes", 0)
	startDate := q.Get("start_date")
	endDate := q.Get("end_date")

	result, err := s.store.QueryTransportEvents(srcIP, protocol, search, timeWindow, page, pageSize, startDate, endDate)
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

func (s *Server) handlePipeline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	data, err := s.store.QueryPipelineStatus()
	if err != nil {
		s.jsonResponse(w, map[string]interface{}{"ok": false, "error": err.Error()}, 500)
		return
	}
	now := time.Now().UTC().Add(8 * time.Hour).Format("2006-01-02 15:04:05")
	data["server_time"] = now
	data["uptime"] = time.Since(s.started).Truncate(time.Second).String()
	data["active_sessions"] = s.engine.ActiveSessions()
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

func (s *Server) handleQUICObservations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	limit := queryInt(r.URL.Query(), "limit", 50)
	data := s.engine.RecentQUICObservations(limit)
	s.jsonResponse(w, map[string]interface{}{"ok": true, "data": data}, 200)
}

func (s *Server) handleExportCSV(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}

	// Extend write deadline to 10 minutes for large exports
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Now().Add(10 * time.Minute))

	q := r.URL.Query()
	exportType := q.Get("type") // "logs" or "request-logs"
	vendor := q.Get("vendor")
	search := q.Get("search")
	channelClass := q.Get("channel_class")
	minBytes := queryInt(q, "min_bytes", 0)
	startDate := q.Get("start_date")
	endDate := q.Get("end_date")

	if exportType != "logs" && exportType != "request-logs" && exportType != "user-summary" && exportType != "user-total" {
		s.jsonResponse(w, map[string]interface{}{"ok": false, "error": "type must be 'logs', 'request-logs', 'user-summary' or 'user-total'"}, 400)
		return
	}

	// Convert time_window_minutes to start_date for user exports
	timeWindow := queryInt(q, "time_window_minutes", 0)
	if (exportType == "user-summary" || exportType == "user-total") && startDate == "" && endDate == "" && timeWindow > 0 {
		startDate = time.Now().UTC().Add(8 * time.Hour).Add(-time.Duration(timeWindow) * time.Minute).Format("2006-01-02 15:04:05")
	}

	now := time.Now().Format("2006-01-02_150405")
	filename := fmt.Sprintf("%s_%s_%s.csv", now, channelClass, exportType)
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Cache-Control", "no-store")

	// Write BOM for Excel compatibility
	w.Write([]byte("\xEF\xBB\xBF"))

	flusher, _ := w.(http.Flusher)

	if exportType == "logs" {
		s.streamExportLogs(w, flusher, vendor, search, channelClass, minBytes, startDate, endDate)
	} else if exportType == "request-logs" {
		s.streamExportRequestLogs(w, flusher, vendor, search, channelClass, minBytes, startDate, endDate)
	} else if exportType == "user-summary" {
		s.streamExportUserSummary(w, flusher, search, startDate, endDate)
	} else {
		s.streamExportUserTotal(w, flusher, search, startDate, endDate)
	}
}

func (s *Server) streamExportLogs(w http.ResponseWriter, flusher http.Flusher, vendor, search, channelClass string, minBytes int, startDate, endDate string) {
	rows, total, err := s.store.StreamExportLogs(vendor, search, channelClass, minBytes, startDate, endDate)
	if err != nil {
		log.Printf("[api] export logs error: %v", err)
		return
	}
	defer rows.Close()

	// Header
	w.Write([]byte("抓包网卡,源IP,用户,部门,首次时间,最近时间,调用类型,模型厂商,访问域名,上行流量,下行流量,总流量,输入Token,输出Token,总Token,预估金额USD,请求次数\n"))
	if flusher != nil {
		flusher.Flush()
	}

	log.Printf("[api] streaming export logs: %d rows", total)
	count := 0
	for rows.Next() {
		var id int64
		var r struct {
			CaptureJobID                                                                                                                            int
			Iface, SrcIP, FirstSeen, Vendor, Domain, LastSeen, UpdatedAt, ClosedAt, Status, SessionKey, SrcUser, SrcHostname, SrcDepartment string
			SrcPort, DstPort, RequestCount, PacketCount                                                                                     int
			DstIP                                                                                                                           string
			UplinkBytes, DownlinkBytes, TotalBytes                                                                                          int64
		}
		if err := rows.Scan(&id, &r.CaptureJobID, &r.Iface, &r.SrcIP, &r.SrcPort,
			&r.DstIP, &r.DstPort, &r.FirstSeen, &r.Vendor, &r.Domain,
			&r.UplinkBytes, &r.DownlinkBytes, &r.TotalBytes,
			&r.RequestCount, &r.PacketCount, &r.SessionKey, &r.LastSeen,
			&r.UpdatedAt, &r.ClosedAt, &r.Status,
			&r.SrcUser, &r.SrcHostname, &r.SrcDepartment); err != nil {
			log.Printf("[api] export scan error at row %d: %v", count, err)
			return
		}

		// Enrich IP-user if DB fields are empty
		user, department := r.SrcUser, r.SrcDepartment
		if user == "" {
			if entry := s.ipUsers.Lookup(r.SrcIP); entry != nil {
				user = entry.Username
				department = entry.Department
			}
		}

		// Compute tokens/cost
		m := map[string]interface{}{
			"uplink_bytes":   r.UplinkBytes,
			"downlink_bytes": r.DownlinkBytes,
			"vendor":         r.Vendor,
			"domain":         r.Domain,
		}
		enrichUsageMetrics(m, s.cfg)

		line := fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s,%s,%d,%d,%d,%v,%v,%v,%v,%d\n",
			csvField(r.Iface), csvField(r.SrcIP), csvField(user), csvField(department),
			csvField(r.FirstSeen), csvField(r.LastSeen),
			csvField(toString(m["channel_type"])),
			csvField(r.Vendor), csvField(r.Domain),
			r.UplinkBytes, r.DownlinkBytes, r.TotalBytes,
			m["input_tokens"], m["output_tokens"], m["total_tokens"],
			m["estimated_cost_usd"], r.RequestCount)
		w.Write([]byte(line))
		count++
		if count%5000 == 0 && flusher != nil {
			flusher.Flush()
		}
	}
	if flusher != nil {
		flusher.Flush()
	}
	log.Printf("[api] export logs complete: %d rows written", count)
}

func (s *Server) streamExportRequestLogs(w http.ResponseWriter, flusher http.Flusher, vendor, search, channelClass string, minBytes int, startDate, endDate string) {
	rows, total, err := s.store.StreamExportRequestLogs(vendor, search, channelClass, minBytes, startDate, endDate)
	if err != nil {
		log.Printf("[api] export request-logs error: %v", err)
		return
	}
	defer rows.Close()

	// Header
	w.Write([]byte("抓包网卡,源IP,用户,部门,访问时间,调用类型,模型厂商,访问域名,上行流量,下行流量,总流量,输入Token,输出Token,总Token,预估金额USD,请求次数\n"))
	if flusher != nil {
		flusher.Flush()
	}

	log.Printf("[api] streaming export request-logs: %d rows", total)
	count := 0
	for rows.Next() {
		var r struct {
			ID, CaptureJobID                                                                                           int
			RequestKey, SessionKey, Iface, SrcIP, DstIP, SeenAt, Vendor, Domain, SrcUser, SrcHostname, SrcDepartment string
			SrcPort, DstPort, RequestCount                                                                             int
			UplinkBytes, DownlinkBytes, TotalBytes                                                                     int64
		}
		if err := rows.Scan(&r.ID, &r.CaptureJobID, &r.RequestKey, &r.SessionKey,
			&r.Iface, &r.SrcIP, &r.SrcPort, &r.DstIP, &r.DstPort,
			&r.SeenAt, &r.Vendor, &r.Domain,
			&r.UplinkBytes, &r.DownlinkBytes, &r.TotalBytes, &r.RequestCount,
			&r.SrcUser, &r.SrcHostname, &r.SrcDepartment); err != nil {
			log.Printf("[api] export scan error at row %d: %v", count, err)
			return
		}

		user, department := r.SrcUser, r.SrcDepartment
		if user == "" {
			if entry := s.ipUsers.Lookup(r.SrcIP); entry != nil {
				user = entry.Username
				department = entry.Department
			}
		}

		m := map[string]interface{}{
			"uplink_bytes":   r.UplinkBytes,
			"downlink_bytes": r.DownlinkBytes,
			"vendor":         r.Vendor,
			"domain":         r.Domain,
		}
		enrichUsageMetrics(m, s.cfg)

		line := fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s,%d,%d,%d,%v,%v,%v,%v,%d\n",
			csvField(r.Iface), csvField(r.SrcIP), csvField(user), csvField(department),
			csvField(r.SeenAt),
			csvField(toString(m["channel_type"])),
			csvField(r.Vendor), csvField(r.Domain),
			r.UplinkBytes, r.DownlinkBytes, r.TotalBytes,
			m["input_tokens"], m["output_tokens"], m["total_tokens"],
			m["estimated_cost_usd"], r.RequestCount)
		w.Write([]byte(line))
		count++
		if count%5000 == 0 && flusher != nil {
			flusher.Flush()
		}
	}
	if flusher != nil {
		flusher.Flush()
	}
	log.Printf("[api] export request-logs complete: %d rows written", count)
}

func (s *Server) streamExportUserSummary(w http.ResponseWriter, flusher http.Flusher, search, startDate, endDate string) {
	rows, total, err := s.store.StreamExportUserSummary(search, startDate, endDate)
	if err != nil {
		log.Printf("[api] export user-summary error: %v", err)
		return
	}
	defer rows.Close()

	w.Write([]byte("用户,部门,用户IP,模型厂商,调用类型,访问域名,会话数,请求次数,上行流量,下行流量,总流量,输入Token,输出Token,总Token,预估金额USD,首次访问时间,最后访问时间\n"))
	if flusher != nil {
		flusher.Flush()
	}

	log.Printf("[api] streaming export user-summary: %d rows", total)
	count := 0
	for rows.Next() {
		var srcUser, srcDept, srcIP, vendor, domain, firstSeen, lastSeen string
		var sessionCount, requestCount int
		var uplinkBytes, downlinkBytes, totalBytes int64
		if err := rows.Scan(&srcUser, &srcDept, &srcIP, &vendor, &domain,
			&sessionCount, &requestCount, &uplinkBytes, &downlinkBytes, &totalBytes,
			&firstSeen, &lastSeen); err != nil {
			log.Printf("[api] export user-summary scan error at row %d: %v", count, err)
			return
		}

		m := map[string]interface{}{
			"uplink_bytes":   uplinkBytes,
			"downlink_bytes": downlinkBytes,
			"vendor":         vendor,
			"domain":         domain,
		}
		enrichUsageMetrics(m, s.cfg)

		// Enrich user from IPUserMap if DB field is empty
		if srcUser == "" {
			if entry := s.ipUsers.Lookup(srcIP); entry != nil && entry.Username != "" {
				srcUser = entry.Username
				srcDept = entry.Department
			}
		}
		displayUser := srcUser
		if displayUser == "" {
			displayUser = "N/A"
		}

		line := fmt.Sprintf("%s,%s,%s,%s,%s,%s,%d,%d,%d,%d,%d,%v,%v,%v,%v,%s,%s\n",
			csvField(displayUser), csvField(srcDept), csvField(srcIP),
			csvField(vendor), csvField(toString(m["channel_type"])), csvField(domain),
			sessionCount, requestCount,
			uplinkBytes, downlinkBytes, totalBytes,
			m["input_tokens"], m["output_tokens"], m["total_tokens"],
			m["estimated_cost_usd"],
			csvField(firstSeen), csvField(lastSeen))
		w.Write([]byte(line))
		count++
		if count%5000 == 0 && flusher != nil {
			flusher.Flush()
		}
	}
	if flusher != nil {
		flusher.Flush()
	}
	log.Printf("[api] export user-summary complete: %d rows written", count)
}

func (s *Server) streamExportUserTotal(w http.ResponseWriter, flusher http.Flusher, search, startDate, endDate string) {
	// Reuse handleUserTotal logic: get detail data, enrich, aggregate
	detailItems, err := s.store.QueryUserSummary(search, startDate, endDate)
	if err != nil {
		log.Printf("[api] export user-total error: %v", err)
		return
	}
	for _, item := range detailItems {
		enrichUsageMetrics(item, s.cfg)
		srcUser := toString(item["src_user"])
		if srcUser == "" {
			srcIP := toString(item["src_ip"])
			if idx := strings.Index(srcIP, ","); idx > 0 {
				srcIP = strings.TrimSpace(srcIP[:idx])
			}
			if entry := s.ipUsers.Lookup(srcIP); entry != nil && entry.Username != "" {
				item["src_user"] = entry.Username
				item["src_department"] = entry.Department
			}
		}
	}

	type userAgg struct {
		SrcUser, SrcDept                                              string
		IPs                                                           map[string]bool
		VendorCount                                                   map[string]bool
		SessionCount, RequestCount                                    int
		UplinkBytes, DownlinkBytes, TotalBytes                        int64
		InputTokens, OutputTokens, TotalTokens                        int64
		CostUSD                                                       float64
		FirstSeen, LastSeen                                           string
	}
	aggMap := make(map[string]*userAgg)
	aggOrder := []string{}

	for _, item := range detailItems {
		srcUser := toString(item["src_user"])
		srcIP := toString(item["src_ip"])
		key := srcUser
		if key == "" {
			firstIP := srcIP
			if idx := strings.Index(firstIP, ","); idx > 0 {
				firstIP = strings.TrimSpace(firstIP[:idx])
			}
			key = "ip:" + firstIP
		}
		agg, exists := aggMap[key]
		if !exists {
			agg = &userAgg{SrcUser: srcUser, SrcDept: toString(item["src_department"]), IPs: make(map[string]bool), VendorCount: make(map[string]bool)}
			aggMap[key] = agg
			aggOrder = append(aggOrder, key)
		}
		for _, ip := range strings.Split(srcIP, ",") {
			if ip = strings.TrimSpace(ip); ip != "" {
				agg.IPs[ip] = true
			}
		}
		agg.VendorCount[toString(item["vendor"])] = true
		if d := toString(item["src_department"]); d != "" {
			agg.SrcDept = d
		}
		agg.SessionCount += int(toInt64(item["session_count"]))
		agg.RequestCount += int(toInt64(item["request_count"]))
		agg.UplinkBytes += toInt64(item["uplink_bytes"])
		agg.DownlinkBytes += toInt64(item["downlink_bytes"])
		agg.TotalBytes += toInt64(item["total_bytes"])
		agg.InputTokens += toInt64(item["input_tokens"])
		agg.OutputTokens += toInt64(item["output_tokens"])
		agg.TotalTokens += toInt64(item["total_tokens"])
		agg.CostUSD += toFloat64(item["estimated_cost_usd"])
		fs := toString(item["first_seen"])
		ls := toString(item["last_seen"])
		if agg.FirstSeen == "" || (fs != "" && fs < agg.FirstSeen) {
			agg.FirstSeen = fs
		}
		if ls > agg.LastSeen {
			agg.LastSeen = ls
		}
	}

	// Sort by cost desc
	sort.SliceStable(aggOrder, func(i, j int) bool {
		return aggMap[aggOrder[i]].CostUSD > aggMap[aggOrder[j]].CostUSD
	})

	w.Write([]byte("用户,部门,用户IP,使用厂商数,请求次数,上行流量,下行流量,总流量,输入Token,输出Token,总Token,预估金额USD,首次访问时间,最后访问时间\n"))
	if flusher != nil {
		flusher.Flush()
	}
	log.Printf("[api] streaming export user-total: %d users", len(aggOrder))
	for _, key := range aggOrder {
		agg := aggMap[key]
		displayUser := agg.SrcUser
		if displayUser == "" {
			displayUser = "N/A"
		}
		ips := make([]string, 0, len(agg.IPs))
		for ip := range agg.IPs {
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		line := fmt.Sprintf("%s,%s,%s,%d,%d,%d,%d,%d,%d,%d,%d,%v,%s,%s\n",
			csvField(displayUser), csvField(agg.SrcDept), csvField(strings.Join(ips, " ")),
			len(agg.VendorCount), agg.RequestCount,
			agg.UplinkBytes, agg.DownlinkBytes, agg.TotalBytes,
			agg.InputTokens, agg.OutputTokens, agg.TotalTokens,
			agg.CostUSD, csvField(agg.FirstSeen), csvField(agg.LastSeen))
		w.Write([]byte(line))
	}
	if flusher != nil {
		flusher.Flush()
	}
	log.Printf("[api] export user-total complete: %d users written", len(aggOrder))
}

func csvField(s string) string {
	if strings.ContainsAny(s, ",\"\n") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

func (s *Server) handleUserSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	q := r.URL.Query()
	page := queryInt(q, "page", 1)
	pageSize := queryInt(q, "page_size", 100)
	if pageSize > maxPageSize {
		pageSize = maxPageSize
	}
	search := q.Get("search")
	startDate := q.Get("start_date")
	endDate := q.Get("end_date")
	vendor := q.Get("vendor")
	timeWindow := queryInt(q, "time_window_minutes", 0)

	// Convert time_window_minutes to start_date if no explicit date range
	if startDate == "" && endDate == "" && timeWindow > 0 {
		startDate = time.Now().UTC().Add(8 * time.Hour).Add(-time.Duration(timeWindow) * time.Minute).Format("2006-01-02 15:04:05")
	}

	allItems, err := s.store.QueryUserSummary(search, startDate, endDate)
	if err != nil {
		log.Printf("[api] query user summary error: %v", err)
		s.jsonResponse(w, map[string]interface{}{"ok": false, "error": err.Error()}, 500)
		return
	}

	// Enrich all rows with token/cost + IP-user mapping
	for _, item := range allItems {
		enrichUsageMetrics(item, s.cfg)
		srcUser := toString(item["src_user"])
		if srcUser == "" {
			// src_ip may be comma-separated (GROUP_CONCAT), try first IP
			srcIP := toString(item["src_ip"])
			if idx := strings.Index(srcIP, ","); idx > 0 {
				srcIP = strings.TrimSpace(srcIP[:idx])
			}
			if entry := s.ipUsers.Lookup(srcIP); entry != nil && entry.Username != "" {
				item["src_user"] = entry.Username
				item["src_department"] = entry.Department
			}
		}
	}

	// Filter by vendor if specified
	if vendor != "" {
		filtered := make([]map[string]interface{}, 0, len(allItems))
		for _, item := range allItems {
			if toString(item["vendor"]) == vendor {
				filtered = append(filtered, item)
			}
		}
		allItems = filtered
	}

	// Sort by estimated_cost_usd descending
	sort.SliceStable(allItems, func(i, j int) bool {
		return toFloat64(allItems[i]["estimated_cost_usd"]) > toFloat64(allItems[j]["estimated_cost_usd"])
	})

	// Manual pagination
	total := len(allItems)
	totalPages := (total + pageSize - 1) / pageSize
	if totalPages == 0 {
		totalPages = 1
	}
	if page > totalPages {
		page = totalPages
	}
	start := (page - 1) * pageSize
	end := start + pageSize
	if end > total {
		end = total
	}
	pageItems := allItems[start:end]

	result := &model.PagedResult{
		Items: pageItems, Total: total, Page: page, PageSize: pageSize, TotalPages: totalPages,
	}

	s.jsonResponse(w, map[string]interface{}{"ok": true, "data": result}, 200)
}

func (s *Server) handleUserTotal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	q := r.URL.Query()
	page := queryInt(q, "page", 1)
	pageSize := queryInt(q, "page_size", 100)
	if pageSize > maxPageSize {
		pageSize = maxPageSize
	}
	search := q.Get("search")
	startDate := q.Get("start_date")
	endDate := q.Get("end_date")
	timeWindow := queryInt(q, "time_window_minutes", 0)

	if startDate == "" && endDate == "" && timeWindow > 0 {
		startDate = time.Now().UTC().Add(8 * time.Hour).Add(-time.Duration(timeWindow) * time.Minute).Format("2006-01-02 15:04:05")
	}

	// Reuse QueryUserSummary (per vendor+domain) to get accurate per-vendor pricing
	detailItems, err := s.store.QueryUserSummary(search, startDate, endDate)
	if err != nil {
		log.Printf("[api] query user total error: %v", err)
		s.jsonResponse(w, map[string]interface{}{"ok": false, "error": err.Error()}, 500)
		return
	}

	// Enrich each detail row with token/cost + IP-user mapping
	for _, item := range detailItems {
		enrichUsageMetrics(item, s.cfg)
		srcUser := toString(item["src_user"])
		if srcUser == "" {
			srcIP := toString(item["src_ip"])
			if idx := strings.Index(srcIP, ","); idx > 0 {
				srcIP = strings.TrimSpace(srcIP[:idx])
			}
			if entry := s.ipUsers.Lookup(srcIP); entry != nil && entry.Username != "" {
				item["src_user"] = entry.Username
				item["src_department"] = entry.Department
			}
		}
	}

	// Aggregate by user: group key = src_user (or src_ip if empty)
	type userAgg struct {
		SrcUser, SrcDept string
		IPs              map[string]bool
		VendorSet        map[string]bool
		SessionCount     int
		RequestCount     int
		UplinkBytes      int64
		DownlinkBytes    int64
		TotalBytes       int64
		InputTokens      int64
		OutputTokens     int64
		TotalTokens      int64
		CostUSD          float64
		FirstSeen        string
		LastSeen         string
	}
	aggMap := make(map[string]*userAgg)
	aggOrder := []string{}

	for _, item := range detailItems {
		srcUser := toString(item["src_user"])
		srcIP := toString(item["src_ip"])
		key := srcUser
		if key == "" {
			// Use first IP as key for anonymous users
			firstIP := srcIP
			if idx := strings.Index(firstIP, ","); idx > 0 {
				firstIP = strings.TrimSpace(firstIP[:idx])
			}
			key = "ip:" + firstIP
		}

		agg, exists := aggMap[key]
		if !exists {
			agg = &userAgg{
				SrcUser: srcUser,
				SrcDept: toString(item["src_department"]),
				IPs:     make(map[string]bool),
				VendorSet: make(map[string]bool),
			}
			aggMap[key] = agg
			aggOrder = append(aggOrder, key)
		}

		// Collect IPs
		for _, ip := range strings.Split(srcIP, ",") {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				agg.IPs[ip] = true
			}
		}
		agg.VendorSet[toString(item["vendor"])] = true
		if dept := toString(item["src_department"]); dept != "" {
			agg.SrcDept = dept
		}
		agg.SessionCount += int(toInt64(item["session_count"]))
		agg.RequestCount += int(toInt64(item["request_count"]))
		agg.UplinkBytes += toInt64(item["uplink_bytes"])
		agg.DownlinkBytes += toInt64(item["downlink_bytes"])
		agg.TotalBytes += toInt64(item["total_bytes"])
		agg.InputTokens += toInt64(item["input_tokens"])
		agg.OutputTokens += toInt64(item["output_tokens"])
		agg.TotalTokens += toInt64(item["total_tokens"])
		agg.CostUSD += toFloat64(item["estimated_cost_usd"])

		fs := toString(item["first_seen"])
		ls := toString(item["last_seen"])
		if agg.FirstSeen == "" || (fs != "" && fs < agg.FirstSeen) {
			agg.FirstSeen = fs
		}
		if ls > agg.LastSeen {
			agg.LastSeen = ls
		}
	}

	// Build result list
	allItems := make([]map[string]interface{}, 0, len(aggOrder))
	for _, key := range aggOrder {
		agg := aggMap[key]
		ips := make([]string, 0, len(agg.IPs))
		for ip := range agg.IPs {
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		allItems = append(allItems, map[string]interface{}{
			"src_user":          agg.SrcUser,
			"src_department":    agg.SrcDept,
			"src_ip":            strings.Join(ips, ", "),
			"vendor_count":      len(agg.VendorSet),
			"session_count":     agg.SessionCount,
			"request_count":     agg.RequestCount,
			"uplink_bytes":      agg.UplinkBytes,
			"downlink_bytes":    agg.DownlinkBytes,
			"total_bytes":       agg.TotalBytes,
			"input_tokens":      agg.InputTokens,
			"output_tokens":     agg.OutputTokens,
			"total_tokens":      agg.TotalTokens,
			"estimated_cost_usd": agg.CostUSD,
			"estimated_cost_cny": agg.CostUSD * s.cfg.USDCNYRate,
			"first_seen":        agg.FirstSeen,
			"last_seen":         agg.LastSeen,
		})
	}

	// Sort by cost descending
	sort.SliceStable(allItems, func(i, j int) bool {
		return toFloat64(allItems[i]["estimated_cost_usd"]) > toFloat64(allItems[j]["estimated_cost_usd"])
	})

	// Manual pagination
	total := len(allItems)
	totalPages := (total + pageSize - 1) / pageSize
	if totalPages == 0 {
		totalPages = 1
	}
	if page > totalPages {
		page = totalPages
	}
	start := (page - 1) * pageSize
	end := start + pageSize
	if end > total {
		end = total
	}

	result := &model.PagedResult{
		Items: allItems[start:end], Total: total, Page: page, PageSize: pageSize, TotalPages: totalPages,
	}
	s.jsonResponse(w, map[string]interface{}{"ok": true, "data": result}, 200)
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

func toFloat64(v interface{}) float64 {
	switch val := v.(type) {
	case float64:
		return val
	case float32:
		return float64(val)
	case int64:
		return float64(val)
	case int:
		return float64(val)
	case string:
		n, _ := strconv.ParseFloat(val, 64)
		return n
	}
	return 0
}
