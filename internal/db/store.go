package db

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/redis/go-redis/v9"

	"llm_api_monitor/internal/config"
	"llm_api_monitor/internal/model"
)

// Store holds the MySQL connection pool and optional Redis client.
type Store struct {
	DB    *sql.DB
	Redis *redis.Client
	cfg   *config.Config
}

// New creates a new Store with connection pools.
func New(cfg *config.Config) (*Store, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=%s&parseTime=false&loc=Local&interpolateParams=true",
		cfg.MySQL.User, cfg.MySQL.Password, cfg.MySQL.Host, cfg.MySQL.Port, cfg.MySQL.Database, cfg.MySQL.Charset)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("mysql open: %w", err)
	}
	db.SetMaxOpenConns(cfg.MySQL.MaxOpen)
	db.SetMaxIdleConns(cfg.MySQL.MaxIdle)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("mysql ping: %w", err)
	}

	s := &Store{DB: db, cfg: cfg}

	if cfg.Redis.Enabled {
		s.Redis = redis.NewClient(&redis.Options{
			Addr:         fmt.Sprintf("%s:%d", cfg.Redis.Host, cfg.Redis.Port),
			Password:     cfg.Redis.Password,
			DB:           cfg.Redis.DB,
			DialTimeout:  1500 * time.Millisecond,
			ReadTimeout:  1500 * time.Millisecond,
			WriteTimeout: 1500 * time.Millisecond,
			PoolSize:     10,
		})
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := s.Redis.Ping(ctx).Err(); err != nil {
			log.Printf("[warn] redis connection failed, disabling: %v", err)
			s.Redis = nil
		}
	}

	return s, nil
}

// Close closes all connections.
func (s *Store) Close() {
	if s.DB != nil {
		s.DB.Close()
	}
	if s.Redis != nil {
		s.Redis.Close()
	}
}

// InitDB ensures all required tables and indexes exist.
func (s *Store) InitDB() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS capture_jobs (
			id INT PRIMARY KEY AUTO_INCREMENT,
			iface VARCHAR(64) NOT NULL,
			window_seconds INT NOT NULL,
			bpf_filter VARCHAR(255) NOT NULL,
			pcap_path VARCHAR(512),
			started_at VARCHAR(19) NOT NULL,
			finished_at VARCHAR(19),
			packet_count INT DEFAULT 0,
			status VARCHAR(32) NOT NULL,
			message TEXT,
			queue_name VARCHAR(32) NOT NULL DEFAULT '',
			analysis_status VARCHAR(32) NOT NULL DEFAULT '',
			analysis_finished_at VARCHAR(19) NULL,
			result_path VARCHAR(512) NULL,
			cleanup_marker_path VARCHAR(512) NULL,
			worker_name VARCHAR(128) NULL
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		`CREATE TABLE IF NOT EXISTS api_logs (
			id INT PRIMARY KEY AUTO_INCREMENT,
			capture_job_id INT NOT NULL,
			iface VARCHAR(64) NOT NULL,
			src_ip VARCHAR(64) NOT NULL,
			src_port INT NOT NULL,
			dst_ip VARCHAR(64) NOT NULL,
			dst_port INT NOT NULL,
			first_seen VARCHAR(19) NOT NULL,
			vendor VARCHAR(128) NOT NULL,
			domain VARCHAR(255) NOT NULL,
			uplink_bytes BIGINT NOT NULL,
			downlink_bytes BIGINT NOT NULL,
			total_bytes BIGINT NOT NULL,
			request_count INT NOT NULL,
			packet_count INT NOT NULL,
			session_key VARCHAR(255),
			last_seen VARCHAR(19),
			updated_at VARCHAR(19),
			closed_at VARCHAR(19),
			status VARCHAR(32) NOT NULL DEFAULT 'open',
			UNIQUE KEY idx_api_logs_session_key (session_key),
			KEY idx_api_logs_last_seen (last_seen),
			KEY idx_api_logs_vendor_last_seen (vendor, last_seen),
			KEY idx_api_logs_vendor_domain (vendor, domain)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		`CREATE TABLE IF NOT EXISTS target_rules (
			id INT PRIMARY KEY AUTO_INCREMENT,
			vendor VARCHAR(128) NOT NULL,
			domain_pattern VARCHAR(255) NOT NULL,
			match_type VARCHAR(32) NOT NULL DEFAULT 'exact',
			source VARCHAR(32) NOT NULL DEFAULT 'default',
			enabled TINYINT(1) NOT NULL DEFAULT 1,
			created_at VARCHAR(19) NOT NULL,
			updated_at VARCHAR(19) NOT NULL,
			UNIQUE KEY idx_target_rules_vendor_domain (vendor, domain_pattern)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		`CREATE TABLE IF NOT EXISTS request_logs (
			id INT PRIMARY KEY AUTO_INCREMENT,
			capture_job_id INT NOT NULL,
			request_key VARCHAR(320),
			session_key VARCHAR(255),
			iface VARCHAR(64) NOT NULL,
			src_ip VARCHAR(64) NOT NULL,
			src_port INT NOT NULL,
			dst_ip VARCHAR(64) NOT NULL,
			dst_port INT NOT NULL,
			seen_at VARCHAR(19) NOT NULL,
			vendor VARCHAR(128) NOT NULL,
			domain VARCHAR(255) NOT NULL,
			uplink_bytes BIGINT NOT NULL,
			downlink_bytes BIGINT NOT NULL,
			total_bytes BIGINT NOT NULL,
			request_count INT NOT NULL,
			UNIQUE KEY idx_request_logs_request_key (request_key),
			KEY idx_request_logs_seen_at (seen_at),
			KEY idx_request_logs_seen_at_id (seen_at, id),
			KEY idx_request_logs_vendor_seen_at (vendor, seen_at),
			KEY idx_request_logs_vendor_seen_at_id (vendor, seen_at, id),
			KEY idx_request_logs_domain_seen_at_id (domain, seen_at, id),
			KEY idx_request_logs_session_key (session_key)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		`CREATE TABLE IF NOT EXISTS transport_events (
			id INT PRIMARY KEY AUTO_INCREMENT,
			capture_job_id INT NOT NULL,
			iface VARCHAR(64) NOT NULL,
			src_ip VARCHAR(64) NOT NULL,
			src_port INT NOT NULL,
			dst_ip VARCHAR(64) NOT NULL,
			dst_port INT NOT NULL,
			protocol VARCHAR(32) NOT NULL,
			note TEXT,
			first_seen VARCHAR(19) NOT NULL,
			last_seen VARCHAR(19) NOT NULL,
			packet_count INT NOT NULL,
			total_bytes BIGINT NOT NULL,
			KEY idx_transport_events_seen_at (last_seen),
			KEY idx_transport_events_seen_at_id (last_seen, id),
			KEY idx_transport_events_src_ip_seen_at (src_ip, last_seen),
			KEY idx_transport_events_protocol_seen_at (protocol, last_seen)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
	}

	for _, stmt := range stmts {
		if _, err := s.DB.Exec(stmt); err != nil {
			return fmt.Errorf("init table: %w", err)
		}
	}
	return nil
}

// InsertJob inserts a new capture job and returns its ID.
func (s *Store) InsertJob(job *model.CaptureJob) (int64, error) {
	res, err := s.DB.Exec(`INSERT INTO capture_jobs
		(iface, window_seconds, bpf_filter, pcap_path, started_at, finished_at, packet_count, status, message, queue_name, analysis_status, worker_name)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		job.Iface, job.WindowSeconds, job.BPFFilter, job.PcapPath,
		job.StartedAt, job.FinishedAt, job.PacketCount, job.Status,
		job.Message, job.QueueName, job.AnalysisStatus, job.WorkerName)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateJobStatus updates the status and analysis fields of a capture job.
func (s *Store) UpdateJobStatus(jobID int64, fields map[string]interface{}) error {
	if len(fields) == 0 {
		return nil
	}
	setClauses := make([]string, 0, len(fields))
	args := make([]interface{}, 0, len(fields))
	for k, v := range fields {
		setClauses = append(setClauses, fmt.Sprintf("%s = ?", k))
		args = append(args, v)
	}
	args = append(args, jobID)
	_, err := s.DB.Exec(
		fmt.Sprintf("UPDATE capture_jobs SET %s WHERE id = ?", strings.Join(setClauses, ", ")),
		args...)
	return err
}

// UpdateJob updates the final status after merge.
func (s *Store) UpdateJob(jobID int64, finishedAt string, packetCount int, status, message, startedAt string) error {
	_, err := s.DB.Exec(`UPDATE capture_jobs SET
		finished_at = ?, packet_count = ?, status = ?, message = ?,
		started_at = COALESCE(NULLIF(?, ''), started_at),
		analysis_status = 'merged', analysis_finished_at = ?
		WHERE id = ?`,
		finishedAt, packetCount, status, message, startedAt, model.NowLocalText(), jobID)
	return err
}

// UpsertSessions upserts session rows into api_logs (batch).
func (s *Store) UpsertSessions(jobID int64, rows []*model.Session) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT INTO api_logs
		(capture_job_id, iface, src_ip, src_port, dst_ip, dst_port,
		 first_seen, vendor, domain, uplink_bytes, downlink_bytes, total_bytes,
		 request_count, packet_count, session_key, last_seen, updated_at, closed_at, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
		capture_job_id = VALUES(capture_job_id),
		uplink_bytes = VALUES(uplink_bytes),
		downlink_bytes = VALUES(downlink_bytes),
		total_bytes = VALUES(total_bytes),
		request_count = VALUES(request_count),
		packet_count = VALUES(packet_count),
		last_seen = VALUES(last_seen),
		updated_at = VALUES(updated_at),
		closed_at = VALUES(closed_at),
		status = VALUES(status)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, r := range rows {
		_, err := stmt.Exec(jobID, r.Iface, r.SrcIP, r.SrcPort, r.DstIP, r.DstPort,
			r.FirstSeen, r.Vendor, r.Domain, r.UplinkBytes, r.DownlinkBytes, r.TotalBytes,
			r.RequestCount, r.PacketCount, r.SessionKey, r.LastSeen, r.UpdatedAt, r.ClosedAt, r.Status)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

// InsertRequestLogs batch inserts request logs.
func (s *Store) InsertRequestLogs(jobID int64, rows []*model.RequestLog) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT INTO request_logs
		(capture_job_id, request_key, session_key, iface, src_ip, src_port,
		 dst_ip, dst_port, seen_at, vendor, domain,
		 uplink_bytes, downlink_bytes, total_bytes, request_count)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
		uplink_bytes = VALUES(uplink_bytes),
		downlink_bytes = VALUES(downlink_bytes),
		total_bytes = VALUES(total_bytes)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, r := range rows {
		r.CaptureJobID = jobID
		_, err := stmt.Exec(r.CaptureJobID, r.RequestKey, r.SessionKey,
			r.Iface, r.SrcIP, r.SrcPort, r.DstIP, r.DstPort,
			r.SeenAt, r.Vendor, r.Domain,
			r.UplinkBytes, r.DownlinkBytes, r.TotalBytes, r.RequestCount)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

// InsertTransportEvents batch inserts transport events.
func (s *Store) InsertTransportEvents(jobID int64, rows []*model.TransportEvent) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT INTO transport_events
		(capture_job_id, iface, src_ip, src_port, dst_ip, dst_port,
		 protocol, note, first_seen, last_seen, packet_count, total_bytes)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, r := range rows {
		r.CaptureJobID = jobID
		_, err := stmt.Exec(r.CaptureJobID, r.Iface, r.SrcIP, r.SrcPort,
			r.DstIP, r.DstPort, r.Protocol, r.Note,
			r.FirstSeen, r.LastSeen, r.PacketCount, r.TotalBytes)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

// LoadTargetRules loads enabled target rules from DB.
func (s *Store) LoadTargetRules() ([]model.TargetRule, error) {
	rows, err := s.DB.Query(`SELECT id, vendor, domain_pattern, match_type, source, enabled, created_at, updated_at
		FROM target_rules WHERE enabled = 1 ORDER BY vendor, domain_pattern`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []model.TargetRule
	for rows.Next() {
		var r model.TargetRule
		if err := rows.Scan(&r.ID, &r.Vendor, &r.DomainPattern, &r.MatchType, &r.Source, &r.Enabled, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// LoadOpenSessions loads sessions with status='open' for writer daemon restoration.
func (s *Store) LoadOpenSessions() ([]*model.Session, error) {
	rows, err := s.DB.Query(`SELECT
		capture_job_id, iface, src_ip, src_port, dst_ip, dst_port,
		first_seen, vendor, domain, uplink_bytes, downlink_bytes, total_bytes,
		request_count, packet_count, session_key, last_seen, updated_at, COALESCE(closed_at,''), status
		FROM api_logs WHERE status = 'open'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*model.Session
	for rows.Next() {
		s := &model.Session{}
		if err := rows.Scan(&s.CaptureJobID, &s.Iface, &s.SrcIP, &s.SrcPort,
			&s.DstIP, &s.DstPort, &s.FirstSeen, &s.Vendor, &s.Domain,
			&s.UplinkBytes, &s.DownlinkBytes, &s.TotalBytes,
			&s.RequestCount, &s.PacketCount, &s.SessionKey, &s.LastSeen,
			&s.UpdatedAt, &s.ClosedAt, &s.Status); err != nil {
			return nil, err
		}
		sessions = append(sessions, s)
	}
	return sessions, rows.Err()
}

// QueryLogs queries api_logs with filtering and pagination.
func (s *Store) QueryLogs(vendor, search, channelClass string, timeWindowMinutes, page, pageSize int) (*model.PagedResult, error) {
	where, args := buildLogFilters(vendor, search, "", timeWindowMinutes)

	var total int
	countSQL := "SELECT COUNT(*) FROM api_logs" + where
	if err := s.DB.QueryRow(countSQL, args...).Scan(&total); err != nil {
		return nil, err
	}

	totalPages := (total + pageSize - 1) / pageSize
	if page > totalPages && totalPages > 0 {
		page = totalPages
	}
	offset := (page - 1) * pageSize

	dataSQL := `SELECT id, capture_job_id, iface, src_ip, src_port, dst_ip, dst_port,
		first_seen, vendor, domain, uplink_bytes, downlink_bytes, total_bytes,
		request_count, packet_count, session_key, last_seen, updated_at,
		COALESCE(closed_at,'') AS closed_at, status
		FROM api_logs` + where + ` ORDER BY last_seen DESC, id DESC LIMIT ? OFFSET ?`
	args = append(args, pageSize, offset)

	rows, err := s.DB.Query(dataSQL, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []map[string]interface{}
	for rows.Next() {
		var r model.Session
		if err := rows.Scan(&r.CaptureJobID, &r.CaptureJobID, &r.Iface, &r.SrcIP, &r.SrcPort,
			&r.DstIP, &r.DstPort, &r.FirstSeen, &r.Vendor, &r.Domain,
			&r.UplinkBytes, &r.DownlinkBytes, &r.TotalBytes,
			&r.RequestCount, &r.PacketCount, &r.SessionKey, &r.LastSeen,
			&r.UpdatedAt, &r.ClosedAt, &r.Status); err != nil {
			return nil, err
		}
		items = append(items, sessionToMap(&r))
	}

	return &model.PagedResult{
		Items:      items,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// QuerySummary returns vendor-level aggregation.
func (s *Store) QuerySummary() ([]map[string]interface{}, error) {
	rows, err := s.DB.Query(`SELECT
		vendor,
		COUNT(*) AS session_count,
		SUM(uplink_bytes) AS total_uplink,
		SUM(downlink_bytes) AS total_downlink,
		SUM(total_bytes) AS total_bytes,
		SUM(request_count) AS total_requests,
		MIN(first_seen) AS earliest,
		MAX(last_seen) AS latest
		FROM api_logs
		GROUP BY vendor
		ORDER BY total_bytes DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var vendor string
		var sessionCount, totalRequests int
		var totalUplink, totalDownlink, totalBytes int64
		var earliest, latest string
		if err := rows.Scan(&vendor, &sessionCount, &totalUplink, &totalDownlink,
			&totalBytes, &totalRequests, &earliest, &latest); err != nil {
			return nil, err
		}
		results = append(results, map[string]interface{}{
			"vendor":        vendor,
			"session_count": sessionCount,
			"uplink_bytes":  totalUplink,
			"downlink_bytes": totalDownlink,
			"total_bytes":   totalBytes,
			"request_count": totalRequests,
			"earliest":      earliest,
			"latest":        latest,
		})
	}
	return results, nil
}

// QueryRequestLogs queries request_logs with filtering and pagination.
func (s *Store) QueryRequestLogs(vendor, search, channelClass string, timeWindowMinutes, page, pageSize int) (*model.PagedResult, error) {
	where, args := buildRequestLogFilters(vendor, search, timeWindowMinutes)

	var total int
	if err := s.DB.QueryRow("SELECT COUNT(*) FROM request_logs"+where, args...).Scan(&total); err != nil {
		return nil, err
	}

	totalPages := (total + pageSize - 1) / pageSize
	if page > totalPages && totalPages > 0 {
		page = totalPages
	}
	offset := (page - 1) * pageSize

	dataSQL := `SELECT id, capture_job_id, request_key, session_key, iface,
		src_ip, src_port, dst_ip, dst_port, seen_at, vendor, domain,
		uplink_bytes, downlink_bytes, total_bytes, request_count
		FROM request_logs` + where + ` ORDER BY seen_at DESC, id DESC LIMIT ? OFFSET ?`
	args = append(args, pageSize, offset)

	rows, err := s.DB.Query(dataSQL, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []map[string]interface{}
	for rows.Next() {
		var r model.RequestLog
		if err := rows.Scan(&r.ID, &r.CaptureJobID, &r.RequestKey, &r.SessionKey,
			&r.Iface, &r.SrcIP, &r.SrcPort, &r.DstIP, &r.DstPort,
			&r.SeenAt, &r.Vendor, &r.Domain,
			&r.UplinkBytes, &r.DownlinkBytes, &r.TotalBytes, &r.RequestCount); err != nil {
			return nil, err
		}
		items = append(items, map[string]interface{}{
			"id": r.ID, "capture_job_id": r.CaptureJobID,
			"request_key": r.RequestKey, "session_key": r.SessionKey,
			"iface": r.Iface, "src_ip": r.SrcIP, "src_port": r.SrcPort,
			"dst_ip": r.DstIP, "dst_port": r.DstPort, "seen_at": r.SeenAt,
			"vendor": r.Vendor, "domain": r.Domain,
			"uplink_bytes": r.UplinkBytes, "downlink_bytes": r.DownlinkBytes,
			"total_bytes": r.TotalBytes, "request_count": r.RequestCount,
		})
	}

	return &model.PagedResult{
		Items: items, Total: total, Page: page, PageSize: pageSize, TotalPages: totalPages,
	}, nil
}

// QueryTransportEvents queries transport_events with pagination.
func (s *Store) QueryTransportEvents(srcIP, protocol, search string, timeWindowMinutes, page, pageSize int) (*model.PagedResult, error) {
	where, args := buildTransportFilters(srcIP, protocol, search, timeWindowMinutes)

	var total int
	if err := s.DB.QueryRow("SELECT COUNT(*) FROM transport_events"+where, args...).Scan(&total); err != nil {
		return nil, err
	}

	totalPages := (total + pageSize - 1) / pageSize
	if page > totalPages && totalPages > 0 {
		page = totalPages
	}
	offset := (page - 1) * pageSize

	dataSQL := `SELECT id, capture_job_id, iface, src_ip, src_port, dst_ip, dst_port,
		protocol, COALESCE(note,''), first_seen, last_seen, packet_count, total_bytes
		FROM transport_events` + where + ` ORDER BY last_seen DESC, id DESC LIMIT ? OFFSET ?`
	args = append(args, pageSize, offset)

	rows, err := s.DB.Query(dataSQL, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []map[string]interface{}
	for rows.Next() {
		var r model.TransportEvent
		if err := rows.Scan(&r.ID, &r.CaptureJobID, &r.Iface, &r.SrcIP, &r.SrcPort,
			&r.DstIP, &r.DstPort, &r.Protocol, &r.Note,
			&r.FirstSeen, &r.LastSeen, &r.PacketCount, &r.TotalBytes); err != nil {
			return nil, err
		}
		items = append(items, map[string]interface{}{
			"id": r.ID, "capture_job_id": r.CaptureJobID,
			"iface": r.Iface, "src_ip": r.SrcIP, "src_port": r.SrcPort,
			"dst_ip": r.DstIP, "dst_port": r.DstPort,
			"protocol": r.Protocol, "note": r.Note,
			"first_seen": r.FirstSeen, "last_seen": r.LastSeen,
			"packet_count": r.PacketCount, "total_bytes": r.TotalBytes,
		})
	}

	return &model.PagedResult{
		Items: items, Total: total, Page: page, PageSize: pageSize, TotalPages: totalPages,
	}, nil
}

// QueryJobs returns the latest capture jobs.
func (s *Store) QueryJobs(limit int) ([]map[string]interface{}, error) {
	rows, err := s.DB.Query(`SELECT id, iface, window_seconds, bpf_filter,
		COALESCE(pcap_path,''), started_at, COALESCE(finished_at,''),
		packet_count, status, COALESCE(message,''),
		queue_name, analysis_status, COALESCE(worker_name,'')
		FROM capture_jobs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []map[string]interface{}
	for rows.Next() {
		var j model.CaptureJob
		if err := rows.Scan(&j.ID, &j.Iface, &j.WindowSeconds, &j.BPFFilter,
			&j.PcapPath, &j.StartedAt, &j.FinishedAt, &j.PacketCount,
			&j.Status, &j.Message, &j.QueueName, &j.AnalysisStatus, &j.WorkerName); err != nil {
			return nil, err
		}
		items = append(items, map[string]interface{}{
			"id": j.ID, "iface": j.Iface, "window_seconds": j.WindowSeconds,
			"bpf_filter": j.BPFFilter, "pcap_path": j.PcapPath,
			"started_at": j.StartedAt, "finished_at": j.FinishedAt,
			"packet_count": j.PacketCount, "status": j.Status,
			"message": j.Message, "queue_name": j.QueueName,
			"analysis_status": j.AnalysisStatus, "worker_name": j.WorkerName,
		})
	}
	return items, nil
}

// QueryAllTargetRules returns all target rules grouped by vendor.
func (s *Store) QueryAllTargetRules() ([]map[string]interface{}, error) {
	rows, err := s.DB.Query(`SELECT id, vendor, domain_pattern, match_type, source, enabled
		FROM target_rules ORDER BY vendor, domain_pattern`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	vendorMap := make(map[string][]map[string]interface{})
	var vendorOrder []string
	for rows.Next() {
		var id int64
		var vendor, domainPattern, matchType, source string
		var enabled int
		if err := rows.Scan(&id, &vendor, &domainPattern, &matchType, &source, &enabled); err != nil {
			return nil, err
		}
		if _, exists := vendorMap[vendor]; !exists {
			vendorOrder = append(vendorOrder, vendor)
		}
		vendorMap[vendor] = append(vendorMap[vendor], map[string]interface{}{
			"id": id, "domain_pattern": domainPattern,
			"match_type": matchType, "source": source, "enabled": enabled,
		})
	}

	var result []map[string]interface{}
	for _, v := range vendorOrder {
		result = append(result, map[string]interface{}{
			"vendor":  v,
			"domains": vendorMap[v],
		})
	}
	return result, nil
}

// AddTargetRules adds target rules for a vendor.
func (s *Store) AddTargetRules(vendor string, domains []string, matchType string) error {
	now := model.NowLocalText()
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT INTO target_rules (vendor, domain_pattern, match_type, source, enabled, created_at, updated_at)
		VALUES (?, ?, ?, 'custom', 1, ?, ?)
		ON DUPLICATE KEY UPDATE updated_at = VALUES(updated_at)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, d := range domains {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if _, err := stmt.Exec(vendor, d, matchType, now, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// helper: build WHERE clause for api_logs
func buildLogFilters(vendor, search, channelClass string, timeWindowMinutes int) (string, []interface{}) {
	var clauses []string
	var args []interface{}

	if vendor != "" {
		clauses = append(clauses, "vendor = ?")
		args = append(args, vendor)
	}
	if search != "" {
		clauses = append(clauses, "(domain LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ? OR vendor LIKE ?)")
		s := "%" + search + "%"
		args = append(args, s, s, s, s)
	}
	if timeWindowMinutes > 0 {
		cutoff := time.Now().UTC().Add(8 * time.Hour).Add(-time.Duration(timeWindowMinutes) * time.Minute).Format("2006-01-02 15:04:05")
		clauses = append(clauses, "last_seen >= ?")
		args = append(args, cutoff)
	}

	if len(clauses) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

func buildRequestLogFilters(vendor, search string, timeWindowMinutes int) (string, []interface{}) {
	var clauses []string
	var args []interface{}

	if vendor != "" {
		clauses = append(clauses, "vendor = ?")
		args = append(args, vendor)
	}
	if search != "" {
		clauses = append(clauses, "(domain LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ?)")
		s := "%" + search + "%"
		args = append(args, s, s, s)
	}
	if timeWindowMinutes > 0 {
		cutoff := time.Now().UTC().Add(8 * time.Hour).Add(-time.Duration(timeWindowMinutes) * time.Minute).Format("2006-01-02 15:04:05")
		clauses = append(clauses, "seen_at >= ?")
		args = append(args, cutoff)
	}

	if len(clauses) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

func buildTransportFilters(srcIP, protocol, search string, timeWindowMinutes int) (string, []interface{}) {
	var clauses []string
	var args []interface{}

	if srcIP != "" {
		clauses = append(clauses, "src_ip = ?")
		args = append(args, srcIP)
	}
	if protocol != "" {
		clauses = append(clauses, "protocol = ?")
		args = append(args, protocol)
	}
	if search != "" {
		clauses = append(clauses, "(src_ip LIKE ? OR dst_ip LIKE ? OR note LIKE ?)")
		s := "%" + search + "%"
		args = append(args, s, s, s)
	}
	if timeWindowMinutes > 0 {
		cutoff := time.Now().UTC().Add(8 * time.Hour).Add(-time.Duration(timeWindowMinutes) * time.Minute).Format("2006-01-02 15:04:05")
		clauses = append(clauses, "last_seen >= ?")
		args = append(args, cutoff)
	}

	if len(clauses) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

func sessionToMap(s *model.Session) map[string]interface{} {
	return map[string]interface{}{
		"capture_job_id": s.CaptureJobID,
		"iface":          s.Iface,
		"src_ip":         s.SrcIP,
		"src_port":       s.SrcPort,
		"dst_ip":         s.DstIP,
		"dst_port":       s.DstPort,
		"first_seen":     s.FirstSeen,
		"vendor":         s.Vendor,
		"domain":         s.Domain,
		"uplink_bytes":   s.UplinkBytes,
		"downlink_bytes": s.DownlinkBytes,
		"total_bytes":    s.TotalBytes,
		"request_count":  s.RequestCount,
		"packet_count":   s.PacketCount,
		"session_key":    s.SessionKey,
		"last_seen":      s.LastSeen,
		"updated_at":     s.UpdatedAt,
		"closed_at":      s.ClosedAt,
		"status":         s.Status,
	}
}
