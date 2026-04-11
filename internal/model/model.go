package model

import "time"

// Session represents a TCP session tracked by the monitor (maps to api_logs table).
type Session struct {
	SessionKey   string `json:"session_key" db:"session_key"`
	CaptureJobID int64  `json:"capture_job_id" db:"capture_job_id"`
	Iface        string `json:"iface" db:"iface"`
	SrcIP        string `json:"src_ip" db:"src_ip"`
	SrcPort      int    `json:"src_port" db:"src_port"`
	DstIP        string `json:"dst_ip" db:"dst_ip"`
	DstPort      int    `json:"dst_port" db:"dst_port"`
	Vendor       string `json:"vendor" db:"vendor"`
	Domain       string `json:"domain" db:"domain"`
	FirstSeen    string `json:"first_seen" db:"first_seen"`
	LastSeen     string `json:"last_seen" db:"last_seen"`
	UpdatedAt    string `json:"updated_at" db:"updated_at"`
	ClosedAt     string `json:"closed_at,omitempty" db:"closed_at"`
	Status       string `json:"status" db:"status"`
	UplinkBytes  int64  `json:"uplink_bytes" db:"uplink_bytes"`
	DownlinkBytes int64 `json:"downlink_bytes" db:"downlink_bytes"`
	TotalBytes   int64  `json:"total_bytes" db:"total_bytes"`
	RequestCount int    `json:"request_count" db:"request_count"`
	PacketCount  int    `json:"packet_count" db:"packet_count"`

	// internal fields (not persisted directly)
	FirstSeenEpoch float64 `json:"-"`
	LastSeenEpoch  float64 `json:"-"`
	PendingRequest *RequestLog `json:"-"`
}

// RequestLog represents a single request within a session (maps to request_logs table).
type RequestLog struct {
	ID            int64  `json:"id,omitempty" db:"id"`
	CaptureJobID  int64  `json:"capture_job_id" db:"capture_job_id"`
	RequestKey    string `json:"request_key" db:"request_key"`
	SessionKey    string `json:"session_key" db:"session_key"`
	Iface         string `json:"iface" db:"iface"`
	SrcIP         string `json:"src_ip" db:"src_ip"`
	SrcPort       int    `json:"src_port" db:"src_port"`
	DstIP         string `json:"dst_ip" db:"dst_ip"`
	DstPort       int    `json:"dst_port" db:"dst_port"`
	SeenAt        string `json:"seen_at" db:"seen_at"`
	Vendor        string `json:"vendor" db:"vendor"`
	Domain        string `json:"domain" db:"domain"`
	UplinkBytes   int64  `json:"uplink_bytes" db:"uplink_bytes"`
	DownlinkBytes int64  `json:"downlink_bytes" db:"downlink_bytes"`
	TotalBytes    int64  `json:"total_bytes" db:"total_bytes"`
	RequestCount  int    `json:"request_count" db:"request_count"`
}

// TransportEvent represents a low-level transport event (maps to transport_events table).
type TransportEvent struct {
	ID           int64  `json:"id,omitempty" db:"id"`
	CaptureJobID int64  `json:"capture_job_id" db:"capture_job_id"`
	Iface        string `json:"iface" db:"iface"`
	SrcIP        string `json:"src_ip" db:"src_ip"`
	SrcPort      int    `json:"src_port" db:"src_port"`
	DstIP        string `json:"dst_ip" db:"dst_ip"`
	DstPort      int    `json:"dst_port" db:"dst_port"`
	Protocol     string `json:"protocol" db:"protocol"`
	Note         string `json:"note,omitempty" db:"note"`
	FirstSeen    string `json:"first_seen" db:"first_seen"`
	LastSeen     string `json:"last_seen" db:"last_seen"`
	PacketCount  int    `json:"packet_count" db:"packet_count"`
	TotalBytes   int64  `json:"total_bytes" db:"total_bytes"`
}

// CaptureJob represents a pcap capture/parse job (maps to capture_jobs table).
type CaptureJob struct {
	ID                 int64  `json:"id" db:"id"`
	Iface              string `json:"iface" db:"iface"`
	WindowSeconds      int    `json:"window_seconds" db:"window_seconds"`
	BPFFilter          string `json:"bpf_filter" db:"bpf_filter"`
	PcapPath           string `json:"pcap_path" db:"pcap_path"`
	StartedAt          string `json:"started_at" db:"started_at"`
	FinishedAt         string `json:"finished_at,omitempty" db:"finished_at"`
	PacketCount        int    `json:"packet_count" db:"packet_count"`
	Status             string `json:"status" db:"status"`
	Message            string `json:"message,omitempty" db:"message"`
	QueueName          string `json:"queue_name" db:"queue_name"`
	AnalysisStatus     string `json:"analysis_status" db:"analysis_status"`
	AnalysisFinishedAt string `json:"analysis_finished_at,omitempty" db:"analysis_finished_at"`
	ResultPath         string `json:"result_path,omitempty" db:"result_path"`
	WorkerName         string `json:"worker_name,omitempty" db:"worker_name"`
}

// TargetRule represents a domain matching rule (maps to target_rules table).
type TargetRule struct {
	ID            int64  `json:"id" db:"id"`
	Vendor        string `json:"vendor" db:"vendor"`
	DomainPattern string `json:"domain_pattern" db:"domain_pattern"`
	MatchType     string `json:"match_type" db:"match_type"`
	Source        string `json:"source" db:"source"`
	Enabled       int    `json:"enabled" db:"enabled"`
	CreatedAt     string `json:"created_at" db:"created_at"`
	UpdatedAt     string `json:"updated_at" db:"updated_at"`
}

// PacketEvent is a parsed packet from a pcap file.
type PacketEvent struct {
	Epoch    float64 `json:"epoch"`
	SrcIP    string  `json:"src_ip"`
	SrcPort  int     `json:"src_port"`
	DstIP    string  `json:"dst_ip"`
	DstPort  int     `json:"dst_port"`
	Length   int     `json:"length"`
	Protocol string  `json:"protocol"` // "tcp" or "udp"
	IsClose  bool    `json:"is_close"` // TCP FIN or RST
}

// ParseResult holds the result of parsing a single pcap file.
type ParseResult struct {
	PcapPath        string              `json:"pcap_path"`
	PacketCount     int                 `json:"packet_count"`
	PacketEvents    []PacketEvent       `json:"packet_events"`
	PayloadHints    map[FlowKey]string  `json:"payload_hints"`
	StartedAt       string              `json:"started_at"`
	FinishedAt      string              `json:"finished_at"`
	LastEpoch       float64             `json:"last_epoch"`
	JobID           int64               `json:"job_id"`
	QueueName       string              `json:"queue_name"`
	WorkerName      string              `json:"worker_name"`
}

// MergeResult holds the result of merging parsed packets into sessions.
type MergeResult struct {
	PacketCount     int
	TouchedSessions map[string]bool
	RequestLogs     []*RequestLog
	TransportEvents []*TransportEvent
	StartedAt       string
	FinishedAt      string
	LastEpoch       float64
}

// FlowKey uniquely identifies a network flow.
type FlowKey struct {
	SrcIP   string
	SrcPort int
	DstIP   string
	DstPort int
}

// Reverse returns the reverse direction flow key.
func (fk FlowKey) Reverse() FlowKey {
	return FlowKey{SrcIP: fk.DstIP, SrcPort: fk.DstPort, DstIP: fk.SrcIP, DstPort: fk.SrcPort}
}

// PagedResult is a generic paginated response.
type PagedResult struct {
	Items      interface{} `json:"items"`
	Total      int         `json:"total"`
	Page       int         `json:"page"`
	PageSize   int         `json:"page_size"`
	TotalPages int         `json:"total_pages"`
}

// StatusData represents the system status response.
type StatusData struct {
	Running         bool   `json:"running"`
	CaptureRunning  bool   `json:"capture_running"`
	ParserRunning   bool   `json:"parser_running"`
	Iface           string `json:"iface"`
	WindowSeconds   int    `json:"window_seconds"`
	BPFFilter       string `json:"bpf_filter"`
	PendingSegments int    `json:"pending_segments"`
	RetainParsedPcap bool  `json:"retain_parsed_pcap"`
	LastJobID       int64  `json:"last_job_id"`
	ActiveSessions  int    `json:"active_sessions"`
	Uptime          string `json:"uptime"`
	StartedAt       string `json:"started_at"`
}

// NowLocalText returns the current time formatted as "YYYY-MM-DD HH:MM:SS" in UTC+8.
func NowLocalText() string {
	return time.Now().UTC().Add(8 * time.Hour).Format("2006-01-02 15:04:05")
}

// EpochToLocalText converts a Unix epoch to "YYYY-MM-DD HH:MM:SS" in UTC+8.
func EpochToLocalText(epoch float64) string {
	t := time.Unix(int64(epoch), int64((epoch-float64(int64(epoch)))*1e9))
	return t.UTC().Add(8 * time.Hour).Format("2006-01-02 15:04:05")
}
