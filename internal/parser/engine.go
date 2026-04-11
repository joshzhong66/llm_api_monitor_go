package parser

import (
	"fmt"
	"log"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"llm_api_monitor/internal/config"
	"llm_api_monitor/internal/model"
)

var (
	domainRE    = regexp.MustCompile(`([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}`)
	ignoreDomains = map[string]bool{
		"h2.http": true, "http.1.1": true, "spdy.3": true, "www.w3.org": true,
	}
)

// Engine handles pcap parsing, session tracking, and flow management.
type Engine struct {
	mu       sync.Mutex
	cfg      *config.Config
	matcher  *TargetMatcher
	sessions map[string]*model.Session
	flowMap  map[model.FlowKey]string // forward: (client→server) → session_key
	revMap   map[model.FlowKey]string // reverse: (server→client) → session_key
	ipHints  *IPHintCache
	lastJobID int64
}

// NewEngine creates a new parser engine.
func NewEngine(cfg *config.Config, matcher *TargetMatcher) *Engine {
	return &Engine{
		cfg:      cfg,
		matcher:  matcher,
		sessions: make(map[string]*model.Session),
		flowMap:  make(map[model.FlowKey]string),
		revMap:   make(map[model.FlowKey]string),
		ipHints:  NewIPHintCache(cfg.IPHintsCacheTTL),
	}
}

// SetMatcher atomically replaces the target matcher.
func (e *Engine) SetMatcher(m *TargetMatcher) {
	e.mu.Lock()
	e.matcher = m
	e.mu.Unlock()
}

// RebuildIPHints rebuilds the IP→domain hint cache from target rules.
func (e *Engine) RebuildIPHints(rules []model.TargetRule) {
	e.ipHints.Rebuild(rules)
}

// ActiveSessions returns the number of active sessions.
func (e *Engine) ActiveSessions() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.sessions)
}

// LastJobID returns the most recently processed job ID.
func (e *Engine) LastJobID() int64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.lastJobID
}

// RestoreSessions restores open sessions from DB (for writer daemon startup).
func (e *Engine) RestoreSessions(openSessions []*model.Session) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, s := range openSessions {
		e.sessions[s.SessionKey] = s
		fk := model.FlowKey{SrcIP: s.SrcIP, SrcPort: s.SrcPort, DstIP: s.DstIP, DstPort: s.DstPort}
		e.flowMap[fk] = s.SessionKey
		e.revMap[fk.Reverse()] = s.SessionKey
	}
	log.Printf("[parser] restored %d open sessions", len(openSessions))
}

// ParsePcap parses a pcap file using gopacket — single pass, no tcpdump subprocess.
// Returns packet events and payload hints in one traversal.
func (e *Engine) ParsePcap(pcapPath string) (*model.ParseResult, error) {
	handle, err := pcap.OpenOffline(pcapPath)
	if err != nil {
		return nil, fmt.Errorf("open pcap %s: %w", pcapPath, err)
	}
	defer handle.Close()

	result := &model.ParseResult{
		PcapPath:     pcapPath,
		PayloadHints: make(map[model.FlowKey]string),
	}

	var firstEpoch, lastEpoch float64
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.Lazy = true
	packetSource.NoCopy = true

	for packet := range packetSource.Packets() {
		meta := packet.Metadata()
		if meta == nil {
			continue
		}
		epoch := float64(meta.Timestamp.UnixNano()) / 1e9
		if firstEpoch == 0 {
			firstEpoch = epoch
		}
		lastEpoch = epoch

		// Extract network layer
		networkLayer := packet.NetworkLayer()
		if networkLayer == nil {
			continue
		}
		var srcIP, dstIP string
		if ipv4, ok := networkLayer.(*layers.IPv4); ok {
			srcIP = ipv4.SrcIP.String()
			dstIP = ipv4.DstIP.String()
		} else {
			continue // skip non-IPv4
		}

		// Extract transport layer
		var srcPort, dstPort int
		var protocol string
		var isClose bool
		var payloadLen int

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP)
			srcPort = int(tcp.SrcPort)
			dstPort = int(tcp.DstPort)
			protocol = "tcp"
			isClose = tcp.FIN || tcp.RST
			if tcp.PSH || len(tcp.Payload) > 0 {
				payloadLen = len(tcp.Payload)
			}

			// Extract domain from TLS ClientHello SNI (single-pass hint extraction)
			if dstPort == 443 && payloadLen > 0 {
				fk := model.FlowKey{SrcIP: srcIP, SrcPort: srcPort, DstIP: dstIP, DstPort: dstPort}
				if _, exists := result.PayloadHints[fk]; !exists {
					if domain := extractSNI(tcp.Payload); domain != "" {
						result.PayloadHints[fk] = domain
					} else if domain := extractDomainFromPayload(tcp.Payload); domain != "" {
						result.PayloadHints[fk] = domain
					}
				}
			}
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp := udpLayer.(*layers.UDP)
			srcPort = int(udp.SrcPort)
			dstPort = int(udp.DstPort)
			protocol = "udp"
			payloadLen = len(udp.Payload)
		} else {
			continue
		}

		// Only track port 443 traffic
		if srcPort != 443 && dstPort != 443 {
			continue
		}

		// Calculate packet length from IP layer total length
		pktLen := payloadLen
		if pktLen == 0 {
			// Use total IP length minus headers as approximation
			if nl := packet.NetworkLayer(); nl != nil {
				pktLen = len(nl.LayerPayload())
			}
		}

		event := model.PacketEvent{
			Epoch:    epoch,
			SrcIP:    srcIP,
			SrcPort:  srcPort,
			DstIP:    dstIP,
			DstPort:  dstPort,
			Length:   pktLen,
			Protocol: protocol,
			IsClose:  isClose,
		}
		result.PacketEvents = append(result.PacketEvents, event)
		result.PacketCount++
	}

	result.LastEpoch = lastEpoch
	if firstEpoch > 0 {
		result.StartedAt = model.EpochToLocalText(firstEpoch)
	}
	if lastEpoch > 0 {
		result.FinishedAt = model.EpochToLocalText(lastEpoch)
	}
	return result, nil
}

// MergeResult merges parsed packet events into sessions and produces DB-ready data.
func (e *Engine) MergeResult(parsed *model.ParseResult, jobID int64) *model.MergeResult {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.lastJobID = jobID
	now := model.NowLocalText()
	touched := make(map[string]bool)
	requestLogs := make(map[string]*model.RequestLog)
	var transportEvents []*model.TransportEvent

	for i := range parsed.PacketEvents {
		evt := &parsed.PacketEvents[i]

		if evt.Protocol == "udp" {
			if evt.SrcPort == 443 || evt.DstPort == 443 {
				te := e.recordTransportEvent(evt, now)
				if te != nil {
					transportEvents = append(transportEvents, te)
				}
			}
			continue
		}

		// TCP flow lookup
		fk := model.FlowKey{SrcIP: evt.SrcIP, SrcPort: evt.SrcPort, DstIP: evt.DstIP, DstPort: evt.DstPort}
		revFK := fk.Reverse()

		sessionKey := e.flowMap[fk]
		if sessionKey == "" {
			sessionKey = e.revMap[fk]
		}

		if sessionKey == "" && (evt.SrcPort == 443 || evt.DstPort == 443) {
			// Try to identify and register session
			domain, vendor := e.lookupRegistrationHint(evt, parsed.PayloadHints)
			if domain != "" && vendor != "" {
				sessionKey = e.registerSession(evt, domain, vendor, now)
			}
		}

		if sessionKey == "" {
			continue
		}

		session := e.sessions[sessionKey]
		if session == nil {
			continue
		}

		// Apply packet to session
		e.applyPacket(session, evt, requestLogs, now)
		touched[sessionKey] = true

		if evt.IsClose {
			session.Status = "closed"
			session.ClosedAt = model.EpochToLocalText(evt.Epoch)
			session.UpdatedAt = now
			touched[sessionKey] = true
		}

		_ = revFK // suppress unused warning
	}

	// Collect request logs as slice
	var rlSlice []*model.RequestLog
	for _, rl := range requestLogs {
		rlSlice = append(rlSlice, rl)
	}

	result := &model.MergeResult{
		PacketCount:     parsed.PacketCount,
		TouchedSessions: touched,
		RequestLogs:     rlSlice,
		TransportEvents: transportEvents,
		StartedAt:       parsed.StartedAt,
		FinishedAt:      parsed.FinishedAt,
		LastEpoch:       parsed.LastEpoch,
	}

	return result
}

// GetTouchedSessions returns session data for the given session keys.
func (e *Engine) GetTouchedSessions(keys map[string]bool) []*model.Session {
	e.mu.Lock()
	defer e.mu.Unlock()

	var result []*model.Session
	for k := range keys {
		if s, ok := e.sessions[k]; ok {
			result = append(result, s)
		}
	}
	return result
}

// ExpireIdleSessions closes sessions that have been idle too long.
func (e *Engine) ExpireIdleSessions(currentEpoch float64) []*model.Session {
	e.mu.Lock()
	defer e.mu.Unlock()

	idleThreshold := float64(e.cfg.IdleSessionSeconds)
	var expired []*model.Session
	now := model.NowLocalText()

	for key, session := range e.sessions {
		lastEpoch := session.LastSeenEpoch
		if lastEpoch == 0 {
			lastEpoch = session.FirstSeenEpoch
		}
		if currentEpoch-lastEpoch < idleThreshold {
			continue
		}

		session.Status = "closed"
		if session.ClosedAt == "" {
			session.ClosedAt = model.EpochToLocalText(lastEpoch)
		}
		session.UpdatedAt = now
		expired = append(expired, session)

		fk := model.FlowKey{SrcIP: session.SrcIP, SrcPort: session.SrcPort, DstIP: session.DstIP, DstPort: session.DstPort}
		if e.flowMap[fk] == key {
			delete(e.flowMap, fk)
		}
		revFK := fk.Reverse()
		if e.revMap[revFK] == key {
			delete(e.revMap, revFK)
		}
		delete(e.sessions, key)
	}

	return expired
}

func (e *Engine) registerSession(evt *model.PacketEvent, domain, vendor, now string) string {
	// Ensure client side is src (client→server: dst_port=443)
	srcIP, srcPort, dstIP, dstPort := evt.SrcIP, evt.SrcPort, evt.DstIP, evt.DstPort
	if evt.SrcPort == 443 {
		srcIP, srcPort, dstIP, dstPort = evt.DstIP, evt.DstPort, evt.SrcIP, evt.SrcPort
	}

	sessionKey := fmt.Sprintf("%s|%s|%d|%s|%d|%s|%d",
		e.cfg.Iface, srcIP, srcPort, dstIP, dstPort, domain, int(evt.Epoch))

	session := &model.Session{
		SessionKey:    sessionKey,
		Iface:         e.cfg.Iface,
		SrcIP:         srcIP,
		SrcPort:       srcPort,
		DstIP:         dstIP,
		DstPort:       dstPort,
		Vendor:        vendor,
		Domain:        domain,
		FirstSeen:     model.EpochToLocalText(evt.Epoch),
		LastSeen:      model.EpochToLocalText(evt.Epoch),
		UpdatedAt:     now,
		Status:        "open",
		FirstSeenEpoch: evt.Epoch,
		LastSeenEpoch:  evt.Epoch,
	}

	e.sessions[sessionKey] = session
	fk := model.FlowKey{SrcIP: srcIP, SrcPort: srcPort, DstIP: dstIP, DstPort: dstPort}
	e.flowMap[fk] = sessionKey
	e.revMap[fk.Reverse()] = sessionKey

	return sessionKey
}

func (e *Engine) applyPacket(session *model.Session, evt *model.PacketEvent, requestLogs map[string]*model.RequestLog, now string) {
	session.PacketCount++
	session.LastSeen = model.EpochToLocalText(evt.Epoch)
	session.LastSeenEpoch = evt.Epoch
	session.UpdatedAt = now

	if evt.DstPort == 443 {
		// Uplink (client → server)
		session.UplinkBytes += int64(evt.Length)
		session.TotalBytes += int64(evt.Length)
		if evt.Length > 0 {
			session.RequestCount++
			reqKey := fmt.Sprintf("%s#%d", session.SessionKey, session.RequestCount)
			rl := &model.RequestLog{
				RequestKey:    reqKey,
				SessionKey:    session.SessionKey,
				Iface:         session.Iface,
				SrcIP:         session.SrcIP,
				SrcPort:       session.SrcPort,
				DstIP:         session.DstIP,
				DstPort:       session.DstPort,
				SeenAt:        model.EpochToLocalText(evt.Epoch),
				Vendor:        session.Vendor,
				Domain:        session.Domain,
				UplinkBytes:   int64(evt.Length),
				RequestCount:  1,
			}
			requestLogs[reqKey] = rl
			session.PendingRequest = rl
		}
	} else {
		// Downlink (server → client)
		session.DownlinkBytes += int64(evt.Length)
		session.TotalBytes += int64(evt.Length)
		if session.PendingRequest != nil && evt.Length > 0 {
			session.PendingRequest.DownlinkBytes += int64(evt.Length)
			session.PendingRequest.TotalBytes = session.PendingRequest.UplinkBytes + session.PendingRequest.DownlinkBytes
		}
	}
}

func (e *Engine) lookupRegistrationHint(evt *model.PacketEvent, payloadHints map[model.FlowKey]string) (domain, vendor string) {
	// 1. Check payload hints
	fk := model.FlowKey{SrcIP: evt.SrcIP, SrcPort: evt.SrcPort, DstIP: evt.DstIP, DstPort: evt.DstPort}
	if d, ok := payloadHints[fk]; ok {
		if v := e.matcher.Match(d); v != "" {
			return d, v
		}
	}

	// 2. Check reverse (for server→client packets)
	revFK := fk.Reverse()
	if d, ok := payloadHints[revFK]; ok {
		if v := e.matcher.Match(d); v != "" {
			return d, v
		}
	}

	// 3. Check IP hints
	targetIP := evt.DstIP
	if evt.SrcPort == 443 {
		targetIP = evt.SrcIP
	}
	if hint := e.ipHints.Lookup(targetIP); hint != nil {
		return hint.Domain, hint.Vendor
	}

	return "", ""
}

func (e *Engine) recordTransportEvent(evt *model.PacketEvent, now string) *model.TransportEvent {
	note := "udp/443"
	if evt.Protocol == "tcp" {
		note = "tcp/443"
	}
	return &model.TransportEvent{
		Iface:       e.cfg.Iface,
		SrcIP:       evt.SrcIP,
		SrcPort:     evt.SrcPort,
		DstIP:       evt.DstIP,
		DstPort:     evt.DstPort,
		Protocol:    evt.Protocol,
		Note:        note,
		FirstSeen:   model.EpochToLocalText(evt.Epoch),
		LastSeen:    model.EpochToLocalText(evt.Epoch),
		PacketCount: 1,
		TotalBytes:  int64(evt.Length),
	}
}

// extractSNI extracts the Server Name Indication from a TLS ClientHello.
func extractSNI(payload []byte) string {
	if len(payload) < 6 {
		return ""
	}
	// TLS record: ContentType=0x16 (Handshake), Version, Length
	if payload[0] != 0x16 {
		return ""
	}
	// Skip TLS record header (5 bytes)
	// Handshake type 0x01 = ClientHello
	if len(payload) < 6 || payload[5] != 0x01 {
		return ""
	}

	// Parse ClientHello to find SNI extension
	pos := 5 + 4 // skip record header + handshake header (type + 3-byte length)
	if pos+2 > len(payload) {
		return ""
	}
	// Skip client version (2 bytes)
	pos += 2
	// Skip client random (32 bytes)
	pos += 32
	if pos+1 > len(payload) {
		return ""
	}
	// Skip session ID
	sessionIDLen := int(payload[pos])
	pos += 1 + sessionIDLen
	if pos+2 > len(payload) {
		return ""
	}
	// Skip cipher suites
	cipherLen := int(payload[pos])<<8 | int(payload[pos+1])
	pos += 2 + cipherLen
	if pos+1 > len(payload) {
		return ""
	}
	// Skip compression methods
	compLen := int(payload[pos])
	pos += 1 + compLen
	if pos+2 > len(payload) {
		return ""
	}
	// Extensions length
	extLen := int(payload[pos])<<8 | int(payload[pos+1])
	pos += 2
	endPos := pos + extLen
	if endPos > len(payload) {
		endPos = len(payload)
	}

	// Parse extensions to find SNI (type 0x0000)
	for pos+4 <= endPos {
		extType := int(payload[pos])<<8 | int(payload[pos+1])
		extDataLen := int(payload[pos+2])<<8 | int(payload[pos+3])
		pos += 4
		if extType == 0 && pos+extDataLen <= endPos {
			// SNI extension
			sniData := payload[pos : pos+extDataLen]
			if len(sniData) >= 5 {
				// Skip SNI list length (2 bytes), type (1 byte = 0x00 for hostname)
				nameLen := int(sniData[3])<<8 | int(sniData[4])
				if 5+nameLen <= len(sniData) {
					return string(sniData[5 : 5+nameLen])
				}
			}
			break
		}
		pos += extDataLen
	}
	return ""
}

// extractDomainFromPayload tries to find a domain in raw payload text (fallback).
func extractDomainFromPayload(payload []byte) string {
	// Quick check: look for domain patterns in ASCII text
	text := string(payload)
	matches := domainRE.FindAllString(text, 5)
	for _, m := range matches {
		m = strings.ToLower(m)
		if ignoreDomains[m] {
			continue
		}
		// Basic validation
		if strings.Contains(m, ".") && len(m) > 4 {
			return m
		}
	}
	return ""
}

// IPHintCache caches IP→(domain, vendor) lookups.
type IPHintCache struct {
	mu    sync.RWMutex
	hints map[string]*IPHint
	ttl   time.Duration
	built time.Time
}

type IPHint struct {
	Domain string
	Vendor string
}

func NewIPHintCache(ttl time.Duration) *IPHintCache {
	return &IPHintCache{
		hints: make(map[string]*IPHint),
		ttl:   ttl,
	}
}

func (c *IPHintCache) Lookup(ip string) *IPHint {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.hints[ip]
}

// Rebuild rebuilds the IP hint cache by resolving target rule domains.
func (c *IPHintCache) Rebuild(rules []model.TargetRule) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if time.Since(c.built) < c.ttl {
		return
	}

	hints := make(map[string]*IPHint)
	for _, r := range rules {
		if r.MatchType != "exact" || strings.Contains(r.DomainPattern, "*") {
			continue
		}
		ips, err := net.LookupHost(r.DomainPattern)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			hints[ip] = &IPHint{Domain: r.DomainPattern, Vendor: r.Vendor}
		}
	}
	c.hints = hints
	c.built = time.Now()
	log.Printf("[parser] rebuilt IP hint cache: %d IPs from %d rules", len(hints), len(rules))
}
