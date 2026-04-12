package api

import (
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"
)

// IPUserEntry represents a single IP→user mapping.
type IPUserEntry struct {
	Hostname   string `json:"hostname"`
	Username   string `json:"username"`
	Department string `json:"department"`
}

// IPUserMap provides IP→user lookups, auto-reloads from JSON file.
type IPUserMap struct {
	mu       sync.RWMutex
	entries  map[string]*IPUserEntry
	filePath string
	loadedAt time.Time
	modTime  time.Time
	ttl      time.Duration
}

// NewIPUserMap creates an IP-user mapper that reads from a JSON file.
func NewIPUserMap(filePath string) *IPUserMap {
	m := &IPUserMap{
		entries:  make(map[string]*IPUserEntry),
		filePath: filePath,
		ttl:      5 * time.Minute,
	}
	m.reload()
	return m
}

// Lookup returns the user entry for an IP, or nil if not found.
func (m *IPUserMap) Lookup(ip string) *IPUserEntry {
	m.maybeReload()
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.entries[ip]
}

// EnrichRow adds src_user/src_hostname/src_department to a map if src_ip is known.
func (m *IPUserMap) EnrichRow(row map[string]interface{}) {
	srcIP, _ := row["src_ip"].(string)
	if srcIP == "" {
		return
	}
	entry := m.Lookup(srcIP)
	if entry != nil {
		row["src_user"] = entry.Username
		row["src_hostname"] = entry.Hostname
		row["src_department"] = entry.Department
	} else {
		row["src_user"] = ""
		row["src_hostname"] = ""
		row["src_department"] = ""
	}
}

func (m *IPUserMap) maybeReload() {
	m.mu.RLock()
	stale := time.Since(m.loadedAt) > m.ttl
	m.mu.RUnlock()
	if !stale {
		return
	}

	info, err := os.Stat(m.filePath)
	if err != nil {
		return
	}
	m.mu.RLock()
	changed := info.ModTime() != m.modTime
	m.mu.RUnlock()
	if !changed {
		m.mu.Lock()
		m.loadedAt = time.Now()
		m.mu.Unlock()
		return
	}
	m.reload()
}

func (m *IPUserMap) reload() {
	data, err := os.ReadFile(m.filePath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[ipuser] failed to read %s: %v", m.filePath, err)
		}
		return
	}

	var entries map[string]*IPUserEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		log.Printf("[ipuser] failed to parse %s: %v", m.filePath, err)
		return
	}

	info, _ := os.Stat(m.filePath)
	m.mu.Lock()
	m.entries = entries
	m.loadedAt = time.Now()
	if info != nil {
		m.modTime = info.ModTime()
	}
	m.mu.Unlock()
	log.Printf("[ipuser] loaded %d IP-user mappings from %s", len(entries), m.filePath)
}
