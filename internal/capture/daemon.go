package capture

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"llm_api_monitor/internal/config"
)

// Task represents a pcap file ready for parsing.
type Task struct {
	PcapPath      string
	JobID         int64
	QueueName     string
	Iface         string
	WindowSeconds int
	BPFFilter     string
}

// Daemon manages tcpdump capture and produces parse tasks.
type Daemon struct {
	cfg        *config.Config
	taskChan   chan<- *Task
	mu         sync.Mutex
	captureDir string
	lastSeen   string
}

// NewDaemon creates a new capture daemon.
func NewDaemon(cfg *config.Config, taskChan chan<- *Task) *Daemon {
	return &Daemon{
		cfg:        cfg,
		taskChan:   taskChan,
		captureDir: cfg.CaptureDir,
	}
}

// Run starts the capture loop. Blocks until ctx is cancelled.
func (d *Daemon) Run(ctx context.Context) error {
	if err := os.MkdirAll(d.captureDir, 0755); err != nil {
		return fmt.Errorf("create capture dir: %w", err)
	}

	log.Printf("[capture] starting tcpdump on %s, window=%ds, bpf=%q, dir=%s",
		d.cfg.Iface, d.cfg.WindowSeconds, d.cfg.BPFFilter, d.captureDir)

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := d.runCapture(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Printf("[capture] tcpdump error: %v, restarting in 3s", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(3 * time.Second):
			}
		}
	}
}

func (d *Daemon) runCapture(ctx context.Context) error {
	snaplen := d.cfg.Snaplen
	if snaplen == 0 {
		snaplen = 65535
	}

	args := []string{
		"--immediate-mode",
		"-i", d.cfg.Iface,
		"-s", fmt.Sprintf("%d", snaplen),
		"-nn",
		"-G", fmt.Sprintf("%d", d.cfg.WindowSeconds),
		"-w", filepath.Join(d.captureDir, "capture_%Y%m%d_%H%M%S.pcap"),
	}
	if d.cfg.BPFFilter != "" {
		args = append(args, d.cfg.BPFFilter)
	}

	cmd := exec.CommandContext(ctx, "tcpdump", args...)
	cmd.Stdout = nil
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start tcpdump: %w", err)
	}

	// Scan for completed pcap files while tcpdump runs
	ticker := time.NewTicker(time.Duration(d.cfg.QueuePollSeconds * float64(time.Second)))
	defer ticker.Stop()

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	for {
		select {
		case <-ctx.Done():
			_ = cmd.Process.Signal(os.Interrupt)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				_ = cmd.Process.Kill()
				<-done
			}
			d.enqueueCompleted(true)
			return nil

		case err := <-done:
			d.enqueueCompleted(true)
			return err

		case <-ticker.C:
			d.enqueueCompleted(false)
		}
	}
}

func (d *Daemon) enqueueCompleted(flushAll bool) {
	pattern := filepath.Join(d.captureDir, "capture_*.pcap")
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return
	}
	sort.Strings(matches)

	// Skip the newest file (still being written by tcpdump) unless flushing all
	end := len(matches)
	if !flushAll && end > 0 {
		end--
	}

	d.mu.Lock()
	lastSeen := d.lastSeen
	d.mu.Unlock()

	for i := 0; i < end; i++ {
		pcapPath := matches[i]
		base := filepath.Base(pcapPath)
		if base <= lastSeen {
			continue
		}

		// Check file is not empty
		info, err := os.Stat(pcapPath)
		if err != nil || info.Size() == 0 {
			continue
		}

		task := &Task{
			PcapPath:      pcapPath,
			QueueName:     "realtime",
			Iface:         d.cfg.Iface,
			WindowSeconds: d.cfg.WindowSeconds,
			BPFFilter:     d.cfg.BPFFilter,
		}

		select {
		case d.taskChan <- task:
			d.mu.Lock()
			d.lastSeen = base
			d.mu.Unlock()
		default:
			// Channel full, will retry next tick
			return
		}
	}
}

// SeedExisting finds unprocessed pcap files and sends them as backfill tasks.
func (d *Daemon) SeedExisting(processedPaths map[string]bool) {
	pattern := filepath.Join(d.captureDir, "capture_*.pcap")
	matches, _ := filepath.Glob(pattern)
	sort.Strings(matches)

	count := 0
	for _, pcapPath := range matches {
		absPath, _ := filepath.Abs(pcapPath)
		if processedPaths[absPath] {
			continue
		}
		info, err := os.Stat(pcapPath)
		if err != nil || info.Size() == 0 {
			continue
		}

		task := &Task{
			PcapPath:      pcapPath,
			QueueName:     "backfill",
			Iface:         d.cfg.Iface,
			WindowSeconds: d.cfg.WindowSeconds,
			BPFFilter:     d.cfg.BPFFilter,
		}
		d.taskChan <- task
		count++
	}
	if count > 0 {
		log.Printf("[capture] seeded %d backfill tasks from existing pcap files", count)
	}
}

// CleanProcessedPcaps removes pcap files that have been successfully processed.
func CleanProcessedPcaps(captureDir string, processedPaths map[string]bool, retain bool) int {
	if retain {
		return 0
	}
	removed := 0
	pattern := filepath.Join(captureDir, "capture_*.pcap")
	matches, _ := filepath.Glob(pattern)
	for _, pcapPath := range matches {
		absPath, _ := filepath.Abs(pcapPath)
		if processedPaths[absPath] {
			if err := os.Remove(pcapPath); err == nil {
				removed++
			}
		}
	}
	return removed
}

// PcapStartedAt extracts timestamp from pcap filename pattern capture_YYYYMMDD_HHMMSS.pcap
func PcapStartedAt(pcapPath string) string {
	base := filepath.Base(pcapPath)
	base = strings.TrimPrefix(base, "capture_")
	base = strings.TrimSuffix(base, ".pcap")
	if len(base) >= 15 { // YYYYMMDD_HHMMSS
		t, err := time.Parse("20060102_150405", base[:15])
		if err == nil {
			return t.Format("2006-01-02 15:04:05")
		}
	}
	return ""
}
