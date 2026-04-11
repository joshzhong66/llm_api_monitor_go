package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"llm_api_monitor/internal/api"
	"llm_api_monitor/internal/capture"
	"llm_api_monitor/internal/config"
	"llm_api_monitor/internal/db"
	"llm_api_monitor/internal/model"
	"llm_api_monitor/internal/parser"
	"llm_api_monitor/internal/writer"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("LLM API Monitor (Go) starting...")

	// Load config from .env in current working directory
	cwd, _ := os.Getwd()
	envPath := filepath.Join(cwd, ".env")

	cfg := config.Load(envPath)

	// Resolve relative paths against cwd
	if !filepath.IsAbs(cfg.DataDir) {
		cfg.DataDir = filepath.Join(cwd, cfg.DataDir)
	}
	if !filepath.IsAbs(cfg.LogDir) {
		cfg.LogDir = filepath.Join(cwd, cfg.LogDir)
	}
	if !filepath.IsAbs(cfg.CaptureDir) {
		cfg.CaptureDir = filepath.Join(cwd, cfg.CaptureDir)
	}
	if !filepath.IsAbs(cfg.StaticDir) {
		cfg.StaticDir = filepath.Join(cwd, cfg.StaticDir)
	}
	if !filepath.IsAbs(cfg.PricingXLSXPath) {
		cfg.PricingXLSXPath = filepath.Join(cwd, cfg.PricingXLSXPath)
	}

	// Ensure directories
	for _, dir := range []string{cfg.DataDir, cfg.LogDir, cfg.CaptureDir} {
		_ = os.MkdirAll(dir, 0755)
	}

	log.Printf("config: iface=%s window=%ds workers=%d bpf=%q",
		cfg.Iface, cfg.WindowSeconds, cfg.RealtimeWorkers, cfg.BPFFilter)
	log.Printf("config: mysql=%s:%d/%s redis=%s:%d capture_dir=%s",
		cfg.MySQL.Host, cfg.MySQL.Port, cfg.MySQL.Database,
		cfg.Redis.Host, cfg.Redis.Port, cfg.CaptureDir)

	// Connect to databases
	store, err := db.New(cfg)
	if err != nil {
		log.Fatalf("database connection failed: %v", err)
	}
	defer store.Close()

	// Load pricing catalog from XLSX
	api.LoadPricingCatalog(cfg.PricingXLSXPath)

	// Initialize schema
	if err := store.InitDB(); err != nil {
		log.Fatalf("database init failed: %v", err)
	}

	// Seed default target rules if table is empty
	seedDefaultTargetRules(store)

	// Load target matcher
	rules, err := store.LoadTargetRules()
	if err != nil {
		log.Fatalf("load target rules: %v", err)
	}
	matcher := parser.NewTargetMatcher(rules)
	exactCount := 0
	for _, r := range rules {
		if r.MatchType == "exact" {
			exactCount++
		}
	}
	log.Printf("loaded %d target rules (%d exact, %d wildcard)",
		len(rules), exactCount, len(rules)-exactCount)

	// Create parser engine
	engine := parser.NewEngine(cfg, matcher)

	// Restore open sessions from DB
	openSessions, err := store.LoadOpenSessions()
	if err != nil {
		log.Printf("[warn] restore sessions failed: %v", err)
	} else {
		engine.RestoreSessions(openSessions)
	}

	// Build IP hint cache
	engine.RebuildIPHints(rules)

	// Setup channels
	taskCh := make(chan *capture.Task, 1000)
	resultCh := make(chan *writer.WorkerResult, 500)

	// Context with signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("received signal %v, shutting down...", sig)
		cancel()
	}()

	// Start all components concurrently

	// 1. Parser worker pool (N goroutines reading tasks, writing results)
	workerPool := writer.NewWorkerPool(cfg, engine, store, taskCh, resultCh, cfg.RealtimeWorkers)
	go workerPool.Run(ctx)

	// 2. Writer daemon (reads results, merges into sessions, writes to DB)
	writerDaemon := writer.NewDaemon(cfg, store, engine, resultCh)
	go func() {
		if err := writerDaemon.Run(ctx); err != nil {
			log.Printf("[writer] fatal: %v", err)
		}
	}()

	// 3. Capture daemon (runs tcpdump, produces tasks)
	if cfg.Autostart {
		captureDaemon := capture.NewDaemon(cfg, taskCh)
		go func() {
			if err := captureDaemon.Run(ctx); err != nil && ctx.Err() == nil {
				log.Printf("[capture] fatal: %v", err)
			}
		}()
	}

	// 4. HTTP API server
	apiServer := api.NewServer(cfg, store, engine)
	go func() {
		if err := apiServer.ListenAndServe(); err != nil {
			if ctx.Err() == nil {
				log.Fatalf("[api] server error: %v", err)
			}
		}
	}()

	log.Printf("all components started, serving on %s:%d", cfg.Host, cfg.Port)

	// Block until shutdown signal
	<-ctx.Done()
	log.Printf("shutdown complete")
}

func seedDefaultTargetRules(store *db.Store) {
	existing, err := store.LoadTargetRules()
	if err != nil {
		log.Printf("[warn] check target rules: %v", err)
		return
	}
	if len(existing) > 0 {
		return
	}
	defaults := parser.DefaultTargetRules()
	log.Printf("seeding %d default target rules...", len(defaults))
	for _, r := range defaults {
		_ = store.AddTargetRules(r.Vendor, []string{r.DomainPattern}, r.MatchType)
	}
}

// ensure model is imported (used by other packages, needed for go mod tidy)
var _ = model.NowLocalText
