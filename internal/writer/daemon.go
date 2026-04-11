package writer

import (
	"context"
	"fmt"
	"log"
	"time"

	"llm_api_monitor/internal/capture"
	"llm_api_monitor/internal/config"
	"llm_api_monitor/internal/db"
	"llm_api_monitor/internal/model"
	"llm_api_monitor/internal/parser"
)

// Daemon reads parse results and merges them into the database.
type Daemon struct {
	cfg      *config.Config
	store    *db.Store
	engine   *parser.Engine
	resultCh <-chan *WorkerResult
}

// WorkerResult carries the parsed data from a worker to the writer.
type WorkerResult struct {
	ParseResult *model.ParseResult
	JobID       int64
	PcapPath    string
}

// NewDaemon creates a writer daemon.
func NewDaemon(cfg *config.Config, store *db.Store, engine *parser.Engine, resultCh <-chan *WorkerResult) *Daemon {
	return &Daemon{
		cfg:      cfg,
		store:    store,
		engine:   engine,
		resultCh: resultCh,
	}
}

// Run processes incoming results and writes to DB. Blocks until ctx is cancelled.
func (d *Daemon) Run(ctx context.Context) error {
	log.Printf("[writer] started")
	for {
		select {
		case <-ctx.Done():
			log.Printf("[writer] shutting down")
			return nil

		case wr, ok := <-d.resultCh:
			if !ok {
				return nil
			}
			if err := d.processResult(wr); err != nil {
				log.Printf("[writer] error processing %s: %v", wr.PcapPath, err)
			}
		}
	}
}

func (d *Daemon) processResult(wr *WorkerResult) error {
	jobID := wr.JobID

	_ = d.store.UpdateJobStatus(jobID, map[string]interface{}{
		"status":          "merging",
		"analysis_status": "merging",
	})

	stats := d.engine.MergeResult(wr.ParseResult, jobID)

	touchedRows := d.engine.GetTouchedSessions(stats.TouchedSessions)

	currentEpoch := stats.LastEpoch
	if currentEpoch == 0 {
		currentEpoch = float64(time.Now().Unix())
	}
	expiredRows := d.engine.ExpireIdleSessions(currentEpoch)

	allRows := append(touchedRows, expiredRows...)

	if err := d.store.UpsertSessions(jobID, allRows); err != nil {
		log.Printf("[writer] upsert sessions error: %v", err)
		_ = d.store.UpdateJobStatus(jobID, map[string]interface{}{
			"status":          "failed",
			"analysis_status": "failed",
			"message":         err.Error(),
		})
		return err
	}

	if err := d.store.InsertRequestLogs(jobID, stats.RequestLogs); err != nil {
		log.Printf("[writer] insert request logs error: %v", err)
	}

	if err := d.store.InsertTransportEvents(jobID, stats.TransportEvents); err != nil {
		log.Printf("[writer] insert transport events error: %v", err)
	}

	message := fmt.Sprintf("parsed %d packets, touched %d sessions, requests %d, active %d",
		stats.PacketCount, len(stats.TouchedSessions), len(stats.RequestLogs), d.engine.ActiveSessions())

	err := d.store.UpdateJob(jobID, stats.FinishedAt, stats.PacketCount, "parsed", message, stats.StartedAt)
	if err != nil {
		log.Printf("[writer] update job error: %v", err)
	}

	log.Printf("[writer] job %d: %s", jobID, message)
	return nil
}

// WorkerPool runs N parser goroutines that read tasks and produce results.
type WorkerPool struct {
	cfg      *config.Config
	engine   *parser.Engine
	store    *db.Store
	taskCh   <-chan *capture.Task
	resultCh chan<- *WorkerResult
	workers  int
}

// NewWorkerPool creates a worker pool.
func NewWorkerPool(cfg *config.Config, engine *parser.Engine, store *db.Store,
	taskCh <-chan *capture.Task, resultCh chan<- *WorkerResult, workers int) *WorkerPool {
	return &WorkerPool{
		cfg:      cfg,
		engine:   engine,
		store:    store,
		taskCh:   taskCh,
		resultCh: resultCh,
		workers:  workers,
	}
}

// Run starts all workers. Blocks until ctx is cancelled.
func (wp *WorkerPool) Run(ctx context.Context) {
	log.Printf("[workers] starting %d parser workers", wp.workers)
	done := make(chan struct{}, wp.workers)
	for i := 0; i < wp.workers; i++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()
			wp.worker(ctx, id)
		}(i)
	}
	for i := 0; i < wp.workers; i++ {
		<-done
	}
	log.Printf("[workers] all workers stopped")
}

func (wp *WorkerPool) worker(ctx context.Context, id int) {
	workerName := fmt.Sprintf("rt-worker-%d", id+1)
	log.Printf("[%s] started", workerName)

	for {
		select {
		case <-ctx.Done():
			return
		case task, ok := <-wp.taskCh:
			if !ok {
				return
			}
			wp.handleTask(ctx, task, id)
		}
	}
}

func (wp *WorkerPool) handleTask(ctx context.Context, task *capture.Task, workerID int) {
	workerName := fmt.Sprintf("rt-worker-%d", workerID+1)

	jobID := task.JobID
	if jobID == 0 {
		now := model.NowLocalText()
		startedAt := capture.PcapStartedAt(task.PcapPath)
		if startedAt == "" {
			startedAt = now
		}
		job := &model.CaptureJob{
			Iface:          task.Iface,
			WindowSeconds:  task.WindowSeconds,
			BPFFilter:      task.BPFFilter,
			PcapPath:       task.PcapPath,
			StartedAt:      startedAt,
			Status:         "parsing",
			QueueName:      task.QueueName,
			AnalysisStatus: "parsing",
			WorkerName:     workerName,
		}
		id, err := wp.store.InsertJob(job)
		if err != nil {
			log.Printf("[%s] insert job error for %s: %v", workerName, task.PcapPath, err)
			return
		}
		jobID = id
	} else {
		_ = wp.store.UpdateJobStatus(jobID, map[string]interface{}{
			"status":          "parsing",
			"analysis_status": "parsing",
			"worker_name":     workerName,
		})
	}

	result, err := wp.engine.ParsePcap(task.PcapPath)
	if err != nil {
		log.Printf("[%s] parse error for %s: %v", workerName, task.PcapPath, err)
		_ = wp.store.UpdateJobStatus(jobID, map[string]interface{}{
			"status":          "failed",
			"analysis_status": "failed",
			"message":         err.Error(),
		})
		return
	}

	result.JobID = jobID
	result.QueueName = task.QueueName
	result.WorkerName = workerName

	select {
	case wp.resultCh <- &WorkerResult{
		ParseResult: result,
		JobID:       jobID,
		PcapPath:    task.PcapPath,
	}:
	case <-ctx.Done():
		return
	}

	_ = wp.store.UpdateJobStatus(jobID, map[string]interface{}{
		"status":          "queued",
		"analysis_status": "parsed_ready",
	})
}
