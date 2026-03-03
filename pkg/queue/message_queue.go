package queue

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vayload/plug-registry/pkg/logger"
)

type persistentQueue struct {
	jobs     chan Job
	handlers map[JobType]Handler
	mu       sync.RWMutex
	pool     *elasticPool

	stopChan   chan struct{}
	isShutdown bool

	wal *wal

	// stats
	statPending      atomic.Uint64
	statProcessing   atomic.Uint64
	statCompleted    atomic.Uint64
	statFailed       atomic.Uint64
	statDeadLettered atomic.Uint64
	statRetried      atomic.Uint64

	// ids already processed in this session; prevents double processing after replay
	processed sync.Map // map[string]struct{}
}

type PersistentQueueConfig struct {
	BufferSize     int
	WALPath        string // e.g. "queue.jsonl"
	DeadLetterPath string // e.g. "dead_letter.jsonl"
	// MaxRetries before sending to dead-letter (0 = no retries)
	MaxRetries int

	Pool ElasticPoolConfig
}

func NewMessageQueue(cfg PersistentQueueConfig) (Queue, error) {
	if cfg.WALPath == "" {
		cfg.WALPath = "queue.jsonl"
	}
	if cfg.DeadLetterPath == "" {
		cfg.DeadLetterPath = "dead_letter.jsonl"
	}

	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 256
	}
	if cfg.Pool.MinWorkers == 0 && cfg.Pool.MaxWorkers == 0 {
		cfg.Pool = defaultElasticConfig()
	}

	w, err := newWAL(cfg.WALPath, cfg.DeadLetterPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open WAL: %w", err)
	}

	q := &persistentQueue{
		jobs:     make(chan Job, cfg.BufferSize),
		handlers: make(map[JobType]Handler),
		stopChan: make(chan struct{}),
		wal:      w,
	}

	q.pool = newElasticPool(q.jobs, q.processJob, defaultElasticConfig())
	return q, nil
}

func (q *persistentQueue) Consume(_ context.Context, jobType JobType, handler Handler) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.handlers[jobType] = handler
}

func (q *persistentQueue) Publish(ctx context.Context, job Job) error {
	q.mu.RLock()
	shutdown := q.isShutdown
	q.mu.RUnlock()
	if shutdown {
		return fmt.Errorf("queue is shutdown")
	}

	if job.CreatedAt.IsZero() {
		job.CreatedAt = time.Now().UTC()
	}

	if err := q.wal.write(walEntry{
		ID:      job.ID,
		Type:    string(job.Type),
		Status:  StatusPending,
		Payload: job.Payload,
	}); err != nil {
		return fmt.Errorf("wal write failed: %w", err)
	}

	select {
	case q.jobs <- job:
		q.statPending.Add(1)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		return fmt.Errorf("queue is full")
	}
}

func (q *persistentQueue) Start(ctx context.Context) error {
	if err := q.replayWAL(); err != nil {
		logger.W("WAL replay failed", logger.Fields{"error": err})
	}

	q.pool.Start()
	return nil
}

func (q *persistentQueue) Stop(ctx context.Context) error {
	q.mu.Lock()
	if q.isShutdown {
		q.mu.Unlock()
		return nil
	}
	q.isShutdown = true
	q.mu.Unlock()

	close(q.stopChan)

	done := make(chan struct{})
	go func() {
		q.pool.Stop()
		_ = q.wal.Close()
		close(done)
	}()

	select {
	case <-done:
		logger.I("Persistent queue stopped gracefully")
		return nil
	case <-ctx.Done():
		_ = q.wal.Close()
		return fmt.Errorf("stop timeout exceeded: %w", ctx.Err())
	}
}

func (q *persistentQueue) Stats() Stats {
	return Stats{
		Pending:      q.statPending.Load(),
		Processing:   q.statProcessing.Load(),
		Completed:    q.statCompleted.Load(),
		Failed:       q.statFailed.Load(),
		DeadLettered: q.statDeadLettered.Load(),
		Retried:      q.statRetried.Load(),
	}
}

func (q *persistentQueue) replayWAL() error {
	entries, err := q.wal.Replay()
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return nil
	}

	logger.I("Replaying WAL", logger.Fields{"jobs": len(entries)})
	for _, e := range entries {
		job := Job{
			ID:        e.ID,
			Type:      JobType(e.Type),
			Payload:   e.Payload,
			CreatedAt: time.Now().UTC(),
		}

		select {
		case q.jobs <- job:
			q.statPending.Add(1)
		default:
			logger.W("Buffer full during WAL replay, dropping job", logger.Fields{"job_id": e.ID})
		}
	}
	return nil
}

func (q *persistentQueue) ActiveWorkers() int {
	return q.pool.ActiveWorkers()
}

func (q *persistentQueue) processJob(job Job) {
	// When a job is processed, it is marked as processed to prevent it from being processed again.
	if _, done := q.processed.LoadOrStore(job.ID, struct{}{}); done {
		logger.D("Job already processed, skipping", logger.Fields{"job_id": job.ID})
		return
	}

	q.mu.RLock()
	handler, ok := q.handlers[job.Type]
	q.mu.RUnlock()

	if !ok {
		logger.W("No handler for job type", logger.Fields{"job_type": job.Type, "job_id": job.ID})
		q.nack(job, fmt.Errorf("no handler registered for type %s", job.Type), true)
		return
	}

	_ = q.wal.write(walEntry{ID: job.ID, Type: string(job.Type), Status: StatusProcessing})
	q.statPending.Add(^uint64(0)) // -1
	q.statProcessing.Add(1)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := handler(ctx, job)
	if err == nil {
		q.ack(job)
		return
	}

	q.nack(job, err, IsNonRetryable(err))
}

func (q *persistentQueue) ack(job Job) {
	_ = q.wal.write(walEntry{ID: job.ID, Type: string(job.Type), Status: StatusCompleted})
	q.statProcessing.Add(^uint64(0))
	q.statCompleted.Add(1)
	logger.D("Job completed", logger.Fields{"job_id": job.ID})
}

func (q *persistentQueue) nack(job Job, err error, sendToDeadLetter bool) {
	q.statProcessing.Add(^uint64(0))

	if sendToDeadLetter || IsNonRetryable(err) {
		_ = q.wal.write(walEntry{ID: job.ID, Type: string(job.Type), Status: StatusDeadLetter, Error: err.Error()})
		_ = q.wal.writeDeadLetter(walEntry{ID: job.ID, Type: string(job.Type), Status: StatusDeadLetter, Payload: job.Payload, Error: err.Error()})
		q.statDeadLettered.Add(1)
		logger.E(err, logger.Fields{"job_id": job.ID, "job_type": job.Type, "context": "dead_letter"})
		return
	}

	// When job is retryable, it is marked as failed and retried.
	_ = q.wal.write(walEntry{ID: job.ID, Type: string(job.Type), Status: StatusFailed, Error: err.Error()})
	q.statFailed.Add(1)
	q.statRetried.Add(1)
	logger.W("Job failed, retrying", logger.Fields{"job_id": job.ID, "error": err.Error()})

	// Delete from processed set to allow retry
	q.processed.Delete(job.ID)

	select {
	case q.jobs <- job:
		q.statPending.Add(1)
	default:
		logger.E(fmt.Errorf("queue full, dropping retry for job %s", job.ID), nil)
	}
}
