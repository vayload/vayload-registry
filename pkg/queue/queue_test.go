package queue

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newTestQueue(t *testing.T) (*persistentQueue, func()) {
	t.Helper()

	walFile, err := os.CreateTemp(t.TempDir(), "wal-*.jsonl")
	if err != nil {
		t.Fatalf("temp wal: %v", err)
	}
	walFile.Close()

	dlFile, err := os.CreateTemp(t.TempDir(), "dl-*.jsonl")
	if err != nil {
		t.Fatalf("temp dl: %v", err)
	}
	dlFile.Close()

	q, err := NewMessageQueue(PersistentQueueConfig{
		BufferSize:     64,
		WALPath:        walFile.Name(),
		DeadLetterPath: dlFile.Name(),
	})
	if err != nil {
		t.Fatalf("new queue: %v", err)
	}

	pq := q.(*persistentQueue)
	return pq, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = pq.Stop(ctx)
	}
}

func startQueue(t *testing.T, q *persistentQueue) {
	t.Helper()
	if err := q.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
}

func waitFor(t *testing.T, condition func() bool, timeout time.Duration, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for: %s", msg)
}

// TestACK verifies that a successful job remains in completed and not in dead-letter.
func TestACK(t *testing.T) {
	q, cleanup := newTestQueue(t)
	defer cleanup()

	var processed atomic.Int32
	q.Consume(context.Background(), JobTypeEmailVerification, func(_ context.Context, _ Job) error {
		processed.Add(1)
		return nil
	})
	startQueue(t, q)

	job := NewJob("ack-1", JobTypeEmailVerification, map[string]any{"email": "a@b.com"})
	if err := q.Publish(context.Background(), job); err != nil {
		t.Fatalf("publish: %v", err)
	}

	waitFor(t, func() bool { return processed.Load() == 1 }, 2*time.Second, "job processed")

	stats := q.Stats()
	if stats.Completed != 1 {
		t.Errorf("expected 1 completed, got %d", stats.Completed)
	}
	if stats.DeadLettered != 0 {
		t.Errorf("expected 0 dead-lettered, got %d", stats.DeadLettered)
	}
}

// TestNACK_Retryable verifies that a retryable error re-enqueues the job.
func TestNACK_Retryable(t *testing.T) {
	q, cleanup := newTestQueue(t)
	defer cleanup()

	var attempts atomic.Int32
	q.Consume(context.Background(), JobTypeEmailVerification, func(_ context.Context, _ Job) error {
		n := attempts.Add(1)
		if n < 3 {
			return Retryable(fmt.Errorf("transient error attempt %d", n))
		}
		return nil // 3rd attempt ok
	})
	startQueue(t, q)

	job := NewJob("nack-retry-1", JobTypeEmailVerification, nil)
	if err := q.Publish(context.Background(), job); err != nil {
		t.Fatalf("publish: %v", err)
	}

	waitFor(t, func() bool { return attempts.Load() >= 3 }, 3*time.Second, "3 attempts")

	stats := q.Stats()
	if stats.Completed != 1 {
		t.Errorf("expected 1 completed, got %d", stats.Completed)
	}
	if stats.DeadLettered != 0 {
		t.Errorf("expected 0 dead-lettered, got %d", stats.DeadLettered)
	}
}

// TestNACK_NonRetryable verifies that a non-retryable error goes directly to dead-letter.
func TestNACK_NonRetryable(t *testing.T) {
	q, cleanup := newTestQueue(t)
	defer cleanup()

	var attempts atomic.Int32
	q.Consume(context.Background(), JobTypeEmailVerification, func(_ context.Context, _ Job) error {
		attempts.Add(1)
		return NonRetryable(fmt.Errorf("permanent failure"))
	})
	startQueue(t, q)

	job := NewJob("nack-dl-1", JobTypeEmailVerification, nil)
	if err := q.Publish(context.Background(), job); err != nil {
		t.Fatalf("publish: %v", err)
	}

	waitFor(t, func() bool { return q.Stats().DeadLettered == 1 }, 2*time.Second, "dead-lettered")

	if n := attempts.Load(); n != 1 {
		t.Errorf("non-retryable should only be attempted once, got %d", n)
	}
	stats := q.Stats()
	if stats.Completed != 0 {
		t.Errorf("expected 0 completed, got %d", stats.Completed)
	}
}

// TestDeadLetter_NoDoubleProcess is the main test:
// a dead-lettered job must NOT be processed twice even if it is re-published
// with the same ID in the same session (idempotency by processed set).
func TestDeadLetter_NoDoubleProcess(t *testing.T) {
	q, cleanup := newTestQueue(t)
	defer cleanup()

	var callCount atomic.Int32
	q.Consume(context.Background(), JobTypeEmailVerification, func(_ context.Context, _ Job) error {
		callCount.Add(1)
		return NonRetryable(fmt.Errorf("always fails"))
	})
	startQueue(t, q)

	job := NewJob("idempotent-1", JobTypeEmailVerification, nil)

	// Publish the same job twice
	if err := q.Publish(context.Background(), job); err != nil {
		t.Fatalf("first publish: %v", err)
	}
	waitFor(t, func() bool { return q.Stats().DeadLettered == 1 }, 2*time.Second, "first dead-letter")

	// Second attempt with the same ID: should be ignored by the processed set
	if err := q.Publish(context.Background(), job); err != nil {
		t.Logf("second publish rejected (expected): %v", err)
	}
	time.Sleep(200 * time.Millisecond) // give time for the worker to see it

	if n := callCount.Load(); n != 1 {
		t.Errorf("handler should be called exactly once, got %d", n)
	}
}

// TestDeadLetter_WrittenToDLFile verifies that the dead_letter.jsonl receives the entry.
func TestDeadLetter_WrittenToDLFile(t *testing.T) {
	dir := t.TempDir()
	walPath := dir + "/queue.jsonl"
	dlPath := dir + "/dead_letter.jsonl"

	rawQ, err := NewMessageQueue(PersistentQueueConfig{
		BufferSize:     16,
		WALPath:        walPath,
		DeadLetterPath: dlPath,
	})
	if err != nil {
		t.Fatalf("new queue: %v", err)
	}
	q := rawQ.(*persistentQueue)

	q.Consume(context.Background(), JobTypeEmailVerification, func(_ context.Context, _ Job) error {
		return NonRetryable(fmt.Errorf("hard fail"))
	})
	if err := q.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}

	if err := q.Publish(context.Background(), NewJob("dl-file-1", JobTypeEmailVerification, nil)); err != nil {
		t.Fatalf("publish: %v", err)
	}

	waitFor(t, func() bool { return q.Stats().DeadLettered == 1 }, 2*time.Second, "dead-lettered")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = q.Stop(ctx)

	info, err := os.Stat(dlPath)
	if err != nil {
		t.Fatalf("dead_letter file stat: %v", err)
	}
	if info.Size() == 0 {
		t.Error("dead_letter.jsonl should not be empty")
	}
}

// TestWALReplay simulates a power outage: creates a WAL with pending entries,
// starts a new instance and verifies that the jobs are processed.
func TestWALReplay(t *testing.T) {
	dir := t.TempDir()
	walPath := dir + "/queue.jsonl"
	dlPath := dir + "/dead_letter.jsonl"

	// Write "orphan" entries simulating a crash before ack
	orphanWAL, err := newWAL(walPath, dlPath)
	if err != nil {
		t.Fatalf("wal: %v", err)
	}
	_ = orphanWAL.write(walEntry{ID: "replay-1", Type: string(JobTypeEmailVerification), Status: StatusPending, Payload: map[string]any{"x": 1}})
	_ = orphanWAL.write(walEntry{ID: "replay-2", Type: string(JobTypeEmailVerification), Status: StatusPending, Payload: map[string]any{"x": 2}})
	// replay-3 was completed before the power outage: it should not be replayed
	_ = orphanWAL.write(walEntry{ID: "replay-3", Type: string(JobTypeEmailVerification), Status: StatusPending})
	_ = orphanWAL.write(walEntry{ID: "replay-3", Type: string(JobTypeEmailVerification), Status: StatusCompleted})
	_ = orphanWAL.Close()

	// New instance over the same WAL
	rawQ, err := NewMessageQueue(PersistentQueueConfig{
		BufferSize:     16,
		WALPath:        walPath,
		DeadLetterPath: dlPath,
	})
	if err != nil {
		t.Fatalf("new queue: %v", err)
	}
	q := rawQ.(*persistentQueue)

	var mu sync.Mutex
	processedIDs := make([]string, 0)
	q.Consume(context.Background(), JobTypeEmailVerification, func(_ context.Context, job Job) error {
		mu.Lock()
		processedIDs = append(processedIDs, job.ID)
		mu.Unlock()
		return nil
	})

	if err := q.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = q.Stop(ctx)
	}()

	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(processedIDs) >= 2
	}, 3*time.Second, "replay jobs processed")

	mu.Lock()
	defer mu.Unlock()

	seen := make(map[string]bool)
	for _, id := range processedIDs {
		seen[id] = true
	}

	if !seen["replay-1"] {
		t.Error("replay-1 should have been replayed")
	}
	if !seen["replay-2"] {
		t.Error("replay-2 should have been replayed")
	}
	if seen["replay-3"] {
		t.Error("replay-3 was already completed and should NOT be replayed")
	}
}

// TestOrdering verifies that jobs are processed in FIFO order within a worker.
func TestOrdering(t *testing.T) {
	q, cleanup := newTestQueue(t)
	defer cleanup()

	var mu sync.Mutex
	order := make([]string, 0, 5)

	q.Consume(context.Background(), JobTypeEmailVerification, func(_ context.Context, job Job) error {
		mu.Lock()
		order = append(order, job.ID)
		mu.Unlock()
		return nil
	})
	startQueue(t, q)

	ids := []string{"job-1", "job-2", "job-3", "job-4", "job-5"}
	for _, id := range ids {
		if err := q.Publish(context.Background(), NewJob(id, JobTypeEmailVerification, nil)); err != nil {
			t.Fatalf("publish %s: %v", id, err)
		}
	}

	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(order) == 5
	}, 3*time.Second, "all jobs processed")

	mu.Lock()
	defer mu.Unlock()
	for i, id := range ids {
		if order[i] != id {
			t.Errorf("position %d: expected %s, got %s", i, id, order[i])
		}
	}
}

// TestShutdownDrainsQueue verifies that when Stop is called, the pending jobs are processed.
func TestShutdownDrainsQueue(t *testing.T) {
	q, _ := newTestQueue(t)

	var processed atomic.Int32
	q.Consume(context.Background(), JobTypeEmailVerification, func(_ context.Context, _ Job) error {
		time.Sleep(10 * time.Millisecond)
		processed.Add(1)
		return nil
	})
	startQueue(t, q)

	for i := range 10 {
		id := fmt.Sprintf("drain-%d", i)
		_ = q.Publish(context.Background(), NewJob(id, JobTypeEmailVerification, nil))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := q.Stop(ctx); err != nil {
		t.Fatalf("stop: %v", err)
	}

	if n := processed.Load(); n != 10 {
		t.Errorf("expected all 10 jobs processed on shutdown, got %d", n)
	}
}

func logMemory(t *testing.T) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	t.Logf(
		"[MEM] Alloc=%.2fMB TotalAlloc=%.2fMB Sys=%.2fMB NumGC=%d Goroutines=%d",
		float64(m.Alloc)/1024/1024,
		float64(m.TotalAlloc)/1024/1024,
		float64(m.Sys)/1024/1024,
		m.NumGC,
		runtime.NumGoroutine(),
	)
}

func TestStress_Throughput(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping throughput test in short mode")
	}

	dir := t.TempDir()
	walPath := dir + "/queue.jsonl"
	dlPath := dir + "/dead_letter.jsonl"

	rawQ, err := NewMessageQueue(PersistentQueueConfig{
		BufferSize:     1024,
		WALPath:        walPath,
		DeadLetterPath: dlPath,
	})
	if err != nil {
		t.Fatalf("new queue: %v", err)
	}
	q := rawQ.(*persistentQueue)

	var processed atomic.Uint64
	var totalLatency atomic.Int64

	q.Consume(context.Background(), JobTypeEmailVerification, func(_ context.Context, job Job) error {
		start := time.Since(job.CreatedAt)
		totalLatency.Add(start.Milliseconds())

		time.Sleep(10 * time.Millisecond)

		processed.Add(1)
		return nil
	})

	if err := q.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = q.Stop(ctx)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	go func() {
		counter := 0
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		var startTime = time.Now()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:

				elapsed := time.Since(startTime).Seconds()

				var rate int

				switch {
				case elapsed < 5:
					rate = 50 // low load
				case elapsed < 10:
					rate = 3000 // high load
				case elapsed < 15:
					rate = 10 // almost idle
				case elapsed < 20:
					rate = 100000 // extreme load
				case elapsed < 30:
					rate = 10 // extreme load
				case elapsed < 40:
					rate = 10 // extreme load
				default:
					rate = 0 // silence
				}

				for i := 0; i < rate/10; i++ {
					id := fmt.Sprintf("attack-%d", counter)
					job := NewJob(id, JobTypeEmailVerification, nil)
					_ = q.Publish(context.Background(), job)
					counter++
				}
			}
		}
	}()

	monitorTicker := time.NewTicker(1 * time.Second)
	defer monitorTicker.Stop()

	startTime := time.Now()

	for {
		select {
		case <-ctx.Done():
			elapsed := time.Since(startTime).Seconds()
			totalProcessed := processed.Load()

			throughput := float64(totalProcessed) / elapsed

			var avgLatency float64
			if totalProcessed > 0 {
				avgLatency = float64(totalLatency.Load()) / float64(totalProcessed)
			}

			t.Logf("====== FINAL STATS ======")
			t.Logf("Elapsed: %.2fs", elapsed)
			t.Logf("Total processed: %d", totalProcessed)
			t.Logf("Throughput: %.2f jobs/sec", throughput)
			t.Logf("Avg latency: %.2f ms", avgLatency)
			t.Logf("Queue stats: %+v", q.Stats())

			runtime.GC()
			debug.FreeOSMemory()

			var m runtime.MemStats
			runtime.ReadMemStats(&m)

			t.Logf("====== AFTER FORCED GC ======")
			t.Logf("Alloc=%.2fMB Sys=%.2fMB Goroutines=%d",
				float64(m.Alloc)/1024/1024,
				float64(m.Sys)/1024/1024,
				runtime.NumGoroutine(),
			)

			return

		case <-monitorTicker.C:
			stats := q.Stats()

			var m runtime.MemStats
			runtime.ReadMemStats(&m)

			t.Logf(
				"[LIVE] workers=%d processed=%d pending=%d processing=%d completed=%d retried=%d dead=%d | Alloc=%.2fMB Goroutines=%d GC=%d",
				q.ActiveWorkers(),
				processed.Load(),
				stats.Pending,
				stats.Processing,
				stats.Completed,
				stats.Retried,
				stats.DeadLettered,
				float64(m.Alloc)/1024/1024,
				runtime.NumGoroutine(),
				m.NumGC,
			)

			logMemory(t)
		}
	}

}
