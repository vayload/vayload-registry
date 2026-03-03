package queue

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestChaos_PressureCooker(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping pressure cooker test in short mode")
	}

	dir := t.TempDir()
	rawQ, _ := NewMessageQueue(PersistentQueueConfig{
		BufferSize:     512,
		WALPath:        dir + "/chaos.jsonl",
		DeadLetterPath: dir + "/dead.jsonl",
	})
	q := rawQ.(*persistentQueue)

	q.Consume(context.Background(), JobTypeEmailVerification, func(_ context.Context, job Job) error {
		time.Sleep(50 * time.Millisecond)
		if time.Now().UnixNano()%3 == 0 {
			return fmt.Errorf("error aleatorio de caos")
		}
		return nil
	})

	_ = q.Start(context.Background())

	var published, failed atomic.Uint64
	for i := range 50 {
		go func(id int) {
			for j := range 2000 {
				job := NewJob(fmt.Sprintf("chaos-%d-%d", id, j), JobTypeEmailVerification, nil)
				err := q.Publish(context.Background(), job)
				if err != nil {
					failed.Add(1)
				} else {
					published.Add(1)
				}
			}
		}(i)
	}

	for range 10 {
		time.Sleep(1 * time.Second)
		stats := q.Stats()
		t.Logf("[CHAOS] Published: %d | Pending: %d | Processing: %d | Dead: %d",
			published.Load(), stats.Pending, stats.Processing, stats.DeadLettered)
	}

	defer func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer stopCancel()
		_ = q.Stop(stopCtx)
	}()
}

func TestChaos_DirtyShutdown(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping dirty shutdown test in short mode")
	}

	dir := t.TempDir()
	rawQ, _ := NewMessageQueue(PersistentQueueConfig{
		BufferSize: 100,
		WALPath:    dir + "/dirty.jsonl",
	})
	q := rawQ.(*persistentQueue)

	q.Consume(context.Background(), JobTypeEmailVerification, func(ctx context.Context, _ Job) error {
		select {
		case <-time.After(5 * time.Second):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})

	_ = q.Start(context.Background())

	for i := range 500 {
		_ = q.Publish(context.Background(), NewJob(fmt.Sprintf("j-%d", i), JobTypeEmailVerification, nil))
	}

	stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	t.Log("Stop started...")
	err := q.Stop(stopCtx)
	t.Logf("Stop result (should be timeout/error): %v", err)
}

func TestChaos_WALCorruption(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping WAL corruption test in short mode")
	}

	dir := t.TempDir()
	walPath := dir + "/corrupt.jsonl"
	os.WriteFile(walPath, []byte("this is not a json\n{\"id\":\"123\"}\n{\"incomplete\":\n"), 0644)

	q, err := NewMessageQueue(PersistentQueueConfig{
		WALPath:    walPath,
		BufferSize: 10,
	})

	if err != nil {
		t.Logf("The queue detected the corruption (GOOD): %v", err)
	} else {
		err = q.Start(context.Background())
		t.Errorf("The queue started with a corrupted WAL without protesting. Risk of data loss.")
	}

	defer func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer stopCancel()
		_ = q.Stop(stopCtx)
	}()
}
