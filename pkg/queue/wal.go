package queue

import (
	"bufio"
	"encoding/json"
	"os"
	"sync"
)

type JobStatus string

const (
	StatusPending    JobStatus = "pending"
	StatusProcessing JobStatus = "processing"
	StatusCompleted  JobStatus = "completed"
	StatusFailed     JobStatus = "failed"
	StatusDeadLetter JobStatus = "dead_letter"
)

// Is a entry in the WAL file
type walEntry struct {
	ID      string         `json:"id"`
	Type    string         `json:"type"`
	Status  JobStatus      `json:"status"`
	Payload map[string]any `json:"payload,omitempty"`
	Error   string         `json:"error,omitempty"`
}

// wal is the Write-Ahead Log: append-only JSONL file.
// Each published job writes a line with status=pending.
// Each state change writes another line with the same ID.
// In replay: we go line by line; the last state per ID wins.
// If the last state is pending/processing → the job needs replay.
type wal struct {
	mu         sync.Mutex
	file       *os.File
	writer     *bufio.Writer
	deadLetter *os.File
	dlWriter   *bufio.Writer
}

func newWAL(walPath, deadLetterPath string) (*wal, error) {
	f, err := os.OpenFile(walPath, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}

	dl, err := os.OpenFile(deadLetterPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		f.Close()
		return nil, err
	}

	return &wal{
		file:       f,
		writer:     bufio.NewWriter(f),
		deadLetter: dl,
		dlWriter:   bufio.NewWriter(dl),
	}, nil
}

func (w *wal) write(entry walEntry) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	b, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if _, err := w.writer.Write(append(b, '\n')); err != nil {
		return err
	}
	return w.writer.Flush()
}

func (w *wal) writeDeadLetter(entry walEntry) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	b, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if _, err := w.dlWriter.Write(append(b, '\n')); err != nil {
		return err
	}
	return w.dlWriter.Flush()
}

func (w *wal) Replay() ([]walEntry, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if _, err := w.file.Seek(0, 0); err != nil {
		return nil, err
	}

	seen := make(map[string]walEntry)
	order := make([]string, 0)

	scanner := bufio.NewScanner(w.file)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var entry walEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue // corrupted line, skip
		}
		if _, exists := seen[entry.ID]; !exists {
			order = append(order, entry.ID)
		}
		seen[entry.ID] = entry
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	var pending []walEntry
	for _, id := range order {
		entry := seen[id]
		if entry.Status == StatusPending || entry.Status == StatusProcessing {
			pending = append(pending, entry)
		}
	}
	return pending, nil
}

func (w *wal) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	_ = w.writer.Flush()
	_ = w.dlWriter.Flush()
	_ = w.deadLetter.Close()
	return w.file.Close()
}
