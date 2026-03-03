package queue

import (
	"context"
	"errors"
	"time"
)

const SERVICE_NAME = "queue"

// Job represents a unit of work that can be processed by the queue.
type Job struct {
	ID        string
	Type      JobType
	Payload   map[string]any
	CreatedAt time.Time
}

func NewJob(id string, jobType JobType, payload map[string]any) Job {
	return Job{
		ID:        id,
		Type:      jobType,
		Payload:   payload,
		CreatedAt: time.Now().UTC(),
	}
}

type JobType string

const (
	JobTypeEmailVerification   JobType = "email.verification"
	JobTypeEmailWelcome        JobType = "email.welcome"
	JobTypeEmailPasswordChange JobType = "email.password-change"
	JobTypeEmailChange         JobType = "email.email-change"
)

// Handler is a function that processes a job.
type Handler func(ctx context.Context, job Job) error

type Producer interface {
	// Publish adds a job to the queue.
	Publish(ctx context.Context, job Job) error
}

type Consumer interface {
	// Consume registers a handler for a specific job type.
	Consume(ctx context.Context, jobType JobType, consumer Handler)
}

type Stats struct {
	Pending      uint64
	Processing   uint64
	Completed    uint64
	Failed       uint64
	DeadLettered uint64
	Retried      uint64
}

// Queue defines the interface for publishing jobs to a queue.
type Queue interface {
	// Publisher contract
	Producer

	// Consumer contract
	Consumer

	// Start starts the queue workers.
	Start(ctx context.Context) error

	// Stop gracefully stops the queue workers.
	Stop(ctx context.Context) error

	// Stats returns the current statistics of the queue.
	Stats() Stats
}

type RetryableError struct {
	Err error
}

func (e RetryableError) Error() string { return e.Err.Error() }

func Retryable(err error) error { return RetryableError{Err: err} }

func IsRetryable(err error) bool {
	var retryable RetryableError
	return errors.As(err, &retryable)
}

type NonRetryableError struct {
	Err error
}

func (e NonRetryableError) Error() string { return e.Err.Error() }

func NonRetryable(err error) error { return NonRetryableError{Err: err} }

func IsNonRetryable(err error) bool {
	var nonRetryable NonRetryableError
	return errors.As(err, &nonRetryable)
}
