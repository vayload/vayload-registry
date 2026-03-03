package domain

import (
	"context"

	"github.com/vayload/plug-registry/pkg/queue"
)

type QueueConsumer interface {
	Handle(ctx context.Context, job queue.Job) error
}

type QueueConsumers interface {
	Handlers() map[queue.JobType]queue.Handler
}
