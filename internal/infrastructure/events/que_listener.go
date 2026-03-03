package events

import (
	"context"

	"github.com/vayload/plug-registry/internal/domain"
	"github.com/vayload/plug-registry/pkg/queue"
)

type QueueListener struct {
	consumers []domain.QueueConsumers
	queue     queue.Consumer
}

func NewQueueListener(consumers []domain.QueueConsumers, queue queue.Consumer) *QueueListener {
	return &QueueListener{consumers: consumers, queue: queue}
}

func (l *QueueListener) Listen(ctx context.Context) {
	for _, consumer := range l.consumers {
		for jobType, handler := range consumer.Handlers() {
			l.queue.Consume(ctx, jobType, handler)
		}
	}
}
