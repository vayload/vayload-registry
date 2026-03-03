package queue

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/vayload/plug-registry/pkg/logger"
)

type ElasticPoolConfig struct {
	MinWorkers int
	MaxWorkers int
	// Example: 0.7 → if the channel is at 70% of capacity, add a worker.
	ScaleUpThreshold float64
	// ScaleDownIdle: time that a temporary worker can be idle before dying.
	ScaleDownIdle time.Duration
	// TickInterval: how often the scaler evaluates if it needs to scale.
	TickInterval time.Duration
}

func defaultElasticConfig() ElasticPoolConfig {
	return ElasticPoolConfig{
		MinWorkers:       1,
		MaxWorkers:       16,
		ScaleUpThreshold: 0.75, // scale up when the channel is at 75% of capacity
		ScaleDownIdle:    10 * time.Second,
		TickInterval:     500 * time.Millisecond,
	}
}

// elasticPool manages a set of workers that grow and shrink
// according to the pressure on the jobs channel.
//
// Design:
//   - N "base" workers (MinWorkers) run indefinitely until Stop().
//   - The scaler runs in its own goroutine and each TickInterval observes:
//     occupancy = len(jobs) / cap(jobs)
//     If occupancy >= ScaleUpThreshold and active < MaxWorkers → spawns 1 temporary worker.
//   - Temporary workers self-destruct if they don't receive a job in ScaleDownIdle.
//   - activeWorkers is atomic to avoid the lock in the hot path.
type elasticPool struct {
	jobs    <-chan Job    // jobs channel (read-only, owned by the queue)
	process func(job Job) // function that processes a job (comes from the queue)
	cfg     ElasticPoolConfig

	activeWorkers atomic.Int32  // workers running right now
	stopChan      chan struct{} // global shutdown signal
	wg            sync.WaitGroup
}

func newElasticPool(jobs <-chan Job, process func(Job), cfg ElasticPoolConfig) *elasticPool {
	if cfg.MinWorkers <= 0 {
		cfg.MinWorkers = 1
	}
	if cfg.MaxWorkers < cfg.MinWorkers {
		cfg.MaxWorkers = cfg.MinWorkers
	}
	if cfg.ScaleUpThreshold <= 0 {
		cfg.ScaleUpThreshold = 0.6
	}
	if cfg.ScaleDownIdle <= 0 {
		cfg.ScaleDownIdle = 10 * time.Second
	}
	if cfg.TickInterval <= 0 {
		cfg.TickInterval = 500 * time.Millisecond
	}

	return &elasticPool{
		jobs:     jobs,
		process:  process,
		cfg:      cfg,
		stopChan: make(chan struct{}),
	}
}

func (p *elasticPool) Start() {
	for i := 0; i < p.cfg.MinWorkers; i++ {
		p.spawnWorker(false) // base: no tienen idle timeout
	}
	p.wg.Add(1)
	go p.scaler()

	logger.I("Elastic pool started", logger.Fields{
		"min_workers": p.cfg.MinWorkers,
		"max_workers": p.cfg.MaxWorkers,
	})
}

func (p *elasticPool) Stop() {
	close(p.stopChan)
	p.wg.Wait()
}

func (p *elasticPool) ActiveWorkers() int {
	return int(p.activeWorkers.Load())
}

func (p *elasticPool) scaler() {
	defer p.wg.Done()
	ticker := time.NewTicker(p.cfg.TickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopChan:
			return
		case <-ticker.C:
			p.maybeScaleUp()
		}
	}
}

func (p *elasticPool) maybeScaleUp() {
	bufCap := cap(p.jobs)
	if bufCap == 0 {
		return // bufferless channel: can't measure pressure
	}

	occupancy := float64(len(p.jobs)) / float64(bufCap)
	active := p.activeWorkers.Load()

	if occupancy >= p.cfg.ScaleUpThreshold && int(active) < p.cfg.MaxWorkers {
		p.spawnWorker(true)
		logger.D("Scaled up worker", logger.Fields{
			"active":    active + 1,
			"occupancy": occupancy,
		})
	}
}

func (p *elasticPool) spawnWorker(temporary bool) {
	p.activeWorkers.Add(1)
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer p.activeWorkers.Add(-1)
		p.runWorker(temporary)
	}()
}

func (p *elasticPool) runWorker(temporary bool) {
	var idleTimer *time.Timer
	var idleC <-chan time.Time

	if temporary {
		idleTimer = time.NewTimer(p.cfg.ScaleDownIdle)
		idleC = idleTimer.C
		defer idleTimer.Stop()
	}

	for {
		select {
		case job, ok := <-p.jobs:
			if !ok {
				return
			}
			if temporary {
				// resetear idle timer when job is received
				if !idleTimer.Stop() {
					select {
					case <-idleTimer.C:
					default:
					}
				}
				idleTimer.Reset(p.cfg.ScaleDownIdle)
			}
			p.process(job)

		case <-idleC:
			logger.D("Temporary worker idle timeout, exiting", logger.Fields{
				"active_after": p.activeWorkers.Load() - 1,
			})
			return

		case <-p.stopChan:
			for {
				select {
				case job, ok := <-p.jobs:
					if !ok {
						return
					}
					p.process(job)
				default:
					return
				}
			}
		}
	}
}
