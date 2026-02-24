package cache

import (
	"container/list"
	"context"
	"sync"
	"time"

	"github.com/vayload/plug-registry/internal/domain"
)

type entry[K comparable, V any] struct {
	key        K
	value      V
	expiration int64
}

type LRUCache[K comparable, V any] struct {
	mu        sync.Mutex
	capacity  int
	items     map[K]*list.Element
	evictList *list.List
}

func NewLRUCache[K comparable, V any](capacity int) *LRUCache[K, V] {
	return &LRUCache[K, V]{
		capacity:  capacity,
		items:     make(map[K]*list.Element),
		evictList: list.New(),
	}
}

func (c *LRUCache[K, V]) Get(ctx context.Context, key K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if ent, ok := c.items[key]; ok {
		if time.Now().UnixNano() > ent.Value.(*entry[K, V]).expiration {
			c.removeElement(ent)
			var zero V
			return zero, false
		}
		c.evictList.MoveToFront(ent)
		return ent.Value.(*entry[K, V]).value, true
	}

	var zero V
	return zero, false
}

func (c *LRUCache[K, V]) Set(ctx context.Context, key K, value V, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	exp := time.Now().Add(ttl).UnixNano()

	if ent, ok := c.items[key]; ok {
		c.evictList.MoveToFront(ent)
		ent.Value.(*entry[K, V]).value = value
		ent.Value.(*entry[K, V]).expiration = exp
		return
	}

	ent := &entry[K, V]{key, value, exp}
	element := c.evictList.PushFront(ent)
	c.items[key] = element

	if c.evictList.Len() > c.capacity {
		c.removeOldest()
	}
}

func (c *LRUCache[K, V]) GetOrSet(ctx context.Context, key K, fn func(ctx context.Context) (V, time.Duration, error)) (V, error) {
	value, ok := c.Get(ctx, key)
	if ok {
		return value, nil
	}

	// Create a cancelable context with a timeout of 10 seconds, avoid dead lock
	cancelable, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	value, ttl, err := fn(cancelable)
	if err != nil {
		return value, err
	}

	c.Set(ctx, key, value, ttl)
	return value, nil
}

func (c *LRUCache[K, V]) Delete(ctx context.Context, key K) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if ent, ok := c.items[key]; ok {
		c.removeElement(ent)
	}
}

func (c *LRUCache[K, V]) Flush(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items = make(map[K]*list.Element)
	c.evictList = list.New()
}

// Not use mutex because parent function already locked
func (c *LRUCache[K, V]) removeOldest() {
	e := c.evictList.Back()
	if e != nil {
		c.removeElement(e)
	}
}

// Not use mutex because parent function already locked
func (c *LRUCache[K, V]) removeElement(e *list.Element) {
	c.evictList.Remove(e)
	kv := e.Value.(*entry[K, V])
	delete(c.items, kv.key)
}

func (c *LRUCache[K, V]) Close(ctx context.Context) error {
	return nil
}

var _ domain.StaticCache[any] = (*LRUCache[string, any])(nil)
