package domain

import (
	"context"
	"time"
)

// Dynamic cache represent dynamic cache
type Cache interface {
	Get(ctx context.Context, key string) (any, bool)
	GetOrSet(ctx context.Context, key string, fn func(ctx context.Context) (any, time.Duration, error)) (any, error)
	Set(ctx context.Context, key string, value any, expiration time.Duration)
	Delete(ctx context.Context, key string)
	Flush(ctx context.Context)
	Close(ctx context.Context) error
}

// Static cache represent type safe cache
type StaticCache[T any] interface {
	Get(ctx context.Context, key string) (T, bool)
	// GetOrSet returns the value for the key if it exists, otherwise it calls the function to get the value and sets it in the cache
	GetOrSet(ctx context.Context, key string, fn func(ctx context.Context) (T, time.Duration, error)) (T, error)
	Set(ctx context.Context, key string, value T, expiration time.Duration)
	Delete(ctx context.Context, key string)
	Flush(ctx context.Context)
	Close(ctx context.Context) error
}
