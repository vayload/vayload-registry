//go:build cache_redis

package cache

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/vayload/plug-registry/internal/domain"
)

type RedisCache struct {
	client    *redis.Client
	namespace string
}

func NewCache(config CacheConfig) (*RedisCache, error) {
	if err := validate(config); err != nil {
		return nil, err
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     config.Addr,
		Password: config.Password,
		DB:       config.DB,
	})

	if err := rdb.Ping(context.Background()).Err(); err != nil {
		return nil, err
	}

	return &RedisCache{
		client:    rdb,
		namespace: config.Namespace,
	}, nil
}

func validate(config CacheConfig) error {
	if len(config.Addr) == 0 && config.Password == "" {
		return errors.New("redis address is required")
	}

	if len(config.Namespace) == 0 {
		return errors.New("redis namespace is required")
	}

	return nil
}

func (c *RedisCache) buildKey(key string) string {
	return c.namespace + ":" + key
}

func (c *RedisCache) Get(ctx context.Context, key string) (any, bool) {
	fullKey := c.buildKey(key)

	val, err := c.client.Get(ctx, fullKey).Result()
	if err == redis.Nil {
		return nil, false
	}
	if err != nil {
		return nil, false
	}

	var result any
	if err := json.Unmarshal([]byte(val), &result); err != nil {
		return nil, false
	}

	return result, true
}

func (c *RedisCache) Set(ctx context.Context, key string, value any, expiration time.Duration) {
	fullKey := c.buildKey(key)

	bytes, err := json.Marshal(value)
	if err != nil {
		return
	}

	_ = c.client.Set(ctx, fullKey, bytes, expiration).Err()
}

func (c *RedisCache) Delete(ctx context.Context, key string) {
	fullKey := c.buildKey(key)
	_ = c.client.Del(ctx, fullKey).Err()
}

func (c *RedisCache) Flush(ctx context.Context) {
	pattern := c.namespace + ":*"

	iter := c.client.Scan(ctx, 0, pattern, 0).Iterator()
	for iter.Next(ctx) {
		_ = c.client.Del(ctx, iter.Val()).Err()
	}
}

func (c *RedisCache) GetOrSet(
	ctx context.Context,
	key string,
	fn func(ctx context.Context) (any, time.Duration, error),
) (any, error) {

	if val, ok := c.Get(ctx, key); ok {
		return val, nil
	}

	value, ttl, err := fn(ctx)
	if err != nil {
		return nil, err
	}

	c.Set(ctx, key, value, ttl)

	return value, nil
}

func (c *RedisCache) Close(ctx context.Context) error {
	return c.client.Close()
}

var _ domain.Cache = (*RedisCache)(nil)
