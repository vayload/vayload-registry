//go:build !cache_redis

package cache

func NewCache(config CacheConfig) (*LRUCache[string, any], error) {
	return NewLRUCache[string, any](100), nil
}
