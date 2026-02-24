package container

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
)

// Lifetime defines the lifespan of a service
type Lifetime int

const (
	Singleton Lifetime = iota
	Transient
)

// Closer allows a service to release resources when deleted
type Closer interface {
	Close() error
}

type ContextCloser interface {
	Close(ctx context.Context) error
}

// Provider creates a service instance
type Provider func(c *Container) (any, error)

// entry stores service metadata
type entry struct {
	provider Provider
	lifetime Lifetime
	instance any
	typ      reflect.Type // cached type for fast GetInto
}

type Container struct {
	mu       sync.RWMutex
	services map[string]*entry
	ctx      context.Context
}

func New(ctx context.Context) *Container {
	return &Container{
		services: make(map[string]*entry),
		ctx:      ctx,
	}
}

func (c *Container) Set(name string, instance any) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.services[name]; ok {
		return
	}

	c.services[name] = &entry{
		instance: instance,
		lifetime: Singleton,
		typ:      reflect.TypeOf(instance),
	}
}

func (c *Container) Register(name string, lifetime Lifetime, p Provider) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.services[name]; ok {
		return
	}
	c.services[name] = &entry{
		provider: p,
		lifetime: lifetime,
	}
}

// Get returns the service instance, creating it if necessary
func (c *Container) Get(name string) (any, error) {
	c.mu.RLock()
	item, ok := c.services[name]
	c.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("container: service %s not found", name)
	}
	if item.lifetime == Singleton && item.instance != nil {
		return item.instance, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if item.lifetime == Singleton && item.instance != nil {
		return item.instance, nil
	}
	if item.provider == nil {
		return nil, fmt.Errorf("container: no provider for %s", name)
	}

	instance, err := item.provider(c)
	if err != nil {
		return nil, err
	}
	if item.lifetime == Singleton {
		item.instance = instance
		item.typ = reflect.TypeOf(instance)
	}
	return instance, nil
}

// GetInto injects a service into a pointer. Validates type using cached entry.typ
func (c *Container) GetInto(name string, target any) error {
	c.mu.RLock()
	item, ok := c.services[name]
	c.mu.RUnlock()
	if !ok {
		return fmt.Errorf("container: service %s not found", name)
	}

	tVal := reflect.ValueOf(target)
	if tVal.Kind() != reflect.Ptr || tVal.IsNil() {
		return errors.New("container: target must be a non-nil pointer")
	}

	if item.typ != nil && tVal.Elem().Type() != item.typ {
		return fmt.Errorf("container: target type mismatch for %s (expected *%v)", name, item.typ)
	}

	val, err := c.Get(name)
	if err != nil {
		return err
	}

	tVal.Elem().Set(reflect.ValueOf(val))
	return nil
}

// MapTo is a generic function that maps a service to a specific type
func MapTo[T any](c *Container, name string) (T, error) {
	val, err := c.Get(name)
	if err != nil {
		var zero T
		return zero, err
	}
	typed, ok := val.(T)
	if !ok {
		var zero T
		return zero, fmt.Errorf("container: service %s is not of type %T", name, zero)
	}
	return typed, nil
}

// Delete removes a service and calls Drop() if implemented
func (c *Container) Delete(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if item, ok := c.services[name]; ok {
		if item.lifetime == Singleton && item.instance != nil {
			if d, ok := item.instance.(Closer); ok {
				_ = d.Close()
			}
			if d, ok := item.instance.(ContextCloser); ok {
				_ = d.Close(c.ctx)
			}
		}
		delete(c.services, name)
	}
}

// Flush clears all services, dropping resources for singletons
func (c *Container) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for name, item := range c.services {
		if item.instance != nil {
			if d, ok := item.instance.(Closer); ok {
				_ = d.Close()
			}
			if d, ok := item.instance.(ContextCloser); ok {
				_ = d.Close(c.ctx)
			}
		}
		delete(c.services, name)
	}
}

func (c *Container) Context() context.Context {
	return c.ctx
}
