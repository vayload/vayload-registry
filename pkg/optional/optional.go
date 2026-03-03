package optional

// Optional represents an optional value.
// It wraps a pointer internally but provides a safe API.
type Optional[T any] struct {
	value *T
}

// Of creates an Optional with a non-nil value.
func Of[T any](v T) Optional[T] {
	return Optional[T]{value: &v}
}

// OfPtr creates an Optional from a pointer.
func OfPtr[T any](ptr *T) Optional[T] {
	return Optional[T]{value: ptr}
}

func Ref[T any](val T) Optional[*T] {
	return Of(&val)
}

// Empty creates an empty Optional.
func Empty[T any]() Optional[T] {
	return Optional[T]{value: nil}
}

// IsPresent returns true if the value is not nil.
func (o Optional[T]) IsPresent() bool {
	return o.value != nil
}

// IsEmpty returns true if the value is nil.
func (o Optional[T]) IsEmpty() bool {
	return o.value == nil
}

func AsRef[T any](o Optional[T]) Optional[*T] {
	if o.value == nil {
		return Empty[*T]()
	}

	return Of(o.value)
}

// Get returns the value and whether it exists.
func (o Optional[T]) Get() (T, bool) {
	if o.value == nil {
		var zero T
		return zero, false
	}
	return *o.value, true
}

// MustGet returns the value or panics if empty.
func (o Optional[T]) MustGet() T {
	if o.value == nil {
		panic("optional: value is nil")
	}
	return *o.value
}

// OrElse returns the value or a fallback.
func (o Optional[T]) OrElse(fallback T) T {
	if o.value == nil {
		return fallback
	}
	return *o.value
}

// OrElseGet returns the value or computes it from a function.
func (o Optional[T]) OrElseGet(fn func() T) T {
	if o.value == nil {
		return fn()
	}
	return *o.value
}

// Ptr returns the underlying pointer (may be nil).
func (o Optional[T]) Ptr() *T {
	return o.value
}

// IfPresent executes a function if value exists.
func (o Optional[T]) IfPresent(fn func(T)) {
	if o.value != nil {
		fn(*o.value)
	}
}

// Map transforms the value if present.
func Map[T any, R any](o Optional[T], fn func(T) R) Optional[R] {
	if o.value == nil {
		return Empty[R]()
	}
	v := fn(*o.value)
	return Of(v)
}
