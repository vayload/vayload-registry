package operator

import "reflect"

func Optional[T any](ptr *T) any {
	if ptr == nil {
		return nil
	}
	return *ptr
}

func Coalesce[T any](values ...T) T {
	for _, v := range values {
		if !reflect.ValueOf(v).IsZero() {
			return v
		}
	}
	var zero T
	return zero
}
