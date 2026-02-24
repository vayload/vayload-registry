package collect

import (
	"fmt"
	"slices"
	"sort"
)

// Filtered returns a new slice containing only the elements that satisfy the predicate
func Filter[T any](s []T, predicate func(T) bool) []T {
	result := make([]T, 0, len(s))
	for _, v := range s {
		if predicate(v) {
			result = append(result, v)
		}
	}
	return result
}

// Partition divides the slice into two slices based on the predicate
func Partition[T any](s []T, predicate func(T) bool) ([]T, []T) {
	truePart := make([]T, 0)
	falsePart := make([]T, 0)
	for _, v := range s {
		if predicate(v) {
			truePart = append(truePart, v)
		} else {
			falsePart = append(falsePart, v)
		}
	}
	return truePart, falsePart
}

// Map applies a function to each element of the slice and returns a new slice with the results
func Map[T any, R any](s []T, mapper func(T, int) R) []R {
	if len(s) == 0 {
		return []R{}
	}
	result := make([]R, 0, len(s))
	for i, v := range s {
		result = append(result, mapper(v, i))
	}
	return result
}

// Each applies a function to each element of the slice
func Each[T any](s []T, f func(T, int)) {
	for i, v := range s {
		f(v, i)
	}
}

// Unique returns a new slice with unique elements
func Unique[T comparable](s []T) []T {
	m := make(map[T]struct{})
	for _, v := range s {
		m[v] = struct{}{}
	}
	result := make([]T, 0, len(m))
	for k := range m {
		result = append(result, k)
	}
	return result
}

// Sort returns a new slice sorted according to the provided less function
func Sort[T comparable](s []T, less func(a, b T) bool) []T {
	if len(s) == 0 {
		return s
	}
	result := make([]T, len(s))
	copy(result, s)
	sort.Slice(result, func(i, j int) bool {
		return less(result[i], result[j])
	})
	return result
}

// Return true if all elements in s satisfy the predicate
func Every[T any](target []T, predicate func(T) bool) bool {
	for _, v := range target {
		if !predicate(v) {
			return false
		}
	}
	return true
}

// Return true if at least one element in s satisfies the predicate
func Some[T any](target []T, predicate func(T) bool) bool {
	return slices.ContainsFunc(target, predicate)
}

// Reduce applies a function against an accumulator and each element to reduce it to a single value
func Reduce[T any, R any](s []T, reducer func(R, T, int) R, initialValue R) R {
	result := initialValue
	for i, v := range s {
		result = reducer(result, v, i)
	}
	return result
}

// Find returns the first element that satisfies the predicate and true, or zero value and false
func Find[T any](s []T, predicate func(T) bool) T {
	for _, v := range s {
		if predicate(v) {
			return v
		}
	}
	var zero T
	return zero
}

// FindIndex returns the index of the first element that satisfies the predicate, or -1
func FindIndex[T any](s []T, predicate func(T) bool) int {
	for i, v := range s {
		if predicate(v) {
			return i
		}
	}
	return -1
}

// Chunk divides the slice into chunks of specified size
func Chunk[T any](s []T, size int) [][]T {
	if size <= 0 {
		return nil
	}
	var chunks [][]T
	for i := 0; i < len(s); i += size {
		end := min(i+size, len(s))
		chunks = append(chunks, s[i:end])
	}
	return chunks
}

// Flatten flattens a slice of slices into a single slice
func Flatten[T any](s [][]T) []T {
	var result []T
	for _, inner := range s {
		result = append(result, inner...)
	}
	return result
}

// FlatMap maps and flattens in one operation
func FlatMap[T any, R any](s []T, mapper func(T) []R) []R {
	var result []R
	for _, v := range s {
		result = append(result, mapper(v)...)
	}
	return result
}

// Reverse returns a new slice with elements in reverse order
func Reverse[T any](s []T) []T {
	result := make([]T, len(s))
	for i, v := range s {
		result[len(s)-1-i] = v
	}
	return result
}

// Take returns the first n elements
func Take[T any](s []T, n int) []T {
	if n >= len(s) {
		return slices.Clone(s)
	}
	if n <= 0 {
		return []T{}
	}
	return slices.Clone(s[:n])
}

// TakeWhile takes elements while the predicate is true
func TakeWhile[T any](s []T, predicate func(T) bool) []T {
	var result []T
	for _, v := range s {
		if !predicate(v) {
			break
		}
		result = append(result, v)
	}
	return result
}

// Skip returns a slice without the first n elements
func Skip[T any](s []T, n int) []T {
	if n >= len(s) {
		return []T{}
	}
	if n <= 0 {
		return slices.Clone(s)
	}
	return slices.Clone(s[n:])
}

// SkipWhile skips elements while the predicate is true
func SkipWhile[T any](s []T, predicate func(T) bool) []T {
	for i, v := range s {
		if !predicate(v) {
			return slices.Clone(s[i:])
		}
	}
	return []T{}
}

// GroupBy groups elements by a key function
func GroupBy[T any, K comparable](s []T, keyFunc func(T) K) map[K][]T {
	result := make(map[K][]T)
	for _, v := range s {
		key := keyFunc(v)
		result[key] = append(result[key], v)
	}
	return result
}

// Count returns the number of elements that satisfy the predicate
func Count[T any](s []T, predicate func(T) bool) int {
	count := 0
	for _, v := range s {
		if predicate(v) {
			count++
		}
	}
	return count
}

// Min returns the minimum element according to the less function
func Min[T any](s []T, less func(T, T) bool) (T, bool) {
	if len(s) == 0 {
		var zero T
		return zero, false
	}
	min := s[0]
	for i := 1; i < len(s); i++ {
		if less(s[i], min) {
			min = s[i]
		}
	}
	return min, true
}

// Max returns the maximum element according to the less function
func Max[T any](s []T, less func(T, T) bool) (T, bool) {
	if len(s) == 0 {
		var zero T
		return zero, false
	}
	max := s[0]
	for i := 1; i < len(s); i++ {
		if less(max, s[i]) {
			max = s[i]
		}
	}
	return max, true
}

// MapValues returns a slice of the values from the map
func MapValues[K comparable, V any](m map[K]V) []V {
	values := make([]V, 0, len(m))
	for _, v := range m {
		values = append(values, v)
	}
	return values
}

// Sum returns the sum of all elements using the provided function
func Sum[T any, R any](s []T, selector func(T) R, add func(R, R) R) R {
	var sum R
	for _, v := range s {
		sum = add(sum, selector(v))
	}
	return sum
}

// Intersect returns the intersection of two slices
func Intersect[T comparable](s1, s2 []T) []T {
	m := make(map[T]struct{})
	for _, v := range s1 {
		m[v] = struct{}{}
	}

	var result []T
	seen := make(map[T]struct{})
	for _, v := range s2 {
		if _, exists := m[v]; exists {
			if _, alreadySeen := seen[v]; !alreadySeen {
				result = append(result, v)
				seen[v] = struct{}{}
			}
		}
	}
	return result
}

// Union returns the union of two slices without duplicates
func Union[T comparable](s1, s2 []T) []T {
	m := make(map[T]struct{})
	var result []T

	for _, v := range s1 {
		if _, exists := m[v]; !exists {
			m[v] = struct{}{}
			result = append(result, v)
		}
	}

	for _, v := range s2 {
		if _, exists := m[v]; !exists {
			m[v] = struct{}{}
			result = append(result, v)
		}
	}

	return result
}

// Difference returns elements in s1 that are not in s2
func Difference[T comparable](s1, s2 []T) []T {
	m := make(map[T]struct{})
	for _, v := range s2 {
		m[v] = struct{}{}
	}

	var result []T
	for _, v := range s1 {
		if _, exists := m[v]; !exists {
			result = append(result, v)
		}
	}
	return result
}

// Zip combines two slices into a slice of pairs
func Zip[T, U any](s1 []T, s2 []U) [][2]any {
	minLen := min(len(s2), len(s1))

	result := make([][2]any, minLen)
	for i := range minLen {
		result[i] = [2]any{s1[i], s2[i]}
	}
	return result
}

// Pick creates a map from a slice using a key function
func Pick[T any, K comparable](s []T, keyFunc func(T) K) map[K]T {
	result := make(map[K]T)
	for _, v := range s {
		key := keyFunc(v)
		result[key] = v
	}
	return result
}

// Includes checks if a slice includes a specific element
func Includes[S ~[]E, E comparable](s S, v E) bool {
	return slices.Index(s, v) >= 0
}

// WrapString converts an interface{} to a slice of strings
func WrapString(s any) []string {
	if s == nil {
		return []string{}
	}

	if str, ok := s.(string); ok {
		if str == "null" {
			return []string{}
		}

		return []string{str}
	}

	return []string{fmt.Sprintf("%v", s)}
}

// DifferenceWith returns the difference between two slices using a custom comparison function
func DifferenceWith[T any](a, b []T, cmp func(x, y T) bool) []T {
	var result []T
	for _, itemA := range a {
		found := false
		for _, itemB := range b {
			if cmp(itemA, itemB) {
				found = true
				break
			}
		}
		if !found {
			result = append(result, itemA)
		}
	}
	return result
}
