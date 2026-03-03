package domain

import "github.com/vayload/plug-registry/internal/shared/errors"

var (
	ErrNotResultSet = errors.New("database: result not set")
	ErrNotFound     = errors.New("resource not found")
)
