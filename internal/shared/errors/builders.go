package errors

// ErrBuilder provides a fluent API for building errors
type ErrBuilder struct {
	*Err
}

// With adds a key-value pair to the error details
func (b *ErrBuilder) With(key string, value any) *ErrBuilder {
	if b.Details == nil {
		b.Details = make(map[string]any)
	}
	b.Details[key] = value
	return b
}

// Cause sets the underlying error cause
func (b *ErrBuilder) Cause(cause error) *ErrBuilder {
	b.Err.Cause = cause
	return b
}

// Reason sets a specific reason for the error (for i18n/frontend)
func (b *ErrBuilder) Reason(reason string) *ErrBuilder {
	b.Err.Reason = reason
	return b
}

// Context sets the module context (e.g., "auth", "payments")
func (b *ErrBuilder) Context(context string) *ErrBuilder {
	b.Err.Context = context
	return b
}

// Build returns the underlying error (optional, ErrBuilder already implements error)
func (b *ErrBuilder) Build() *Err {
	b.Err.StatusCode = kindToStatus(b.Err.Kind)
	return b.Err
}

// Error implements the error interface
func (b *ErrBuilder) Error() string {
	return b.Err.Error()
}

func (b *ErrBuilder) Msg(message string) *ErrBuilder {
	b.Err.Message = message
	return b
}

// ============================================================================
// 4xx Client Errors
// ============================================================================

// BadRequest creates a 400 Bad Request error
func BadRequest(message string) *ErrBuilder {
	return &ErrBuilder{
		Err: &Err{
			Kind:       ErrorKindBadRequest,
			StatusCode: 400,
			Code:       CodeInvalidInput,
			Message:    message,
		},
	}
}

// Unauthorized creates a 401 Unauthorized error
func Unauthorized(message string) *ErrBuilder {
	return &ErrBuilder{
		Err: &Err{
			Kind:       ErrorKindUnauthorized,
			StatusCode: 401,
			Code:       CodeUnauthorized,
			Message:    message,
		},
	}
}

// InvalidCredentials creates a 401 error for invalid credentials
func InvalidCredentials(message string) *ErrBuilder {
	return &ErrBuilder{
		Err: &Err{
			Kind:       ErrorKindUnauthorized,
			StatusCode: 401,
			Code:       CodeInvalidCredentials,
			Message:    message,
		},
	}
}

// TokenExpired creates a 401 error for expired tokens
func TokenExpired(message string) *ErrBuilder {
	return &ErrBuilder{
		Err: &Err{
			Kind:       ErrorKindUnauthorized,
			StatusCode: 401,
			Code:       CodeTokenExpired,
			Message:    message,
		},
	}
}

// TokenInvalid creates a 401 error for invalid tokens
func TokenInvalid(message string) *ErrBuilder {
	return &ErrBuilder{
		Err: &Err{
			Kind:       ErrorKindUnauthorized,
			StatusCode: 401,
			Code:       CodeTokenInvalid,
			Message:    message,
		},
	}
}

// Forbidden creates a 403 Forbidden error
func Forbidden(message string) *ErrBuilder {
	return &ErrBuilder{
		Err: &Err{
			Kind:       ErrorKindForbidden,
			StatusCode: 403,
			Code:       CodeForbidden,
			Message:    message,
		},
	}
}

// NotFound creates a 404 Not Found error
func NotFound(message string) *ErrBuilder {
	return &ErrBuilder{
		Err: &Err{
			Kind:       ErrorKindNotFound,
			StatusCode: 404,
			Code:       CodeResourceNotFound,
			Message:    message,
		},
	}
}

// Conflict creates a 409 Conflict error
func Conflict(message string) *ErrBuilder {
	return &ErrBuilder{
		Err: &Err{
			Kind:       ErrorKindConflict,
			StatusCode: 409,
			Code:       CodeConflict,
			Message:    message,
		},
	}
}

// AlreadyExists creates a 409 error for duplicate resources
func AlreadyExists(message string) *ErrBuilder {
	return &ErrBuilder{
		Err: &Err{
			Kind:       ErrorKindConflict,
			StatusCode: 409,
			Code:       CodeAlreadyExists,
			Message:    message,
		},
	}
}

// PreconditionFailed creates a 412 Precondition Failed error
func PreconditionFailed(message string) *ErrBuilder {
	return &ErrBuilder{
		Err: &Err{
			Kind:       ErrorKindPreconditionFailed,
			StatusCode: 412,
			Code:       CodePreconditionFailed,
			Message:    message,
		},
	}
}

// Validation creates a 422 Unprocessable Entity error
func Validation(message string) *ErrBuilder {
	return &ErrBuilder{
		Err: &Err{
			Kind:       ErrorKindValidation,
			StatusCode: 422,
			Code:       CodeValidationFailed,
			Message:    message,
		},
	}
}

// InvalidFormat creates a 422 error for format validation failures
func InvalidFormat(message string) *ErrBuilder {
	return &ErrBuilder{
		Err: &Err{
			Kind:       ErrorKindValidation,
			StatusCode: 422,
			Code:       CodeInvalidFormat,
			Message:    message,
		},
	}
}

// MissingField creates a 422 error for missing required fields
func MissingField(message string) *ErrBuilder {
	return &ErrBuilder{
		Err: &Err{
			Kind:       ErrorKindValidation,
			StatusCode: 422,
			Code:       CodeMissingField,
			Message:    message,
		},
	}
}

// RateLimited creates a 429 Too Many Requests error
func RateLimited(message string) *ErrBuilder {
	return &ErrBuilder{
		Err: &Err{
			Kind:       ErrorKindRateLimit,
			StatusCode: 429,
			Code:       CodeRateLimited,
			Message:    message,
		},
	}
}

// TooManyAttempts creates a 429 error for too many attempts
func TooManyAttempts(message string) *ErrBuilder {
	return &ErrBuilder{
		Err: &Err{
			Kind:       ErrorKindRateLimit,
			StatusCode: 429,
			Code:       CodeTooManyAttempts,
			Message:    message,
		},
	}
}

// ============================================================================
// 5xx Server Errors
// ============================================================================

// Internal creates a 500 Internal Server Error
func Internal(message string) *ErrBuilder {
	return &ErrBuilder{
		Err: &Err{
			Kind:       ErrorKindInternal,
			StatusCode: 500,
			Code:       CodeOperationFailed,
			Message:    message,
		},
	}
}

// CreationFailed creates a 500 error for resource creation failures
func CreationFailed(message string) *ErrBuilder {
	return &ErrBuilder{
		Err: &Err{
			Kind:       ErrorKindInternal,
			StatusCode: 500,
			Code:       CodeResourceCreationFailed,
			Message:    message,
		},
	}
}

// UpdateFailed creates a 500 error for resource update failures
func UpdateFailed(message string) *ErrBuilder {
	return &ErrBuilder{
		Err: &Err{
			Kind:       ErrorKindInternal,
			StatusCode: 500,
			Code:       CodeResourceUpdateFailed,
			Message:    message,
		},
	}
}

// DeletionFailed creates a 500 error for resource deletion failures
func DeletionFailed(message string) *ErrBuilder {
	return &ErrBuilder{
		Err: &Err{
			Kind:       ErrorKindInternal,
			StatusCode: 500,
			Code:       CodeResourceDeletionFailed,
			Message:    message,
		},
	}
}

// Unavailable creates a 503 Service Unavailable error
func Unavailable(message string) *ErrBuilder {
	return &ErrBuilder{
		Err: &Err{
			Kind:       ErrorKindServiceUnavailable,
			StatusCode: 503,
			Code:       CodeServiceUnavailable,
			Message:    message,
		},
	}
}

// ExternalError creates a 503 error for external service failures
func ExternalError(message string) *ErrBuilder {
	return &ErrBuilder{
		Err: &Err{
			Kind:       ErrorKindServiceUnavailable,
			StatusCode: 503,
			Code:       CodeExternalError,
			Message:    message,
		},
	}
}

// Timeout creates a 504 Gateway Timeout error
func Timeout(message string) *ErrBuilder {
	return &ErrBuilder{
		Err: &Err{
			Kind:       ErrorKindDeadlineExceeded,
			StatusCode: 504,
			Code:       CodeOperationTimeout,
			Message:    message,
		},
	}
}
