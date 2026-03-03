package errors

import (
	"errors"
	"fmt"
)

type ErrorKind uint8

const (
	ErrorKindUnknown ErrorKind = iota

	ErrorKindUnauthorized // 401
	ErrorKindForbidden    // 403
	ErrorKindJwt          // 401
	ErrorKindInvalidCredentials

	ErrorKindNotFound      // 404
	ErrorKindAlreadyExists // 409
	ErrorKindConflict      // 409

	ErrorKindValidation // 400
	ErrorKindBadRequest // 400
	ErrorKindPreconditionFailed

	ErrorKindInternal           // 500
	ErrorKindServiceUnavailable // 503
	ErrorKindDeadlineExceeded   // Timeout
	ErrorKindRateLimit          // 429

	ErrorKindNotImplemented
	ErrorKindUnprocessableEntity // 422
)

const (
	// Resource codes
	CodeResourceNotFound       = "RESOURCE_NOT_FOUND"
	CodeResourceAlreadyExists  = "RESOURCE_ALREADY_EXISTS"
	CodeResourceCreationFailed = "RESOURCE_CREATION_FAILED"
	CodeResourceUpdateFailed   = "RESOURCE_UPDATE_FAILED"
	CodeResourceDeletionFailed = "RESOURCE_DELETION_FAILED"

	// Validation codes
	CodeValidationFailed = "VALIDATION_FAILED"
	CodeInvalidInput     = "INVALID_INPUT"
	CodeMissingField     = "MISSING_REQUIRED_FIELD"
	CodeInvalidFormat    = "INVALID_FORMAT"

	// Auth codes
	CodeUnauthorized       = "UNAUTHORIZED"
	CodeForbidden          = "FORBIDDEN"
	CodeInvalidCredentials = "INVALID_CREDENTIALS"
	CodeTokenExpired       = "TOKEN_EXPIRED"
	CodeTokenInvalid       = "TOKEN_INVALID"
	CodeSessionExpired     = "SESSION_EXPIRED"

	// Operation codes
	CodeOperationFailed    = "OPERATION_FAILED"
	CodeOperationTimeout   = "OPERATION_TIMEOUT"
	CodeOperationCancelled = "OPERATION_CANCELLED"

	// State codes
	CodeConflict           = "CONFLICT"
	CodeAlreadyExists      = "ALREADY_EXISTS"
	CodeAlreadyProcessed   = "ALREADY_PROCESSED"
	CodeExpired            = "EXPIRED"
	CodePreconditionFailed = "PRECONDITION_FAILED"

	// External service codes
	CodeServiceUnavailable = "SERVICE_UNAVAILABLE"
	CodeExternalError      = "EXTERNAL_SERVICE_ERROR"

	// Rate limiting
	CodeRateLimited     = "RATE_LIMITED"
	CodeTooManyAttempts = "TOO_MANY_ATTEMPTS"

	// Database codes (internal use)
	CodeNoRowsAffected = "NO_ROWS_AFFECTED"
	CodeDuplicateEntry = "DUPLICATE_ENTRY"
)

// Err represents a domain error with kind, code, context and optional details
type Err struct {
	Kind       ErrorKind      `json:"kind"`
	StatusCode int            `json:"status_code"` // Kept for backward compatibility
	Code       string         `json:"code"`        // Centralized code (e.g., RESOURCE_NOT_FOUND)
	Reason     string         `json:"reason"`      // Reason for the error (e.g., "not_found", "invalid_input")
	Context    string         `json:"context"`     // Module context (e.g., "users", "payments", "medications")
	Message    string         `json:"message"`     // Human-readable message (informative, in English)
	Details    map[string]any `json:"details,omitempty"`
	Cause      error          `json:"cause,omitempty"`
}

type Error interface {
	Status() int
	Error() string
	Cause() error
	Details() map[string]any
	Message() string
	Code() string
}

type SimpleError struct {
	message string
}

func New(message string) error {
	return &SimpleError{
		message: message,
	}
}

func Is(err error, target error) bool {
	return errors.Is(err, target)
}

func As(err error, target any) bool {
	return errors.As(err, target)
}

func (e *SimpleError) Error() string {
	return e.message
}

// NewErr creates a new error (deprecated: use NewDomainErr instead)
func NewErr(status int, code, message string, details map[string]any, cause error) *Err {
	return &Err{
		Kind:       statusToKind(status),
		StatusCode: status,
		Code:       code,
		Message:    message,
		Details:    details,
		Cause:      cause,
	}
}

// NewDomainErr creates a new domain error with ErrorKind and context
func NewDomainErr(kind ErrorKind, code, context, message string, details map[string]any, cause error) *Err {
	return &Err{
		Kind:       kind,
		StatusCode: kindToStatus(kind),
		Code:       code,
		Context:    context,
		Message:    message,
		Details:    details,
		Cause:      cause,
	}
}

func (e *Err) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s:%s] %s: %v", e.Context, e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s:%s] %s", e.Context, e.Code, e.Message)
}

func (e *Err) Status() int {
	return e.StatusCode
}

func (e *Err) GetKind() ErrorKind {
	return e.Kind
}

func (e *Err) GetContext() string {
	return e.Context
}

func (e *Err) GetCode() string {
	return e.Code
}

func statusToKind(status int) ErrorKind {
	switch {
	case status == 400:
		return ErrorKindBadRequest
	case status == 401:
		return ErrorKindUnauthorized
	case status == 403:
		return ErrorKindForbidden
	case status == 404:
		return ErrorKindNotFound
	case status == 409:
		return ErrorKindConflict
	case status == 412:
		return ErrorKindPreconditionFailed
	case status == 422:
		return ErrorKindValidation
	case status == 429:
		return ErrorKindRateLimit
	case status == 503:
		return ErrorKindServiceUnavailable
	case status == 504:
		return ErrorKindDeadlineExceeded
	case status >= 500:
		return ErrorKindInternal
	default:
		return ErrorKindUnknown
	}
}

func kindToStatus(kind ErrorKind) int {
	switch kind {
	case ErrorKindNotFound:
		return 404
	case ErrorKindValidation:
		return 422
	case ErrorKindBadRequest:
		return 400
	case ErrorKindConflict:
		return 409
	case ErrorKindUnauthorized:
		return 401
	case ErrorKindForbidden:
		return 403
	case ErrorKindInternal:
		return 500
	case ErrorKindServiceUnavailable:
		return 503
	case ErrorKindDeadlineExceeded:
		return 504
	case ErrorKindRateLimit:
		return 429
	case ErrorKindPreconditionFailed:
		return 412
	default:
		return 500
	}
}
