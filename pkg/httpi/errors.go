package httpi

import (
	"fmt"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/vayload/plug-registry/internal/shared/errors"
	"github.com/vayload/plug-registry/pkg/logger"
)

type LogLevel int

const (
	LogLevelDebug LogLevel = iota // Log everything
	LogLevelInfo                  // Log info and above
	LogLevelWarn                  // Log warnings and above (client errors 4xx)
	LogLevelError                 // Log errors only (server errors 5xx)
	LogLevelFatal                 // Log only fatal/critical errors (internal, unavailable, timeout)
	LogLevelNone                  // Disable logging
)

// Default log level - can be changed at runtime
var ErrorHandlerLogLevel = LogLevelDebug

type StatusText string

const (
	StatusTextCreated             StatusText = "CREATED"
	StatusTextOK                  StatusText = "OK"
	StatusTextNoContent           StatusText = "NO_CONTENT"
	StatusTextBadRequest          StatusText = "BAD_REQUEST"
	StatusTextUnauthorized        StatusText = "UNAUTHORIZED"
	StatusTextForbidden           StatusText = "FORBIDDEN"
	StatusTextNotFound            StatusText = "NOT_FOUND"
	StatusTextUnprocessableEntity StatusText = "UNPROCESSABLE_ENTITY"
	StatusTextConflict            StatusText = "CONFLICT"
	StatusTextValidation          StatusText = "VALIDATION_ERROR"
	StatusTextTooManyRequests     StatusText = "TOO_MANY_REQUESTS"
	StatusTextInternal            StatusText = "INTERNAL_ERROR"
	StatusTextUnavailable         StatusText = "UNAVAILABLE"
	StatusTextTimeout             StatusText = "TIMEOUT"
)

type Err struct {
	Status int            `json:"status"`
	Err    HttpError      `json:"error"`
	Meta   map[string]any `json:"meta,omitempty"` // Additional metadata
	Cause  error          `json:"-"`              // Original error, not included in JSON response
}

// NewErr creates a new standardized HTTP error
func NewErr(status int, code, message string, details any, cause error) *Err {
	return &Err{
		Status: status,
		Err: HttpError{
			Code:    code,
			Message: message,
			Details: details,
		},
		Meta:  map[string]any{},
		Cause: cause,
	}
}

// Error returns the error message (implements error interface)
func (e *Err) Error() string {
	return e.Err.Message
}

// Unwrap returns the underlying cause (for errors.Is / errors.As)
func (e *Err) Unwrap() error {
	return e.Cause
}

// Log logs the error (optional)
func (e *Err) Log() *Err {
	logger.E(e.Cause, logger.Fields{"code": e.Err.Code, "message": e.Err.Message})
	return e
}

func newWithOptionalDetails(status int, code, message string, cause error, details ...any) *Err {
	var d any
	if len(details) > 0 {
		d = details[0]
	}
	return NewErr(status, code, message, d, cause)
}

// 400 - Bad Request
func ErrBadRequest(cause error, details ...any) *Err {
	return newWithOptionalDetails(http.StatusBadRequest, "BAD_REQUEST", "Invalid request", cause, details...)
}

// 401 - Unauthorized
func ErrUnauthorized(cause error, details ...any) *Err {
	return newWithOptionalDetails(http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required", cause, details...)
}

// 403 - Forbidden
func ErrForbidden(cause error, details ...any) *Err {
	return newWithOptionalDetails(http.StatusForbidden, "FORBIDDEN", "Access forbidden", cause, details...)
}

// 404 - Not Found
func ErrNotFound(cause error, details ...any) *Err {
	return newWithOptionalDetails(http.StatusNotFound, "RESOURCE_NOT_FOUND", "Resource not found", cause, details...)
}

// Unprocessable Entity (422) - Validation errors
func ErrUnprocessableEntity(cause error, details ...any) *Err {
	return newWithOptionalDetails(http.StatusUnprocessableEntity, "UNPROCESSABLE_ENTITY", "Validation error", cause, details...)
}

// 409 - Conflict
func ErrConflict(cause error, details ...any) *Err {
	return newWithOptionalDetails(http.StatusConflict, "CONFLICT", "Conflict occurred", cause, details...)
}

// 422 - Unprocessable Entity (validation)
func ErrValidation(cause error, details ...any) *Err {
	return newWithOptionalDetails(http.StatusUnprocessableEntity, "VALIDATION_ERROR", "Validation failed", cause, details...)
}

func ErrTooManyRequests(cause error, details ...any) *Err {
	return newWithOptionalDetails(http.StatusTooManyRequests, "TOO_MANY_REQUESTS", "Rate limit exceeded", cause, details...)
}

// 500 - Internal Server Error
func ErrInternal(cause error, details ...any) *Err {
	return newWithOptionalDetails(http.StatusInternalServerError, "INTERNAL_ERROR", "Internal server error", cause, details...)
}

// ErrWrapping wraps an error with additional context
func ErrWrapping(cause error, details ...any) *Err {
	var httErr *Err
	if errors.As(cause, &httErr) {
		newDetails := httErr.Err.Details
		if len(details) > 0 {
			newDetails = details[0]
		}
		return NewErr(httErr.Status, httErr.Err.Code, httErr.Err.Message, newDetails, cause)
	}

	return ErrInternal(cause, details...)
}

func MapRequestException(cause error, details ...any) *Err {
	var httErr *Err
	if errors.As(cause, &httErr) {
		newDetails := httErr.Err.Details
		if len(details) > 0 {
			newDetails = details[0]
		}

		return NewErr(httErr.Status, httErr.Err.Code, httErr.Err.Message, newDetails, cause)
	}

	return ErrInternal(cause, details...)
}

func HandleException(cause error, details ...any) *Err {
	return ErrWrapping(cause, details...)
}

func MappingErrToHttp(err error) error {
	if err == nil {
		return nil
	}

	// Use type switch for direct type checking (not recursive like errors.As)
	// This prevents matching errors nested in Cause
	switch e := err.(type) {
	case *errors.ErrBuilder:
		return mapErrToHttp(e.Err)
	case *errors.Err:
		return mapErrToHttp(e)
	case *HttpClientErr:
		return &Err{
			Status: e.Status,
			Err: HttpError{
				Code:    e.Code,
				Message: e.Message,
			},
			Cause: e.Cause,
		}
	case *Err:
		return e
	}

	// Fallback: try errors.As for wrapped errors (but only if direct check failed)
	var builderErr *errors.ErrBuilder
	if errors.As(err, &builderErr) {
		return mapErrToHttp(builderErr.Err)
	}

	var domainErr *errors.Err
	if errors.As(err, &domainErr) {
		return mapErrToHttp(domainErr)
	}

	return ErrInternal(fmt.Errorf("unexpected error: %w", err))
}

func mapErrToHttp(domainErr *errors.Err) *Err {
	httpErr := HttpError{
		Code:    domainErr.Code,
		Message: domainErr.Message,
	}
	if domainErr.Details != nil {
		httpErr.Details = domainErr.Details
	}
	if domainErr.Reason != "" {
		httpErr.Reason = domainErr.Reason
	}

	return &Err{
		Status: domainErr.StatusCode,
		Err:    httpErr,
		Cause:  domainErr.Cause,
	}
}

func HttpErrorHandler(req HttpRequest, res HttpResponse, err error) error {
	requestCtx := logger.Fields{
		"ip":         req.GetIP(),
		"user_agent": req.GetUserAgent(),
	}

	shouldLogged := false
	var meta map[string]any
	requestId := req.GetHeader("X-Request-Id")
	if requestId != "" {
		meta = map[string]any{
			"request_id": requestId,
		}
		requestCtx["request_id"] = requestId
	}

	// Automatic check for nil error (marks as error because it should not happen)
	if err == nil {
		logger.E(errors.New("error handler called with <nil> error"), requestCtx)
		return nil
	}

	statusCode := 500
	code := "INTERNAL_SERVER_ERROR"
	message := "Internal server error"
	var details any
	var reason string

	// Use type switch to avoid recursive matching via errors.As
	// This ensures we match the TOP-LEVEL error type, not nested causes
	// TODO: Migrate to errors.Is() when go 1.21 is available
	switch e := err.(type) {
	case *Err:
		statusCode = e.Status
		code = e.Err.Code
		message = e.Err.Message
		details = e.Err.Details
		reason = e.Err.Reason

		if shouldLog(statusCode) {
			cause := e.Cause
			if cause == nil {
				cause = errors.New(message)
			}
			logByStatus(statusCode, cause, requestCtx, logger.Fields{"code": code, "message": message})
			shouldLogged = true
		}

	case *HttpClientErr:
		statusCode = e.Status
		code = e.Code
		message = e.Message

		if shouldLog(statusCode) {
			cause := e.Cause
			if cause == nil {
				cause = errors.New(message)
			}
			logByStatus(statusCode, cause, requestCtx, logger.Fields{"code": code, "message": message, "type": "http_client"})
			shouldLogged = true
		}

	case *fiber.Error:
		statusCode = e.Code
		code = "SYSTEM_ERROR"
		message = e.Message

		if shouldLog(statusCode) {
			logByStatus(statusCode, e, requestCtx, logger.Fields{"code": code, "message": message, "type": "fiber"})
			shouldLogged = true
		}

	default:
		// Fallback: try errors.As but only for wrapped errors
		var httpiErr *Err
		if errors.As(err, &httpiErr) {
			statusCode = httpiErr.Status
			code = httpiErr.Err.Code
			message = httpiErr.Err.Message
			details = httpiErr.Err.Details
			reason = httpiErr.Err.Reason

			if shouldLog(statusCode) {
				cause := httpiErr.Cause
				if cause == nil {
					cause = errors.New(message)
				}
				logByStatus(statusCode, cause, requestCtx, logger.Fields{"code": code, "message": message})
				shouldLogged = true
			}
		}
	}

	finalResponse := Error{
		Status: "error",
		Error: HttpError{
			Code:    code,
			Message: message,
		},
	}
	if meta != nil {
		finalResponse.Meta = meta
	}
	if details != nil {
		finalResponse.Error.Details = details
	}
	if reason != "" {
		finalResponse.Error.Reason = reason
	}

	if !shouldLogged {
		logger.E(err, requestCtx, logger.Fields{"code": code, "message": message})
	}

	return res.Status(statusCode).Json(finalResponse)
}

// shouldLog determines if an error should be logged based on status code and configured level
func shouldLog(statusCode int) bool {
	switch ErrorHandlerLogLevel {
	case LogLevelNone:
		return false
	case LogLevelFatal:
		// Only log 500, 503, 504 (internal, unavailable, timeout)
		return statusCode == 500 || statusCode == 503 || statusCode == 504
	case LogLevelError:
		// Log all 5xx errors
		return statusCode >= 500
	case LogLevelWarn:
		// Log 4xx and 5xx
		return statusCode >= 400
	case LogLevelInfo, LogLevelDebug:
		// Log everything
		return true
	default:
		return statusCode >= 500
	}
}

// logByStatus logs using appropriate log level based on status code
func logByStatus(statusCode int, cause error, fields ...logger.Fields) {
	// Protect against nil
	if cause == nil {
		cause = errors.New("unknown error")
	}

	switch {
	case statusCode == 500 || statusCode == 503 || statusCode == 504:
		// Critical/Fatal errors
		logger.E(cause, fields...)
	case statusCode >= 500:
		// Other server errors
		logger.E(cause, fields...)
	case statusCode >= 400:
		// Client errors - warn level
		logger.W(cause.Error(), fields...)
	default:
		// Info level for other cases
		logger.I(cause.Error(), fields...)
	}
}
