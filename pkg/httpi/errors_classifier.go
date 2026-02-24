package httpi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"

	"github.com/goccy/go-json"
)

type ExternalErrorKind int

const (
	ErrKindUnknown ExternalErrorKind = iota
	ErrKindNetwork
	ErrKindTimeout
	ErrKindServer
	ErrKindClient
	ErrKindParsing
	ErrKindRateLimit
	ErrKindUnauthorized
)

type ExternalError struct {
	Kind       ExternalErrorKind
	StatusCode int
	Message    string
	Response   []byte
	Cause      error
	Retryable  bool
}

func (e *ExternalError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s (status=%d): %v", e.Message, e.StatusCode, e.Cause)
	}
	return fmt.Sprintf("%s (status=%d)", e.Message, e.StatusCode)
}

func (e *ExternalError) Unwrap() error      { return e.Cause }
func (e *ExternalError) IsRetryable() bool  { return e.Retryable }
func (e *ExternalError) KindString() string { return kindToString(e.Kind) }

func kindToString(k ExternalErrorKind) string {
	switch k {
	case ErrKindNetwork:
		return "network"
	case ErrKindTimeout:
		return "timeout"
	case ErrKindServer:
		return "server"
	case ErrKindClient:
		return "client"
	case ErrKindParsing:
		return "parsing"
	case ErrKindRateLimit:
		return "rate_limit"
	case ErrKindUnauthorized:
		return "unauthorized"
	default:
		return "unknown"
	}
}

func IsExternalError(err error, kinds ...ExternalErrorKind) bool {
	var ext *ExternalError
	if !errors.As(err, &ext) {
		return false
	}
	if len(kinds) == 0 {
		return true
	}

	return slices.Contains(kinds, ext.Kind)
}

func IsRetryable(err error) bool {
	var ext *ExternalError
	return errors.As(err, &ext) && ext.Retryable
}

func ClassifyError(err error, res *http.Response) *ExternalError {
	defer func() {
		if res != nil && res.Body != nil {
			res.Body.Close()
		}
	}()

	bytes := []byte{}
	if res != nil && res.Body != nil {
		bytes, _ = io.ReadAll(res.Body)
	}

	e := &ExternalError{
		Kind:     ErrKindUnknown,
		Response: bytes,
		Cause:    err,
	}

	if res != nil {
		e.StatusCode = res.StatusCode
	}

	if err != nil {
		return classifyErrorType(e, err)
	}
	if res != nil {
		return classifyStatusCode(e, res.StatusCode)
	}

	e.Message = "unexpected nil error and nil response"
	return e
}

func classifyErrorType(e *ExternalError, err error) *ExternalError {
	switch {
	// Context
	case errors.Is(err, context.DeadlineExceeded):
		return set(e, ErrKindTimeout, "request timeout", true)

	case errors.Is(err, context.Canceled):
		return set(e, ErrKindTimeout, "request canceled", false)

	// Network / DNS / IO
	case isNetErr(err):
		return set(e, ErrKindNetwork, "network error", true)

	case isDNSErrRetryable(err):
		return set(e, ErrKindNetwork, "DNS resolution failed", true)

	case isDNSErrFatal(err):
		return set(e, ErrKindNetwork, "DNS not found", false)

	case isConnClosed(err):
		return set(e, ErrKindNetwork, "connection closed", true)

	// JSON
	case isJSONSyntaxErr(err, e):
		return e

	case isJSONTypeErr(err, e):
		return e

	// HTTP Client
	case isHTTPClientErr(err, e):
		return classifyStatusCode(e, e.StatusCode)
	}

	return set(e, ErrKindUnknown, "unknown error", false)
}

// --- Type checks ---

func isNetErr(err error) bool {
	var ne net.Error
	return errors.As(err, &ne)
}

func isDNSErrRetryable(err error) bool {
	var d *net.DNSError
	return errors.As(err, &d) && !d.IsNotFound
}

func isDNSErrFatal(err error) bool {
	var d *net.DNSError
	return errors.As(err, &d) && d.IsNotFound
}

func isConnClosed(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

func isJSONSyntaxErr(err error, e *ExternalError) bool {
	var je *json.SyntaxError
	if errors.As(err, &je) {
		*e = *set(e, ErrKindParsing,
			fmt.Sprintf("JSON syntax error at offset %d", je.Offset),
			false,
		)
		return true
	}
	return false
}

func isJSONTypeErr(err error, e *ExternalError) bool {
	var ue *json.UnmarshalTypeError
	if errors.As(err, &ue) {
		*e = *set(e, ErrKindParsing,
			fmt.Sprintf("JSON type mismatch: field=%s expected=%s got=%s",
				ue.Field, ue.Type, ue.Value),
			false,
		)
		return true
	}
	return false
}

func isHTTPClientErr(err error, e *ExternalError) bool {
	var h *HttpClientErr
	if errors.As(err, &h) {
		e.StatusCode = h.Status
		return true
	}
	return false
}

func classifyStatusCode(e *ExternalError, code int) *ExternalError {
	switch {
	case code >= 200 && code < 300:
		return set(e, ErrKindUnknown, "unexpected success", false)

	case code == 401 || code == 403:
		return set(e, ErrKindUnauthorized, "unauthorized", false)

	case code == 429:
		return set(e, ErrKindRateLimit, "rate limited", true)

	case code >= 400 && code < 500:
		return set(e, ErrKindClient, fmt.Sprintf("client error %d", code), false)

	case code == 504:
		return set(e, ErrKindTimeout, "gateway timeout", true)

	case code >= 500:
		return set(e, ErrKindServer, fmt.Sprintf("server error %d", code), true)
	}

	return set(e, ErrKindUnknown, fmt.Sprintf("unexpected status %d", code), false)
}

func set(e *ExternalError, k ExternalErrorKind, msg string, retry bool) *ExternalError {
	e.Kind = k
	e.Message = msg
	e.Retryable = retry
	return e
}
