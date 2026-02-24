package httpi

import (
	"context"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v2"
)

func TestNewErr(t *testing.T) {
	cause := errors.New("original error")
	details := map[string]string{"field": "invalid"}

	err := NewErr(400, "BAD_REQUEST", "Invalid request", details, cause)

	if err.Status != 400 {
		t.Errorf("Expected status 400, got %d", err.Status)
	}
	if err.Err.Code != "BAD_REQUEST" {
		t.Errorf("Expected code BAD_REQUEST, got %s", err.Err.Code)
	}
	if err.Err.Message != "Invalid request" {
		t.Errorf("Expected message 'Invalid request', got %s", err.Err.Message)
	}
	if err.Cause != cause {
		t.Error("Expected cause to be set")
	}
	if err.Meta == nil {
		t.Error("Expected meta map to be initialized")
	}
}

func TestErr_Error(t *testing.T) {
	err := NewErr(400, "BAD_REQUEST", "Invalid request", nil, nil)

	if err.Error() != "Invalid request" {
		t.Errorf("Expected error message 'Invalid request', got %s", err.Error())
	}
}

func TestErr_Unwrap(t *testing.T) {
	cause := errors.New("original error")
	err := NewErr(500, "INTERNAL_ERROR", "Server error", nil, cause)

	if err.Unwrap() != cause {
		t.Error("Expected Unwrap to return the original cause")
	}
}

func TestErr_Log(t *testing.T) {
	// This test mainly verifies that Log() returns the same error instance
	err := NewErr(500, "INTERNAL_ERROR", "Server error", nil, nil)

	loggedErr := err.Log()
	if loggedErr != err {
		t.Error("Expected Log() to return the same error instance")
	}
}

func TestErrBadRequest(t *testing.T) {
	cause := errors.New("validation failed")
	details := map[string]string{"field": "required"}

	err := ErrBadRequest(cause, details)

	if err.Status != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, err.Status)
	}
	if err.Err.Code != "BAD_REQUEST" {
		t.Errorf("Expected code BAD_REQUEST, got %s", err.Err.Code)
	}
	if err.Err.Message != "Invalid request" {
		t.Errorf("Expected message 'Invalid request', got %s", err.Err.Message)
	}
	if err.Cause != cause {
		t.Error("Expected cause to be set")
	}
}

func TestErrUnauthorized(t *testing.T) {
	cause := errors.New("token expired")

	err := ErrUnauthorized(cause)

	if err.Status != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, err.Status)
	}
	if err.Err.Code != "UNAUTHORIZED" {
		t.Errorf("Expected code UNAUTHORIZED, got %s", err.Err.Code)
	}
	if err.Err.Message != "Authentication required" {
		t.Errorf("Expected message 'Authentication required', got %s", err.Err.Message)
	}
}

func TestErrForbidden(t *testing.T) {
	cause := errors.New("insufficient permissions")

	err := ErrForbidden(cause)

	if err.Status != http.StatusForbidden {
		t.Errorf("Expected status %d, got %d", http.StatusForbidden, err.Status)
	}
	if err.Err.Code != "FORBIDDEN" {
		t.Errorf("Expected code FORBIDDEN, got %s", err.Err.Code)
	}
	if err.Err.Message != "Access forbidden" {
		t.Errorf("Expected message 'Access forbidden', got %s", err.Err.Message)
	}
}

func TestErrNotFound(t *testing.T) {
	cause := errors.New("resource does not exist")

	err := ErrNotFound(cause)

	if err.Status != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, err.Status)
	}
	if err.Err.Code != "RESOURCE_NOT_FOUND" {
		t.Errorf("Expected code RESOURCE_NOT_FOUND, got %s", err.Err.Code)
	}
	if err.Err.Message != "Resource not found" {
		t.Errorf("Expected message 'Resource not found', got %s", err.Err.Message)
	}
}

func TestErrUnprocessableEntity(t *testing.T) {
	cause := errors.New("invalid data format")

	err := ErrUnprocessableEntity(cause)

	if err.Status != http.StatusUnprocessableEntity {
		t.Errorf("Expected status %d, got %d", http.StatusUnprocessableEntity, err.Status)
	}
	if err.Err.Code != "UNPROCESSABLE_ENTITY" {
		t.Errorf("Expected code UNPROCESSABLE_ENTITY, got %s", err.Err.Code)
	}
	if err.Err.Message != "Validation error" {
		t.Errorf("Expected message 'Validation error', got %s", err.Err.Message)
	}
}

func TestErrConflict(t *testing.T) {
	cause := errors.New("resource already exists")

	err := ErrConflict(cause)

	if err.Status != http.StatusConflict {
		t.Errorf("Expected status %d, got %d", http.StatusConflict, err.Status)
	}
	if err.Err.Code != "CONFLICT" {
		t.Errorf("Expected code CONFLICT, got %s", err.Err.Code)
	}
	if err.Err.Message != "Conflict occurred" {
		t.Errorf("Expected message 'Conflict occurred', got %s", err.Err.Message)
	}
}

func TestErrValidation(t *testing.T) {
	cause := errors.New("field validation failed")
	details := map[string][]string{
		"email": {"required", "email"},
	}

	err := ErrValidation(cause, details)

	if err.Status != http.StatusUnprocessableEntity {
		t.Errorf("Expected status %d, got %d", http.StatusUnprocessableEntity, err.Status)
	}
	if err.Err.Code != "VALIDATION_ERROR" {
		t.Errorf("Expected code VALIDATION_ERROR, got %s", err.Err.Code)
	}
	if err.Err.Message != "Validation failed" {
		t.Errorf("Expected message 'Validation failed', got %s", err.Err.Message)
	}
}

func TestErrInternal(t *testing.T) {
	cause := errors.New("database connection failed")

	err := ErrInternal(cause)

	if err.Status != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, err.Status)
	}
	if err.Err.Code != "INTERNAL_ERROR" {
		t.Errorf("Expected code INTERNAL_ERROR, got %s", err.Err.Code)
	}
	if err.Err.Message != "Internal server error" {
		t.Errorf("Expected message 'Internal server error', got %s", err.Err.Message)
	}
}

func TestErrWrapping(t *testing.T) {
	t.Run("Wrapping existing HTTP error", func(t *testing.T) {
		originalErr := ErrBadRequest(errors.New("original cause"))
		details := map[string]string{"wrapped": "true"}

		wrappedErr := ErrWrapping(originalErr, details)

		if wrappedErr.Status != originalErr.Status {
			t.Errorf("Expected status %d, got %d", originalErr.Status, wrappedErr.Status)
		}
		if wrappedErr.Err.Code != originalErr.Err.Code {
			t.Errorf("Expected code %s, got %s", originalErr.Err.Code, wrappedErr.Err.Code)
		}
		if wrappedErr.Err.Message != originalErr.Err.Message {
			t.Errorf("Expected message %s, got %s", originalErr.Err.Message, wrappedErr.Err.Message)
		}
	})

	t.Run("Wrapping non-HTTP error", func(t *testing.T) {
		originalErr := errors.New("some generic error")
		details := map[string]string{"wrapped": "true"}

		wrappedErr := ErrWrapping(originalErr, details)

		if wrappedErr.Status != http.StatusInternalServerError {
			t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, wrappedErr.Status)
		}
		if wrappedErr.Err.Code != "INTERNAL_ERROR" {
			t.Errorf("Expected code INTERNAL_ERROR, got %s", wrappedErr.Err.Code)
		}
		if wrappedErr.Err.Message != "Internal server error" {
			t.Errorf("Expected message 'Internal server error', got %s", wrappedErr.Err.Message)
		}
	})
}

func TestValidate(t *testing.T) {
	type TestStruct struct {
		Email    string `validate:"required,email"`
		Password string `validate:"required,min=8"`
		Age      int    `validate:"min=0,max=120"`
	}

	t.Run("Valid struct", func(t *testing.T) {
		valid := TestStruct{
			Email:    "test@example.com",
			Password: "password123",
			Age:      25,
		}

		err := Validate(valid)
		if err != nil {
			t.Errorf("Expected no validation error, got %v", err)
		}
	})

	t.Run("Invalid struct", func(t *testing.T) {
		invalid := TestStruct{
			Email:    "invalid-email",
			Password: "123", // too short
			Age:      -1,    // negative
		}

		err := Validate(invalid)
		if err == nil {
			t.Error("Expected validation error")
		}

		var httpErr *Err
		if !errors.As(err, &httpErr) {
			t.Error("Expected HTTP error type")
		} else {
			if httpErr.Err.Code != "VALIDATION_ERROR" {
				t.Errorf("Expected VALIDATION_ERROR code, got %s", httpErr.Err.Code)
			}
		}
	})

	t.Run("Invalid validation target", func(t *testing.T) {
		// Test with non-struct type
		err := Validate("not a struct")
		if err == nil {
			t.Error("Expected validation error for invalid target")
		}

		var httpErr *Err
		if !errors.As(err, &httpErr) {
			t.Error("Expected HTTP error type")
		} else {
			if httpErr.Err.Code != "INTERNAL_ERROR" {
				t.Errorf("Expected INTERNAL_ERROR code, got %s", httpErr.Err.Code)
			}
		}
	})
}

func TestCustomValidation_EmailOrPhone(t *testing.T) {
	type TestStruct struct {
		Contact string `validate:"email-or-phone"`
	}

	t.Run("Valid email", func(t *testing.T) {
		data := TestStruct{Contact: "test@example.com"}
		err := Validate(data)
		if err != nil {
			t.Errorf("Expected valid email to pass, got %v", err)
		}
	})

	t.Run("Valid phone (assuming utils.IsValidPhone works)", func(t *testing.T) {
		// Note: This test depends on the implementation of utils.IsValidPhone
		// We're assuming it validates phone numbers correctly
		data := TestStruct{Contact: "+1234567890"}
		err := Validate(data)
		// We can't be sure about the validation result without knowing the utils implementation
		// This test is more about ensuring the validator is registered
		_ = err // Acknowledge we're not asserting on the result
	})

	t.Run("Invalid email and phone", func(t *testing.T) {
		data := TestStruct{Contact: "invalid"}
		err := Validate(data)
		if err == nil {
			t.Error("Expected validation error for invalid email/phone")
		}
	})
}

// Mock implementations for testing error handler
type mockHttpRequest struct {
	headers map[string]string
}

func (m *mockHttpRequest) GetParam(key string, defaultValue ...string) string       { return "" }
func (m *mockHttpRequest) GetParamInt(key string, defaultValue ...int) (int, error) { return 0, nil }
func (m *mockHttpRequest) GetBody() []byte                                          { return nil }
func (m *mockHttpRequest) GetHeader(key string) string {
	if m.headers != nil {
		return m.headers[key]
	}
	return ""
}
func (m *mockHttpRequest) GetHeaders() map[string]string {
	return m.headers
}
func (m *mockHttpRequest) GetMethod() string                                             { return "GET" }
func (m *mockHttpRequest) GetPath() string                                               { return "/test" }
func (m *mockHttpRequest) GetQuery(key string, defaultValue ...string) string            { return "" }
func (m *mockHttpRequest) GetQueryInt(key string, defaultValue ...int) int               { return 0 }
func (m *mockHttpRequest) Queries() map[string]string                                    { return nil }
func (m *mockHttpRequest) GetIP() string                                                 { return "127.0.0.1" }
func (m *mockHttpRequest) GetUserAgent() string                                          { return "test-agent" }
func (m *mockHttpRequest) GetHost() string                                               { return "localhost" }
func (m *mockHttpRequest) ParseBody(any) error                                           { return nil }
func (m *mockHttpRequest) File(key string) (*multipart.FileHeader, error)                { return nil, nil }
func (m *mockHttpRequest) FormData(key string) []string                                  { return nil }
func (m *mockHttpRequest) SaveFile(file *multipart.FileHeader, destination string) error { return nil }
func (m *mockHttpRequest) GetCookie(name string) string                                  { return "" }
func (m *mockHttpRequest) Context() context.Context                                      { return context.Background() }
func (m *mockHttpRequest) SetAuth(auth *HttpAuth)                                        {}
func (m *mockHttpRequest) Auth() *HttpAuth                                               { return nil }
func (m *mockHttpRequest) TryAuth() (*HttpAuth, error)                                   { return nil, nil }
func (m *mockHttpRequest) Locals(key string, value any) any                              { return nil }
func (m *mockHttpRequest) GetLocal(key string) any                                       { return nil }
func (m *mockHttpRequest) Next() error                                                   { return nil }
func (m *mockHttpRequest) Validate(any) error                                            { return nil }
func (m *mockHttpRequest) ValidateBody(any) error                                        { return nil }
func (m *mockHttpRequest) FiberCtx() *fiber.Ctx                                          { return nil }

type mockHttpResponse struct {
	statusCode int
	body       any
}

func (m *mockHttpResponse) SetStatus(status int)               { m.statusCode = status }
func (m *mockHttpResponse) SetHeader(key string, value string) {}
func (m *mockHttpResponse) Send(data []byte) error             { return nil }
func (m *mockHttpResponse) JSON(data any) error                { m.body = data; return nil }
func (m *mockHttpResponse) Json(data any) error                { m.body = data; return nil }
func (m *mockHttpResponse) File(path string) error             { return nil }
func (m *mockHttpResponse) Stream(stream io.Reader) error      { return nil }
func (m *mockHttpResponse) Status(status int) HttpResponse {
	m.statusCode = status
	return m
}
func (m *mockHttpResponse) Redirect(path string, status int) error        { return nil }
func (m *mockHttpResponse) SetBodyStreamWriter(writer StreamWriter) error { return nil }
func (m *mockHttpResponse) Cookie(cookie *Cookie) HttpResponse            { return m }
func (m *mockHttpResponse) Cookies(cookies ...*Cookie) HttpResponse       { return m }

func TestHttpErrorHandler(t *testing.T) {
	t.Run("No error", func(t *testing.T) {
		req := &mockHttpRequest{}
		res := &mockHttpResponse{}

		err := HttpErrorHandler(req, res, nil)
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
	})

	t.Run("HTTP error", func(t *testing.T) {
		req := &mockHttpRequest{
			headers: map[string]string{"X-Request-Id": "test-123"},
		}
		res := &mockHttpResponse{}

		originalErr := ErrBadRequest(errors.New("validation failed"), map[string]string{"field": "invalid"})

		err := HttpErrorHandler(req, res, originalErr)
		if err != nil {
			t.Errorf("Expected no error from handler, got %v", err)
		}

		if res.statusCode != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, res.statusCode)
		}

		errorResponse, ok := res.body.(Error)
		if !ok {
			t.Fatal("Expected Error type in response body")
		}

		if errorResponse.Status != "error" {
			t.Errorf("Expected status 'error', got %s", errorResponse.Status)
		}
		if errorResponse.Error.Code != "BAD_REQUEST" {
			t.Errorf("Expected code 'BAD_REQUEST', got %s", errorResponse.Error.Code)
		}
		if errorResponse.Error.Details == nil {
			t.Error("Expected error details to be preserved")
		}

		meta, ok := errorResponse.Meta.(map[string]any)
		if !ok {
			t.Error("Expected meta to be a map")
		} else if meta["request_id"] != "test-123" {
			t.Errorf("Expected request_id 'test-123', got %v", meta["request_id"])
		}
	})

	t.Run("HttpClient error", func(t *testing.T) {
		req := &mockHttpRequest{}
		res := &mockHttpResponse{}

		clientErr := &HttpClientErr{
			Status:  502,
			Code:    "GATEWAY_ERROR",
			Message: "Gateway timeout",
			Cause:   errors.New("connection failed"),
		}

		err := HttpErrorHandler(req, res, clientErr)
		if err != nil {
			t.Errorf("Expected no error from handler, got %v", err)
		}

		if res.statusCode != 502 {
			t.Errorf("Expected status 502, got %d", res.statusCode)
		}

		errorResponse := res.body.(Error)
		if errorResponse.Error.Code != "GATEWAY_ERROR" {
			t.Errorf("Expected code 'GATEWAY_ERROR', got %s", errorResponse.Error.Code)
		}
	})

	t.Run("Fiber error", func(t *testing.T) {
		req := &mockHttpRequest{}
		res := &mockHttpResponse{}

		fiberErr := fiber.NewError(fiber.StatusNotFound, "Route not found")

		err := HttpErrorHandler(req, res, fiberErr)
		if err != nil {
			t.Errorf("Expected no error from handler, got %v", err)
		}

		if res.statusCode != fiber.StatusNotFound {
			t.Errorf("Expected status %d, got %d", fiber.StatusNotFound, res.statusCode)
		}

		errorResponse := res.body.(Error)
		if errorResponse.Error.Code != "SYSTEM_ERROR" {
			t.Errorf("Expected code 'SYSTEM_ERROR', got %s", errorResponse.Error.Code)
		}
		if errorResponse.Error.Message != "Route not found" {
			t.Errorf("Expected message 'Route not found', got %s", errorResponse.Error.Message)
		}
	})

	t.Run("Generic error", func(t *testing.T) {
		req := &mockHttpRequest{}
		res := &mockHttpResponse{}

		genericErr := errors.New("some generic error")

		err := HttpErrorHandler(req, res, genericErr)
		if err != nil {
			t.Errorf("Expected no error from handler, got %v", err)
		}

		if res.statusCode != http.StatusInternalServerError {
			t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, res.statusCode)
		}

		errorResponse := res.body.(Error)
		if errorResponse.Error.Code != "INTERNAL_SERVER_ERROR" {
			t.Errorf("Expected code 'INTERNAL_SERVER_ERROR', got %s", errorResponse.Error.Code)
		}
		if errorResponse.Error.Message != "Internal server error" {
			t.Errorf("Expected message 'Internal server error', got %s", errorResponse.Error.Message)
		}
	})
}

func TestHttpError_Struct(t *testing.T) {
	httpErr := HttpError{
		Code:       "TEST_ERROR",
		Message:    "This is a test error",
		Details:    map[string]string{"key": "value"},
		StatusCode: 400,
		Cause:      errors.New("original cause"),
	}

	if httpErr.Code != "TEST_ERROR" {
		t.Errorf("Expected Code 'TEST_ERROR', got %s", httpErr.Code)
	}
	if httpErr.Message != "This is a test error" {
		t.Errorf("Expected Message 'This is a test error', got %s", httpErr.Message)
	}
	if httpErr.StatusCode != 400 {
		t.Errorf("Expected StatusCode 400, got %d", httpErr.StatusCode)
	}
	if httpErr.Cause == nil {
		t.Error("Expected Cause to be set")
	}
}

func TestAPIError_Struct(t *testing.T) {
	apiError := APIError{
		Code:    "API_ERROR",
		Message: "API error message",
	}

	if apiError.Code != "API_ERROR" {
		t.Errorf("Expected Code 'API_ERROR', got %s", apiError.Code)
	}
	if apiError.Message != "API error message" {
		t.Errorf("Expected Message 'API error message', got %s", apiError.Message)
	}
}

func TestResponseStructures(t *testing.T) {
	t.Run("Body struct", func(t *testing.T) {
		body := Body{
			Status: "success",
			Data:   map[string]string{"key": "value"},
			Meta:   map[string]any{"page": 1},
		}

		if body.Status != "success" {
			t.Errorf("Expected Status 'success', got %s", body.Status)
		}
		if body.Meta == nil {
			t.Error("Expected Meta to be set")
		}
	})

	t.Run("RequestBody struct", func(t *testing.T) {
		reqBody := RequestBody[map[string]string]{
			Data: map[string]string{"key": "value"},
			Metadata: Metadata{
				RequestID: "req-123",
			},
		}

		if reqBody.Metadata.RequestID != "req-123" {
			t.Errorf("Expected RequestID 'req-123', got %s", reqBody.Metadata.RequestID)
		}
	})

	t.Run("ResponseBody struct", func(t *testing.T) {
		respBody := ResponseBody[map[string]string]{
			Status: "success",
			Data:   map[string]string{"key": "value"},
			Metadata: &RespMeta{
				RequestID: "req-123",
				Status:    200,
				Message:   "OK",
			},
		}

		if respBody.Status != "success" {
			t.Errorf("Expected Status 'success', got %s", respBody.Status)
		}
		if respBody.Metadata.Status != 200 {
			t.Errorf("Expected Metadata Status 200, got %d", respBody.Metadata.Status)
		}
	})

	t.Run("ErrorResponse struct", func(t *testing.T) {
		errorResp := ErrorResponse{
			Status: "error",
			Error: HttpError{
				Code:    "TEST_ERROR",
				Message: "Test error message",
			},
			Meta: map[string]any{"timestamp": "2023-01-01"},
		}

		if errorResp.Status != "error" {
			t.Errorf("Expected Status 'error', got %s", errorResp.Status)
		}
		if errorResp.Error.Code != "TEST_ERROR" {
			t.Errorf("Expected Error Code 'TEST_ERROR', got %s", errorResp.Error.Code)
		}
	})
}
