package httpi

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
)

func TestHttpRequest(t *testing.T) {
	app := fiber.New()

	var capturedRequest HttpRequest
	app.Get("/test/:id", func(c *fiber.Ctx) error {
		capturedRequest = NewHttpRequest(c)
		return c.JSON(map[string]string{"status": "ok"})
	})

	app.Post("/test-post", func(c *fiber.Ctx) error {
		capturedRequest = NewHttpRequest(c)
		return c.JSON(map[string]string{"status": "ok"})
	})

	t.Run("GetParam", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test/123", nil)
		_, err := app.Test(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		if capturedRequest.GetParam("id") != "123" {
			t.Errorf("Expected param 'id' to be '123', got %s", capturedRequest.GetParam("id"))
		}

		if capturedRequest.GetParam("nonexistent", "default") != "default" {
			t.Errorf("Expected default value 'default', got %s", capturedRequest.GetParam("nonexistent", "default"))
		}
	})

	t.Run("GetParamInt", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test/456", nil)
		_, err := app.Test(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		value, err := capturedRequest.GetParamInt("id")
		if err != nil {
			t.Fatalf("Expected no error parsing int, got %v", err)
		}
		if value != 456 {
			t.Errorf("Expected param 'id' to be 456, got %d", value)
		}
	})

	t.Run("Request methods and headers", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/test-post?query=value", strings.NewReader(`{"key": "value"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "TestAgent/1.0")
		req.Header.Set("Authorization", "Bearer token123")

		_, err := app.Test(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		if capturedRequest.GetMethod() != "POST" {
			t.Errorf("Expected method 'POST', got %s", capturedRequest.GetMethod())
		}

		if capturedRequest.GetPath() != "/test-post" {
			t.Errorf("Expected path '/test-post', got %s", capturedRequest.GetPath())
		}

		if capturedRequest.GetQuery("query") != "value" {
			t.Errorf("Expected query 'query' to be 'value', got %s", capturedRequest.GetQuery("query"))
		}

		if capturedRequest.GetHeader("Content-Type") != "application/json" {
			t.Errorf("Expected Content-Type 'application/json', got %s", capturedRequest.GetHeader("Content-Type"))
		}

		if capturedRequest.GetHeader("Authorization") != "Bearer token123" {
			t.Errorf("Expected Authorization 'Bearer token123', got %s", capturedRequest.GetHeader("Authorization"))
		}

		if capturedRequest.GetIP() == "" {
			t.Error("Expected IP to be set")
		}
	})

	t.Run("Queries", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test/123?param1=value1&param2=value2", nil)
		_, err := app.Test(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		queries := capturedRequest.Queries()
		if queries["param1"] != "value1" {
			t.Errorf("Expected param1 'value1', got %s", queries["param1"])
		}
		if queries["param2"] != "value2" {
			t.Errorf("Expected param2 'value2', got %s", queries["param2"])
		}
	})

	t.Run("GetQueryInt", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test/123?page=5", nil)
		_, err := app.Test(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		page := capturedRequest.GetQueryInt("page")
		if page != 5 {
			t.Errorf("Expected page 5, got %d", page)
		}

		nonExistent := capturedRequest.GetQueryInt("nonexistent", 10)
		if nonExistent != 10 {
			t.Errorf("Expected default value 10, got %d", nonExistent)
		}
	})
}

func TestHttpRequest_ParseBody(t *testing.T) {
	app := fiber.New()

	var capturedRequest HttpRequest
	app.Post("/test", func(c *fiber.Ctx) error {
		capturedRequest = NewHttpRequest(c)
		return c.JSON(map[string]string{"status": "ok"})
	})

	type TestStruct struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	}

	testData := TestStruct{
		Name:  "John Doe",
		Email: "john@example.com",
	}

	jsonData, _ := json.Marshal(testData)
	req := httptest.NewRequest("POST", "/test", bytes.NewReader(jsonData))
	req.Header.Set("Content-Type", "application/json")

	_, err := app.Test(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	var parsed TestStruct
	err = capturedRequest.ParseBody(&parsed)
	if err != nil {
		t.Fatalf("ParseBody failed: %v", err)
	}

	if parsed.Name != testData.Name {
		t.Errorf("Expected Name '%s', got '%s'", testData.Name, parsed.Name)
	}
	if parsed.Email != testData.Email {
		t.Errorf("Expected Email '%s', got '%s'", testData.Email, parsed.Email)
	}
}

func TestHttpRequest_Validate(t *testing.T) {
	type TestStruct struct {
		Email string `validate:"required,email"`
		Age   int    `validate:"min=0,max=120"`
	}

	req := NewHttpRequest(&fiber.Ctx{})

	t.Run("Valid data", func(t *testing.T) {
		valid := TestStruct{
			Email: "test@example.com",
			Age:   25,
		}

		err := req.Validate(valid)
		if err != nil {
			t.Errorf("Expected no validation error, got %v", err)
		}
	})

	t.Run("Invalid data", func(t *testing.T) {
		invalid := TestStruct{
			Email: "invalid-email",
			Age:   -1,
		}

		err := req.Validate(invalid)
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
}

func TestHttpRequest_ValidateBody(t *testing.T) {
	app := fiber.New()

	var capturedRequest HttpRequest
	app.Post("/test", func(c *fiber.Ctx) error {
		capturedRequest = NewHttpRequest(c)
		return c.JSON(map[string]string{"status": "ok"})
	})

	type TestStruct struct {
		Email string `json:"email" validate:"required,email"`
		Name  string `json:"name" validate:"required,min=2"`
	}

	t.Run("Valid body", func(t *testing.T) {
		validData := TestStruct{
			Email: "test@example.com",
			Name:  "John Doe",
		}

		jsonData, _ := json.Marshal(validData)
		req := httptest.NewRequest("POST", "/test", bytes.NewReader(jsonData))
		req.Header.Set("Content-Type", "application/json")

		_, err := app.Test(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		var parsed TestStruct
		err = capturedRequest.ValidateBody(&parsed)
		if err != nil {
			t.Errorf("Expected no validation error, got %v", err)
		}

		if parsed.Email != validData.Email {
			t.Errorf("Expected email '%s', got '%s'", validData.Email, parsed.Email)
		}
	})

	t.Run("Invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/test", strings.NewReader("invalid json"))
		req.Header.Set("Content-Type", "application/json")

		_, err := app.Test(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		var parsed TestStruct
		err = capturedRequest.ValidateBody(&parsed)
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}

		var httpErr *Err
		if !errors.As(err, &httpErr) {
			t.Error("Expected HTTP error type")
		} else {
			if httpErr.Err.Code != "BAD_REQUEST" {
				t.Errorf("Expected BAD_REQUEST code, got %s", httpErr.Err.Code)
			}
		}
	})

	t.Run("Invalid validation", func(t *testing.T) {
		invalidData := TestStruct{
			Email: "invalid-email",
			Name:  "A", // too short
		}

		jsonData, _ := json.Marshal(invalidData)
		req := httptest.NewRequest("POST", "/test", bytes.NewReader(jsonData))
		req.Header.Set("Content-Type", "application/json")

		_, err := app.Test(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		var parsed TestStruct
		err = capturedRequest.ValidateBody(&parsed)
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

			// Check if details contain field validation errors
			if httpErr.Err.Details == nil {
				t.Error("Expected validation error details")
			}
		}
	})
}

func TestHttpRequest_Auth(t *testing.T) {
	app := fiber.New()

	var capturedRequest HttpRequest
	app.Get("/test", func(c *fiber.Ctx) error {
		capturedRequest = NewHttpRequest(c)
		return c.JSON(map[string]string{"status": "ok"})
	})

	app.Get("/test-auth", func(c *fiber.Ctx) error {
		// Simulate auth middleware setting auth data
		auth := &HttpAuth{
			AccessToken: "token-abc",
		}
		c.Locals("__auth__", auth)
		capturedRequest = NewHttpRequest(c)
		return c.JSON(map[string]string{"status": "ok"})
	})

	t.Run("No auth data", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		_, err := app.Test(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		auth := capturedRequest.Auth()
		if auth == nil {
			t.Fatal("Expected auth object to be returned")
		}

		if auth.AccessToken != "" {
			t.Errorf("Expected empty access token, got %s", auth.AccessToken)
		}
	})

	t.Run("With auth data", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test-auth", nil)
		_, err := app.Test(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		auth := capturedRequest.Auth()
		if auth == nil {
			t.Fatal("Expected auth object to be returned")
		}

		if auth.AccessToken != "token-abc" {
			t.Errorf("Expected AccessToken 'token-abc', got %s", auth.AccessToken)
		}
	})
}

func TestHttpRequest_Locals(t *testing.T) {
	app := fiber.New()

	var capturedRequest HttpRequest
	app.Get("/test", func(c *fiber.Ctx) error {
		capturedRequest = NewHttpRequest(c)
		return c.JSON(map[string]string{"status": "ok"})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	_, err := app.Test(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	// Set a local value
	result := capturedRequest.Locals("test-key", "test-value")
	if result != "test-value" {
		t.Errorf("Expected 'test-value', got %v", result)
	}

	// Get the local value
	retrieved := capturedRequest.Locals("test-key", nil)
	if retrieved != "test-value" {
		t.Errorf("Expected 'test-value', got %v", retrieved)
	}

	// Get non-existent key
	nonExistent := capturedRequest.Locals("non-existent", nil)
	if nonExistent != nil {
		t.Errorf("Expected nil for non-existent key, got %v", nonExistent)
	}
}

func TestHttpResponse(t *testing.T) {
	app := fiber.New()

	var capturedResponse HttpResponse
	app.Get("/test", func(c *fiber.Ctx) error {
		capturedResponse = NewHttpResponse(c)
		return capturedResponse.JSON(map[string]string{"status": "ok"})
	})

	app.Get("/test-status", func(c *fiber.Ctx) error {
		capturedResponse = NewHttpResponse(c)
		return capturedResponse.Status(201).JSON(map[string]string{"created": "true"})
	})

	app.Get("/test-send", func(c *fiber.Ctx) error {
		capturedResponse = NewHttpResponse(c)
		return capturedResponse.Send([]byte("raw response"))
	})

	t.Run("JSON response", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		var result map[string]string
		json.NewDecoder(resp.Body).Decode(&result)
		if result["status"] != "ok" {
			t.Errorf("Expected status 'ok', got %s", result["status"])
		}
	})

	t.Run("Status and JSON", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test-status", nil)
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusCreated {
			t.Errorf("Expected status 201, got %d", resp.StatusCode)
		}

		var result map[string]string
		json.NewDecoder(resp.Body).Decode(&result)
		if result["created"] != "true" {
			t.Errorf("Expected created 'true', got %s", result["created"])
		}
	})

	t.Run("Send raw bytes", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test-send", nil)
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		if string(body) != "raw response" {
			t.Errorf("Expected 'raw response', got %s", string(body))
		}
	})
}

func TestHttpResponse_Headers(t *testing.T) {
	app := fiber.New()

	app.Get("/test", func(c *fiber.Ctx) error {
		resp := NewHttpResponse(c)
		resp.SetHeader("X-Custom-Header", "custom-value")
		resp.SetHeader("X-Another-Header", "another-value")
		return resp.JSON(map[string]string{"status": "ok"})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.Header.Get("X-Custom-Header") != "custom-value" {
		t.Errorf("Expected X-Custom-Header 'custom-value', got %s", resp.Header.Get("X-Custom-Header"))
	}
	if resp.Header.Get("X-Another-Header") != "another-value" {
		t.Errorf("Expected X-Another-Header 'another-value', got %s", resp.Header.Get("X-Another-Header"))
	}
}

func TestHttpResponse_Cookies(t *testing.T) {
	app := fiber.New()

	app.Get("/test-cookie", func(c *fiber.Ctx) error {
		resp := NewHttpResponse(c)

		cookie := &Cookie{
			Name:     "test-cookie",
			Value:    "test-value",
			Path:     "/",
			MaxAge:   3600,
			HttpOnly: true,
			Secure:   true,
		}

		return resp.Cookie(cookie).JSON(map[string]string{"status": "ok"})
	})

	app.Get("/test-multiple-cookies", func(c *fiber.Ctx) error {
		resp := NewHttpResponse(c)

		cookies := []*Cookie{
			{
				Name:  "cookie1",
				Value: "value1",
				Path:  "/",
			},
			{
				Name:  "cookie2",
				Value: "value2",
				Path:  "/api",
			},
		}

		return resp.Cookies(cookies...).JSON(map[string]string{"status": "ok"})
	})

	t.Run("Single cookie", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test-cookie", nil)
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		cookies := resp.Header["Set-Cookie"]
		if len(cookies) == 0 {
			t.Error("Expected cookie to be set")
		} else {
			cookieStr := cookies[0]
			if !strings.Contains(cookieStr, "test-cookie=test-value") {
				t.Errorf("Expected cookie string to contain 'test-cookie=test-value', got %s", cookieStr)
			}
			if !strings.Contains(cookieStr, "HttpOnly") {
				t.Errorf("Expected cookie to be HttpOnly, got %s", cookieStr)
			}
			if !strings.Contains(cookieStr, "Secure") {
				t.Errorf("Expected cookie to be Secure, got %s", cookieStr)
			}
		}
	})

	t.Run("Multiple cookies", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test-multiple-cookies", nil)
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		cookies := resp.Header["Set-Cookie"]
		if len(cookies) != 2 {
			t.Errorf("Expected 2 cookies, got %d", len(cookies))
		}

		cookieStr := strings.Join(cookies, " ")
		if !strings.Contains(cookieStr, "cookie1=value1") {
			t.Error("Expected cookie1 to be set")
		}
		if !strings.Contains(cookieStr, "cookie2=value2") {
			t.Error("Expected cookie2 to be set")
		}
	})
}

func TestHttpResponse_Redirect(t *testing.T) {
	app := fiber.New()

	app.Get("/redirect", func(c *fiber.Ctx) error {
		resp := NewHttpResponse(c)
		return resp.Redirect("/new-location", http.StatusMovedPermanently)
	})

	req := httptest.NewRequest("GET", "/redirect", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMovedPermanently {
		t.Errorf("Expected status 301, got %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if location != "/new-location" {
		t.Errorf("Expected Location '/new-location', got %s", location)
	}
}

func TestHttpResponse_StreamWriter(t *testing.T) {
	app := fiber.New()

	app.Get("/stream", func(c *fiber.Ctx) error {
		resp := NewHttpResponse(c)

		writer := func(w *bufio.Writer) error {
			w.WriteString("chunk 1\n")
			w.Flush()
			w.WriteString("chunk 2\n")
			w.Flush()
			return nil
		}

		return resp.SetBodyStreamWriter(writer)
	})

	req := httptest.NewRequest("GET", "/stream", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, "chunk 1") {
		t.Error("Expected 'chunk 1' in response")
	}
	if !strings.Contains(bodyStr, "chunk 2") {
		t.Error("Expected 'chunk 2' in response")
	}
}

func TestFiberWrap(t *testing.T) {
	handlerExecuted := false

	httpHandler := func(req HttpRequest, res HttpResponse) error {
		handlerExecuted = true

		// Test that we can access Fiber context methods through our interfaces
		if req.GetMethod() != "POST" {
			t.Errorf("Expected method POST, got %s", req.GetMethod())
		}

		return res.JSON(map[string]string{"wrapped": "true"})
	}

	fiberHandler := FiberWrap(httpHandler)

	app := fiber.New()
	app.Post("/test", fiberHandler)

	req := httptest.NewRequest("POST", "/test", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if !handlerExecuted {
		t.Error("Expected handler to be executed")
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)
	if result["wrapped"] != "true" {
		t.Errorf("Expected wrapped 'true', got %s", result["wrapped"])
	}
}

func TestFiberWrap_ErrorHandling(t *testing.T) {
	expectedErr := errors.New("handler error")

	httpHandler := func(req HttpRequest, res HttpResponse) error {
		return expectedErr
	}

	fiberHandler := FiberWrap(httpHandler)

	app := fiber.New()
	app.Get("/test", fiberHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Fiber should handle the error and return 500 by default
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", resp.StatusCode)
	}
}

func TestHttpRoute_Struct(t *testing.T) {
	handler := func(req HttpRequest, res HttpResponse) error { return nil }
	middleware := func(req HttpRequest, res HttpResponse) error { return nil }

	route := HttpRoute{
		Path:           "/api/users",
		Method:         "GET",
		Handler:        handler,
		Middleware:     []HttpHandler{middleware},
		PermissionRule: "user:read",
		Public:         false,
	}

	if route.Path != "/api/users" {
		t.Errorf("Expected Path '/api/users', got %s", route.Path)
	}
	if route.Method != "GET" {
		t.Errorf("Expected Method 'GET', got %s", route.Method)
	}
	if route.Handler == nil {
		t.Error("Expected Handler to be set")
	}
	if len(route.Middleware) != 1 {
		t.Errorf("Expected 1 middleware, got %d", len(route.Middleware))
	}
	if route.PermissionRule != "user:read" {
		t.Errorf("Expected PermissionRule 'user:read', got %s", route.PermissionRule)
	}
	if route.Public != false {
		t.Errorf("Expected Public false, got %t", route.Public)
	}
}

func TestCookie_Struct(t *testing.T) {
	expires := time.Now().Add(24 * time.Hour)

	cookie := Cookie{
		Name:        "session",
		Value:       "abc123",
		Path:        "/",
		Domain:      "example.com",
		MaxAge:      86400,
		Expires:     expires,
		Secure:      true,
		HttpOnly:    true,
		SameSite:    "Strict",
		SessionOnly: false,
	}

	if cookie.Name != "session" {
		t.Errorf("Expected Name 'session', got %s", cookie.Name)
	}
	if cookie.Value != "abc123" {
		t.Errorf("Expected Value 'abc123', got %s", cookie.Value)
	}
	if cookie.Path != "/" {
		t.Errorf("Expected Path '/', got %s", cookie.Path)
	}
	if cookie.Domain != "example.com" {
		t.Errorf("Expected Domain 'example.com', got %s", cookie.Domain)
	}
	if cookie.MaxAge != 86400 {
		t.Errorf("Expected MaxAge 86400, got %d", cookie.MaxAge)
	}
	if !cookie.Expires.Equal(expires) {
		t.Error("Expected Expires to match")
	}
	if !cookie.Secure {
		t.Error("Expected Secure to be true")
	}
	if !cookie.HttpOnly {
		t.Error("Expected HttpOnly to be true")
	}
	if cookie.SameSite != "Strict" {
		t.Errorf("Expected SameSite 'Strict', got %s", cookie.SameSite)
	}
	if cookie.SessionOnly {
		t.Error("Expected SessionOnly to be false")
	}
}
