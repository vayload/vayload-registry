package httpi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewHttpClient(t *testing.T) {
	t.Run("Default configuration", func(t *testing.T) {
		client := NewHttpClient()

		if client.BaseURL != "" {
			t.Errorf("Expected empty BaseURL, got %s", client.BaseURL)
		}
		if client.HTTPClient.Timeout != 30*time.Second {
			t.Errorf("Expected timeout 30s, got %v", client.HTTPClient.Timeout)
		}
		if client.Headers == nil {
			t.Error("Expected headers map to be initialized")
		}
		if client.events == nil {
			t.Error("Expected events map to be initialized")
		}
	})

	t.Run("Custom configuration", func(t *testing.T) {
		config := HttpClientConfig{
			BaseURL: "https://api.example.com",
			Timeout: 10 * time.Second,
			Headers: map[string]string{
				"Authorization": "Bearer token123",
				"User-Agent":    "TestClient/1.0",
			},
			Params: map[string]string{
				"version": "v1",
			},
			Auth: &BasicAuth{
				Username: "user",
				Password: "pass",
			},
		}

		client := NewHttpClient(config)

		if client.BaseURL != config.BaseURL {
			t.Errorf("Expected BaseURL %s, got %s", config.BaseURL, client.BaseURL)
		}
		if client.HTTPClient.Timeout != config.Timeout {
			t.Errorf("Expected timeout %v, got %v", config.Timeout, client.HTTPClient.Timeout)
		}
		if client.Headers["Authorization"] != "Bearer token123" {
			t.Errorf("Expected Authorization header, got %s", client.Headers["Authorization"])
		}
		if client.Params["version"] != "v1" {
			t.Errorf("Expected version param v1, got %s", client.Params["version"])
		}
		if client.Auth.Username != "user" || client.Auth.Password != "pass" {
			t.Error("Expected auth credentials to be set")
		}
	})
}

func TestHttpClient_BasicRequests(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]any{
			"method": r.Method,
			"path":   r.URL.Path,
			"query":  r.URL.RawQuery,
		}

		if r.Method != "GET" && r.Method != "DELETE" {
			body, _ := io.ReadAll(r.Body)
			if len(body) > 0 {
				var data any
				json.Unmarshal(body, &data)
				response["body"] = data
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewHttpClient(HttpClientConfig{
		BaseURL: server.URL,
	})

	ctx := context.Background()

	t.Run("GET request", func(t *testing.T) {
		resp, err := client.Get(ctx, "/users")
		if err != nil {
			t.Fatalf("GET request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		var result map[string]any
		json.NewDecoder(resp.Body).Decode(&result)

		if result["method"] != "GET" {
			t.Errorf("Expected method GET, got %v", result["method"])
		}
		if result["path"] != "/users" {
			t.Errorf("Expected path /users, got %v", result["path"])
		}
	})

	t.Run("POST request with JSON body", func(t *testing.T) {
		data := map[string]any{
			"name":  "John Doe",
			"email": "john@example.com",
		}

		resp, err := client.Post(ctx, "/users", data)
		if err != nil {
			t.Fatalf("POST request failed: %v", err)
		}
		defer resp.Body.Close()

		var result map[string]any
		json.NewDecoder(resp.Body).Decode(&result)

		if result["method"] != "POST" {
			t.Errorf("Expected method POST, got %v", result["method"])
		}

		body, ok := result["body"].(map[string]any)
		if !ok {
			t.Fatal("Expected body to be an object")
		}
		if body["name"] != "John Doe" {
			t.Errorf("Expected name John Doe, got %v", body["name"])
		}
	})

	t.Run("PUT request", func(t *testing.T) {
		data := map[string]string{"status": "updated"}

		resp, err := client.Put(ctx, "/users/1", data)
		if err != nil {
			t.Fatalf("PUT request failed: %v", err)
		}
		defer resp.Body.Close()

		var result map[string]any
		json.NewDecoder(resp.Body).Decode(&result)

		if result["method"] != "PUT" {
			t.Errorf("Expected method PUT, got %v", result["method"])
		}
	})

	t.Run("PATCH request", func(t *testing.T) {
		data := map[string]string{"status": "patched"}

		resp, err := client.Patch(ctx, "/users/1", data)
		if err != nil {
			t.Fatalf("PATCH request failed: %v", err)
		}
		defer resp.Body.Close()

		var result map[string]any
		json.NewDecoder(resp.Body).Decode(&result)

		if result["method"] != "PATCH" {
			t.Errorf("Expected method PATCH, got %v", result["method"])
		}
	})

	t.Run("DELETE request", func(t *testing.T) {
		resp, err := client.Delete(ctx, "/users/1")
		if err != nil {
			t.Fatalf("DELETE request failed: %v", err)
		}
		defer resp.Body.Close()

		var result map[string]any
		json.NewDecoder(resp.Body).Decode(&result)

		if result["method"] != "DELETE" {
			t.Errorf("Expected method DELETE, got %v", result["method"])
		}
	})
}

func TestHttpClient_PostForm(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("Expected Content-Type application/x-www-form-urlencoded, got %s", r.Header.Get("Content-Type"))
		}

		body, _ := io.ReadAll(r.Body)
		response := map[string]string{
			"method":      r.Method,
			"body":        string(body),
			"contentType": r.Header.Get("Content-Type"),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewHttpClient(HttpClientConfig{
		BaseURL: server.URL,
	})

	formData := "username=john&password=secret123"
	resp, err := client.PostForm(context.Background(), "/login", formData)
	if err != nil {
		t.Fatalf("PostForm request failed: %v", err)
	}
	defer resp.Body.Close()

	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)

	if result["method"] != "POST" {
		t.Errorf("Expected method POST, got %s", result["method"])
	}
	if result["body"] != formData {
		t.Errorf("Expected body %s, got %s", formData, result["body"])
	}
}

func TestHttpClient_RequestInterceptors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]string{
			"customHeader": r.Header.Get("X-Custom-Header"),
			"authHeader":   r.Header.Get("Authorization"),
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewHttpClient(HttpClientConfig{
		BaseURL: server.URL,
	})

	// Add request interceptor
	client.UseRequestInterceptor(func(req *http.Request) error {
		req.Header.Set("X-Custom-Header", "intercepted")
		return nil
	})

	client.UseRequestInterceptor(func(req *http.Request) error {
		req.Header.Set("Authorization", "Bearer intercepted-token")
		return nil
	})

	resp, err := client.Get(context.Background(), "/test")
	if err != nil {
		t.Fatalf("Request with interceptors failed: %v", err)
	}
	defer resp.Body.Close()

	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)

	if result["customHeader"] != "intercepted" {
		t.Errorf("Expected custom header 'intercepted', got %s", result["customHeader"])
	}
	if result["authHeader"] != "Bearer intercepted-token" {
		t.Errorf("Expected auth header 'Bearer intercepted-token', got %s", result["authHeader"])
	}
}

func TestHttpClient_ResponseInterceptors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Original-Header", "original-value")
		json.NewEncoder(w).Encode(map[string]string{"message": "success"})
	}))
	defer server.Close()

	client := NewHttpClient(HttpClientConfig{
		BaseURL: server.URL,
	})

	var interceptedHeader string
	client.UseResponseInterceptor(func(res *http.Response, req *http.Request) error {
		interceptedHeader = res.Header.Get("X-Original-Header")
		res.Header.Set("X-Modified-Header", "modified-value")
		return nil
	})

	resp, err := client.Get(context.Background(), "/test")
	if err != nil {
		t.Fatalf("Request with response interceptors failed: %v", err)
	}
	defer resp.Body.Close()

	if interceptedHeader != "original-value" {
		t.Errorf("Expected intercepted header 'original-value', got %s", interceptedHeader)
	}
	if resp.Header.Get("X-Modified-Header") != "modified-value" {
		t.Errorf("Expected modified header 'modified-value', got %s", resp.Header.Get("X-Modified-Header"))
	}
}

func TestHttpClient_Events(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	client := NewHttpClient(HttpClientConfig{
		BaseURL: server.URL,
	})

	var requestEventFired, responseEventFired, alwaysEventFired bool

	client.Subscribe(EventRequest, func(id string, req *http.Request, res *http.Response, err error) {
		requestEventFired = true
		if id == "" {
			t.Error("Expected request ID to be set")
		}
		if req == nil {
			t.Error("Expected request to be provided in request event")
		}
	})

	client.Subscribe(EventResponse, func(id string, req *http.Request, res *http.Response, err error) {
		responseEventFired = true
		if res == nil {
			t.Error("Expected response to be provided in response event")
		}
	})

	client.Subscribe(EventAlways, func(id string, req *http.Request, res *http.Response, err error) {
		alwaysEventFired = true
	})

	_, err := client.Get(context.Background(), "/test")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if !requestEventFired {
		t.Error("Expected request event to be fired")
	}
	if !responseEventFired {
		t.Error("Expected response event to be fired")
	}
	if !alwaysEventFired {
		t.Error("Expected always event to be fired")
	}
}

func TestHttpClient_BasicAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		response := map[string]any{
			"hasAuth":  ok,
			"username": username,
			"password": password,
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewHttpClient(HttpClientConfig{
		BaseURL: server.URL,
		Auth: &BasicAuth{
			Username: "testuser",
			Password: "testpass",
		},
	})

	resp, err := client.Get(context.Background(), "/test")
	if err != nil {
		t.Fatalf("Request with basic auth failed: %v", err)
	}
	defer resp.Body.Close()

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)

	if !result["hasAuth"].(bool) {
		t.Error("Expected basic auth to be present")
	}
	if result["username"] != "testuser" {
		t.Errorf("Expected username 'testuser', got %v", result["username"])
	}
	if result["password"] != "testpass" {
		t.Errorf("Expected password 'testpass', got %v", result["password"])
	}
}

func TestHttpClient_Parameters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]string{
			"query": r.URL.RawQuery,
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewHttpClient(HttpClientConfig{
		BaseURL: server.URL,
		Params: map[string]string{
			"apiVersion": "v1",
			"format":     "json",
		},
	})

	resp, err := client.Get(context.Background(), "/test")
	if err != nil {
		t.Fatalf("Request with parameters failed: %v", err)
	}
	defer resp.Body.Close()

	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)

	query := result["query"]
	if !strings.Contains(query, "apiVersion=v1") {
		t.Errorf("Expected apiVersion=v1 in query, got %s", query)
	}
	if !strings.Contains(query, "format=json") {
		t.Errorf("Expected format=json in query, got %s", query)
	}
}

func TestHttpClient_Headers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]string{
			"userAgent":     r.Header.Get("User-Agent"),
			"authorization": r.Header.Get("Authorization"),
			"customHeader":  r.Header.Get("X-Custom-Header"),
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewHttpClient(HttpClientConfig{
		BaseURL: server.URL,
		Headers: map[string]string{
			"User-Agent":      "TestClient/1.0",
			"Authorization":   "Bearer global-token",
			"X-Custom-Header": "global-value",
		},
	})

	t.Run("Global headers", func(t *testing.T) {
		resp, err := client.Get(context.Background(), "/test")
		if err != nil {
			t.Fatalf("Request with global headers failed: %v", err)
		}
		defer resp.Body.Close()

		var result map[string]string
		json.NewDecoder(resp.Body).Decode(&result)

		if result["userAgent"] != "TestClient/1.0" {
			t.Errorf("Expected User-Agent 'TestClient/1.0', got %s", result["userAgent"])
		}
		if result["authorization"] != "Bearer global-token" {
			t.Errorf("Expected Authorization 'Bearer global-token', got %s", result["authorization"])
		}
	})

	t.Run("Request-specific headers override", func(t *testing.T) {
		config := HttpClientConfig{
			Headers: map[string]string{
				"Authorization":   "Bearer request-token",
				"X-Custom-Header": "request-value",
			},
		}

		resp, err := client.Get(context.Background(), "/test", config)
		if err != nil {
			t.Fatalf("Request with override headers failed: %v", err)
		}
		defer resp.Body.Close()

		var result map[string]string
		json.NewDecoder(resp.Body).Decode(&result)

		if result["authorization"] != "Bearer request-token" {
			t.Errorf("Expected Authorization 'Bearer request-token', got %s", result["authorization"])
		}
		if result["customHeader"] != "request-value" {
			t.Errorf("Expected X-Custom-Header 'request-value', got %s", result["customHeader"])
		}
	})
}

func TestHttpClient_ErrorHandling(t *testing.T) {
	// Test server that returns errors
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/error" {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	client := NewHttpClient(HttpClientConfig{
		BaseURL: server.URL,
	})

	t.Run("Server error response", func(t *testing.T) {
		resp, err := client.Get(context.Background(), "/error")
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusInternalServerError {
			t.Errorf("Expected status 500, got %d", resp.StatusCode)
		}
	})

	t.Run("Request interceptor error", func(t *testing.T) {
		clientWithError := NewHttpClient(HttpClientConfig{
			BaseURL: server.URL,
		})

		var errorEventFired bool
		clientWithError.Subscribe(EventError, func(id string, req *http.Request, res *http.Response, err error) {
			errorEventFired = true
		})

		clientWithError.UseRequestInterceptor(func(req *http.Request) error {
			return io.ErrUnexpectedEOF
		})

		_, err := clientWithError.Get(context.Background(), "/test")
		if err == nil {
			t.Error("Expected error from request interceptor")
		}
		if !errorEventFired {
			t.Error("Expected error event to be fired")
		}
	})

	t.Run("Context timeout", func(t *testing.T) {
		slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(100 * time.Millisecond)
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		}))
		defer slowServer.Close()

		client := NewHttpClient(HttpClientConfig{
			BaseURL: slowServer.URL,
		})

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		_, err := client.Get(ctx, "/test")
		if err == nil {
			t.Error("Expected timeout error")
		}
	})
}

func TestHttpClient_ContentTypes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType := r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)

		response := map[string]string{
			"contentType": contentType,
			"body":        string(body),
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewHttpClient(HttpClientConfig{
		BaseURL: server.URL,
	})

	t.Run("JSON content type", func(t *testing.T) {
		data := map[string]string{"key": "value"}

		resp, err := client.Post(context.Background(), "/test", data)
		if err != nil {
			t.Fatalf("JSON POST failed: %v", err)
		}
		defer resp.Body.Close()

		var result map[string]string
		json.NewDecoder(resp.Body).Decode(&result)

		if !strings.Contains(result["contentType"], "application/json") {
			t.Errorf("Expected JSON content type, got %s", result["contentType"])
		}
	})

	t.Run("Form URL encoded content type", func(t *testing.T) {
		config := HttpClientConfig{
			Headers: map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			},
		}

		resp, err := client.Post(context.Background(), "/test", "key=value&foo=bar", config)
		if err != nil {
			t.Fatalf("Form POST failed: %v", err)
		}
		defer resp.Body.Close()

		var result map[string]string
		json.NewDecoder(resp.Body).Decode(&result)

		if result["contentType"] != "application/x-www-form-urlencoded" {
			t.Errorf("Expected form content type, got %s", result["contentType"])
		}
		if result["body"] != "key=value&foo=bar" {
			t.Errorf("Expected form body, got %s", result["body"])
		}
	})
}

func TestHttpClient_UnwrapBody(t *testing.T) {
	t.Run("Successful API response", func(t *testing.T) {
		data := map[string]string{"name": "John"}
		response := APIResponse[map[string]string]{
			Status: "success",
			Data:   &data,
		}

		body, _ := json.Marshal(response)
		resp := &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader(body)),
		}

		result, err := UnwrapBody[map[string]string](resp, nil)
		if err != nil {
			t.Fatalf("UnwrapBody failed: %v", err)
		}

		if result.Status != "success" {
			t.Errorf("Expected status success, got %s", result.Status)
		}
		if (*result.Data)["name"] != "John" {
			t.Errorf("Expected name John, got %s", (*result.Data)["name"])
		}
	})

	t.Run("API error response", func(t *testing.T) {
		response := APIResponse[any]{
			Status: "error",
			Error: &APIError{
				Code:    "VALIDATION_ERROR",
				Message: "Invalid input",
			},
		}

		body, _ := json.Marshal(response)
		resp := &http.Response{
			StatusCode: 400,
			Body:       io.NopCloser(bytes.NewReader(body)),
		}

		_, err := UnwrapBody[any](resp, nil)
		if err == nil {
			t.Error("Expected error from API error response")
		}

		var httpClientErr *HttpClientErr
		if !errors.As(err, &httpClientErr) {
			t.Error("Expected HttpClientErr type")
		} else {
			if httpClientErr.Status != 400 {
				t.Errorf("Expected status 400, got %d", httpClientErr.Status)
			}
			if httpClientErr.Code != "VALIDATION_ERROR" {
				t.Errorf("Expected code VALIDATION_ERROR, got %s", httpClientErr.Code)
			}
		}
	})

	t.Run("Invalid JSON response", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader("invalid json")),
		}

		_, err := UnwrapBody[any](resp, nil)
		if err == nil {
			t.Error("Expected error from invalid JSON")
		}
	})

	t.Run("Request error passed through", func(t *testing.T) {
		originalErr := io.ErrUnexpectedEOF

		_, err := UnwrapBody[any](nil, originalErr)
		if err != originalErr {
			t.Error("Expected original error to be passed through")
		}
	})
}

func TestHttpClient_ElapsedTime(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	client := NewHttpClient(HttpClientConfig{
		BaseURL: server.URL,
	})

	// Initially no request made
	if client.GetElapsedTime() != 0 {
		t.Error("Expected elapsed time to be 0 initially")
	}

	requestAt := client.GetRequestAt()
	if !requestAt.IsZero() {
		t.Error("Expected request time to be zero initially")
	}

	_, err := client.Get(context.Background(), "/test")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	elapsedTime := client.GetElapsedTime()
	if elapsedTime <= 0 {
		t.Error("Expected elapsed time to be greater than 0")
	}

	newRequestAt := client.GetRequestAt()
	if newRequestAt.IsZero() {
		t.Error("Expected request time to be set after request")
	}
	if !newRequestAt.After(requestAt) {
		t.Error("Expected request time to be updated")
	}
}

func TestBuildURL(t *testing.T) {
	tests := []struct {
		baseURL  string
		path     string
		expected string
	}{
		{"https://api.example.com", "/users", "https://api.example.com/users"},
		{"https://api.example.com/", "/users", "https://api.example.com/users"},
		{"https://api.example.com", "users", "https://api.example.com/users"},
		{"https://api.example.com/", "users", "https://api.example.com/users"},
		{"", "/users", "/users"},
		{"https://api.example.com", "", "https://api.example.com/"},
	}

	for _, test := range tests {
		result := buildURL(test.baseURL, test.path)
		if result != test.expected {
			t.Errorf("buildURL(%s, %s) = %s; expected %s",
				test.baseURL, test.path, result, test.expected)
		}
	}
}

func TestGetBodyReader(t *testing.T) {
	t.Run("JSON content type", func(t *testing.T) {
		data := map[string]string{"key": "value"}

		reader, contentType, err := getBodyReader("application/json", data)
		if err != nil {
			t.Fatalf("getBodyReader failed: %v", err)
		}

		if contentType != "application/json; charset=utf-8" {
			t.Errorf("Expected JSON content type, got %s", contentType)
		}

		body, _ := io.ReadAll(reader)
		var result map[string]string
		json.Unmarshal(body, &result)

		if result["key"] != "value" {
			t.Errorf("Expected key=value, got %v", result)
		}
	})

	t.Run("Form URL encoded content type", func(t *testing.T) {
		formData := "key=value&foo=bar"

		reader, contentType, err := getBodyReader("application/x-www-form-urlencoded", formData)
		if err != nil {
			t.Fatalf("getBodyReader failed: %v", err)
		}

		if contentType != "application/x-www-form-urlencoded" {
			t.Errorf("Expected form content type, got %s", contentType)
		}

		body, _ := io.ReadAll(reader)
		if string(body) != formData {
			t.Errorf("Expected %s, got %s", formData, string(body))
		}
	})

	t.Run("Form URL encoded with wrong type", func(t *testing.T) {
		_, _, err := getBodyReader("application/x-www-form-urlencoded", 123)
		if err == nil {
			t.Error("Expected error for non-string body with form encoding")
		}
	})

	t.Run("Multipart form data", func(t *testing.T) {
		formData := map[string]any{
			"field1": "value1",
			"field2": 42,
			"field3": 3.14,
			"field4": true,
			"field5": int64(123),
			"file": FormFile{
				FieldName: "file",
				FileName:  "test.txt",
				Content:   strings.NewReader("file content"),
			},
		}

		reader, contentType, err := getBodyReader("multipart/form-data", formData)
		if err != nil {
			t.Fatalf("getBodyReader failed: %v", err)
		}

		if !strings.HasPrefix(contentType, "multipart/form-data") {
			t.Errorf("Expected multipart content type, got %s", contentType)
		}

		body, _ := io.ReadAll(reader)
		bodyStr := string(body)

		if !strings.Contains(bodyStr, "value1") {
			t.Error("Expected field1=value1 in multipart body")
		}
		if !strings.Contains(bodyStr, "42") {
			t.Error("Expected field2=42 in multipart body")
		}
		if !strings.Contains(bodyStr, "file content") {
			t.Error("Expected file content in multipart body")
		}
	})
}

func TestHttpClientErr(t *testing.T) {
	err := &HttpClientErr{
		Status:  400,
		Code:    "BAD_REQUEST",
		Message: "Invalid request",
		Cause:   io.ErrUnexpectedEOF,
	}

	expected := "[400] BAD_REQUEST: Invalid request (cause: unexpected EOF)"
	if err.Error() != expected {
		t.Errorf("Expected error message %s, got %s", expected, err.Error())
	}
}

func TestFormFile(t *testing.T) {
	content := "test file content"
	file := FormFile{
		FieldName: "upload",
		FileName:  "test.txt",
		Content:   strings.NewReader(content),
	}

	body, _ := io.ReadAll(file.Content)
	if string(body) != content {
		t.Errorf("Expected content %s, got %s", content, string(body))
	}
}
