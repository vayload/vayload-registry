package httpi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

func TestNewHttpProxy(t *testing.T) {
	config := HttpProxyConfig{
		BaseURL: "https://api.example.com",
		Rewrites: map[string]string{
			"/old": "/new",
		},
		Headers: map[string]string{
			"X-Proxy-Header": "proxy-value",
		},
	}

	proxy := NewHttpProxy(config)

	if proxy.config.BaseURL != config.BaseURL {
		t.Errorf("Expected BaseURL %s, got %s", config.BaseURL, proxy.config.BaseURL)
	}
	if proxy.config.Headers["X-Proxy-Header"] != "proxy-value" {
		t.Error("Expected headers to be copied")
	}
	if proxy.reqHook == nil {
		t.Error("Expected request hooks slice to be initialized")
	}
	if proxy.resHook == nil {
		t.Error("Expected response hooks slice to be initialized")
	}
}

func TestHttpProxy_AddRequestHook(t *testing.T) {
	proxy := NewHttpProxy(HttpProxyConfig{})

	hook1 := func(req HttpRequest, proxyReq *http.Request) error {
		proxyReq.Header.Set("X-Hook1", "value1")
		return nil
	}

	hook2 := func(req HttpRequest, proxyReq *http.Request) error {
		proxyReq.Header.Set("X-Hook2", "value2")
		return nil
	}

	proxy.AddRequestHook(hook1)
	proxy.AddRequestHook(hook2)

	if len(proxy.reqHook) != 2 {
		t.Errorf("Expected 2 request hooks, got %d", len(proxy.reqHook))
	}
}

func TestHttpProxy_AddResponseHook(t *testing.T) {
	proxy := NewHttpProxy(HttpProxyConfig{})

	hook1 := func(req HttpRequest, proxyRes *http.Response) error {
		proxyRes.Header.Set("X-Response-Hook1", "value1")
		return nil
	}

	hook2 := func(req HttpRequest, proxyRes *http.Response) error {
		proxyRes.Header.Set("X-Response-Hook2", "value2")
		return nil
	}

	proxy.AddResponseHook(hook1)
	proxy.AddResponseHook(hook2)

	if len(proxy.resHook) != 2 {
		t.Errorf("Expected 2 response hooks, got %d", len(proxy.resHook))
	}
}

// Mock HttpRequest for testing proxy
type mockProxyRequest struct {
	method  string
	path    string
	body    []byte
	headers map[string][]string
	queries map[string]string
}

func (m *mockProxyRequest) GetParam(key string, defaultValue ...string) string       { return "" }
func (m *mockProxyRequest) GetParamInt(key string, defaultValue ...int) (int, error) { return 0, nil }
func (m *mockProxyRequest) GetBody() []byte                                          { return m.body }
func (m *mockProxyRequest) GetHeader(key string) string {
	if headers := m.headers[key]; len(headers) > 0 {
		return headers[0]
	}
	return ""
}
func (m *mockProxyRequest) GetHeaders() map[string]string {
	result := make(map[string]string)
	for key, values := range m.headers {
		if len(values) > 0 {
			result[key] = values[0]
		}
	}
	return result
}
func (m *mockProxyRequest) GetMethod() string { return m.method }
func (m *mockProxyRequest) GetPath() string   { return m.path }
func (m *mockProxyRequest) GetQuery(key string, defaultValue ...string) string {
	if value, exists := m.queries[key]; exists {
		return value
	}
	if len(defaultValue) > 0 {
		return defaultValue[0]
	}
	return ""
}
func (m *mockProxyRequest) GetQueryInt(key string, defaultValue ...int) int               { return 0 }
func (m *mockProxyRequest) Queries() map[string]string                                    { return m.queries }
func (m *mockProxyRequest) GetIP() string                                                 { return "127.0.0.1" }
func (m *mockProxyRequest) GetUserAgent() string                                          { return "test-agent" }
func (m *mockProxyRequest) GetHost() string                                               { return "localhost" }
func (m *mockProxyRequest) ParseBody(any) error                                           { return nil }
func (m *mockProxyRequest) File(key string) (*multipart.FileHeader, error)                { return nil, nil }
func (m *mockProxyRequest) FormData(key string) []string                                  { return nil }
func (m *mockProxyRequest) SaveFile(file *multipart.FileHeader, destination string) error { return nil }
func (m *mockProxyRequest) GetCookie(name string) string                                  { return "" }
func (m *mockProxyRequest) Context() context.Context                                      { return context.Background() }
func (m *mockProxyRequest) GetLocal(key string) any                                       { return nil }
func (m *mockProxyRequest) SetAuth(auth *HttpAuth)                                        {}
func (m *mockProxyRequest) Auth() *HttpAuth                                               { return nil }
func (m *mockProxyRequest) TryAuth() (*HttpAuth, error)                                   { return nil, nil }
func (m *mockProxyRequest) Locals(key string, value any) any                              { return nil }
func (m *mockProxyRequest) Next() error                                                   { return nil }
func (m *mockProxyRequest) Validate(any) error                                            { return nil }
func (m *mockProxyRequest) ValidateBody(any) error                                        { return nil }
func (m *mockProxyRequest) FiberCtx() *fiber.Ctx {
	// Return a mock fiber.Ctx that provides the headers
	return &fiber.Ctx{}
}

// Mock HttpResponse for testing proxy
type mockProxyResponse struct {
	statusCode int
	headers    map[string]string
	body       any
}

func (m *mockProxyResponse) SetStatus(status int) { m.statusCode = status }
func (m *mockProxyResponse) SetHeader(key string, value string) {
	if m.headers == nil {
		m.headers = make(map[string]string)
	}
	m.headers[key] = value
}
func (m *mockProxyResponse) Send(data []byte) error        { m.body = data; return nil }
func (m *mockProxyResponse) JSON(data any) error           { m.body = data; return nil }
func (m *mockProxyResponse) Json(data any) error           { m.body = data; return nil }
func (m *mockProxyResponse) File(path string) error        { return nil }
func (m *mockProxyResponse) Stream(stream io.Reader) error { return nil }
func (m *mockProxyResponse) Status(status int) HttpResponse {
	m.statusCode = status
	return m
}
func (m *mockProxyResponse) Redirect(path string, status int) error        { return nil }
func (m *mockProxyResponse) SetBodyStreamWriter(writer StreamWriter) error { return nil }
func (m *mockProxyResponse) Cookie(cookie *Cookie) HttpResponse            { return m }
func (m *mockProxyResponse) Cookies(cookies ...*Cookie) HttpResponse       { return m }

func TestHttpProxy_Handle(t *testing.T) {
	// Setup target server
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]any{
			"method":        r.Method,
			"path":          r.URL.Path,
			"query":         r.URL.RawQuery,
			"headers":       r.Header,
			"proxyHeader":   r.Header.Get("X-Proxy-Header"),
			"requestHeader": r.Header.Get("X-Request-Header"),
		}

		if r.Method != "GET" {
			body, _ := io.ReadAll(r.Body)
			if len(body) > 0 {
				var data any
				json.Unmarshal(body, &data)
				response["body"] = data
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Target-Header", "target-value")
		json.NewEncoder(w).Encode(response)
	}))
	defer targetServer.Close()

	proxy := NewHttpProxy(HttpProxyConfig{
		BaseURL: targetServer.URL,
		Headers: map[string]string{
			"X-Proxy-Header": "proxy-value",
		},
	})

	// Add request hook
	proxy.AddRequestHook(func(req HttpRequest, proxyReq *http.Request) error {
		proxyReq.Header.Set("X-Request-Hook", "hook-executed")
		return nil
	})

	// Add response hook
	var responseHookExecuted bool
	proxy.AddResponseHook(func(req HttpRequest, proxyRes *http.Response) error {
		responseHookExecuted = true
		proxyRes.Header.Set("X-Response-Hook", "response-hook-executed")
		return nil
	})

	t.Run("GET request", func(t *testing.T) {
		req := &mockProxyRequest{
			method: "GET",
			path:   "/test",
			queries: map[string]string{
				"param1": "value1",
				"param2": "value2",
			},
			headers: map[string][]string{
				"X-Request-Header": {"request-value"},
				"User-Agent":       {"test-agent"},
			},
		}

		res := &mockProxyResponse{}

		err := proxy.Handle(req, res, "/test")
		if err != nil {
			t.Fatalf("Proxy handle failed: %v", err)
		}

		if !responseHookExecuted {
			t.Error("Expected response hook to be executed")
		}

		if res.statusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", res.statusCode)
		}

		if res.headers["X-Response-Hook"] != "response-hook-executed" {
			t.Errorf("Expected response hook header to be set, got %s", res.headers["X-Response-Hook"])
		}
	})

	t.Run("POST request with body", func(t *testing.T) {
		requestBody := map[string]string{"key": "value"}
		bodyBytes, _ := json.Marshal(requestBody)

		req := &mockProxyRequest{
			method: "POST",
			path:   "/create",
			body:   bodyBytes,
			headers: map[string][]string{
				"Content-Type": {"application/json"},
			},
		}

		res := &mockProxyResponse{}

		err := proxy.Handle(req, res, "/create")
		if err != nil {
			t.Fatalf("Proxy handle failed: %v", err)
		}

		if res.statusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", res.statusCode)
		}
	})
}

func TestHttpProxy_HandleWithBodyHook(t *testing.T) {
	// Setup target server
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]any{
			"data":    map[string]string{"original": "value"},
			"status":  "success",
			"message": "original response",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer targetServer.Close()

	proxy := NewHttpProxy(HttpProxyConfig{
		BaseURL: targetServer.URL,
	})

	t.Run("With body modification hook", func(t *testing.T) {
		req := &mockProxyRequest{
			method: "GET",
			path:   "/test",
		}

		res := &mockProxyResponse{}

		// Body modifier hook
		bodyModifier := func(req HttpRequest, body *map[string]any) error {
			(*body)["modified"] = true
			(*body)["message"] = "response modified by proxy"
			return nil
		}

		err := proxy.HandleWithBodyHook(req, res, "/test", bodyModifier)
		if err != nil {
			t.Fatalf("Proxy handle with body hook failed: %v", err)
		}

		if res.statusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", res.statusCode)
		}

		// Verify body was modified
		responseBody, ok := res.body.(map[string]any)
		if !ok {
			t.Fatal("Expected response body to be map[string]any")
		}

		if responseBody["modified"] != true {
			t.Error("Expected body to be modified by hook")
		}

		if responseBody["message"] != "response modified by proxy" {
			t.Errorf("Expected modified message, got %v", responseBody["message"])
		}
	})

	t.Run("Without body modification hook", func(t *testing.T) {
		req := &mockProxyRequest{
			method: "GET",
			path:   "/test",
		}

		res := &mockProxyResponse{}

		err := proxy.HandleWithBodyHook(req, res, "/test", nil)
		if err != nil {
			t.Fatalf("Proxy handle without body hook failed: %v", err)
		}

		if res.statusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", res.statusCode)
		}

		// Should return raw bytes when no hook provided
		bodyBytes, ok := res.body.([]byte)
		if !ok {
			t.Error("Expected response body to be []byte when no hook provided")
		} else {
			var originalResponse map[string]any
			json.Unmarshal(bodyBytes, &originalResponse)

			if originalResponse["message"] != "original response" {
				t.Error("Expected original response when no hook provided")
			}
		}
	})

	t.Run("Body modification hook error", func(t *testing.T) {
		req := &mockProxyRequest{
			method: "GET",
			path:   "/test",
		}

		res := &mockProxyResponse{}

		// Body modifier hook that returns error
		bodyModifier := func(req HttpRequest, body *map[string]any) error {
			return errors.New("modification failed")
		}

		err := proxy.HandleWithBodyHook(req, res, "/test", bodyModifier)
		if err != nil {
			t.Fatalf("Expected proxy to handle hook error, got %v", err)
		}

		if res.statusCode != http.StatusInternalServerError {
			t.Errorf("Expected status 500 for hook error, got %d", res.statusCode)
		}

		errorBody, ok := res.body.(map[string]any)
		if !ok {
			t.Fatal("Expected error response body")
		}

		if !strings.Contains(errorBody["error"].(string), "Error modifying JSON body") {
			t.Error("Expected error message about body modification")
		}
	})
}

func TestHttpProxy_RequestHookError(t *testing.T) {
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer targetServer.Close()

	proxy := NewHttpProxy(HttpProxyConfig{
		BaseURL: targetServer.URL,
	})

	// Add request hook that returns error
	proxy.AddRequestHook(func(req HttpRequest, proxyReq *http.Request) error {
		return errors.New("request hook failed")
	})

	req := &mockProxyRequest{
		method: "GET",
		path:   "/test",
	}

	res := &mockProxyResponse{}

	err := proxy.Handle(req, res, "/test")
	if err != nil {
		t.Fatalf("Expected proxy to handle request hook error, got %v", err)
	}

	if res.statusCode != http.StatusInternalServerError {
		t.Errorf("Expected status 500 for request hook error, got %d", res.statusCode)
	}
}

func TestHttpProxy_ResponseHookError(t *testing.T) {
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer targetServer.Close()

	proxy := NewHttpProxy(HttpProxyConfig{
		BaseURL: targetServer.URL,
	})

	// Add response hook that returns error
	proxy.AddResponseHook(func(req HttpRequest, proxyRes *http.Response) error {
		return errors.New("response hook failed")
	})

	req := &mockProxyRequest{
		method: "GET",
		path:   "/test",
	}

	res := &mockProxyResponse{}

	err := proxy.Handle(req, res, "/test")
	if err != nil {
		t.Fatalf("Expected proxy to handle response hook error, got %v", err)
	}

	if res.statusCode != http.StatusInternalServerError {
		t.Errorf("Expected status 500 for response hook error, got %d", res.statusCode)
	}
}

func TestHttpProxy_TargetServerError(t *testing.T) {
	// No target server - should cause connection error
	proxy := NewHttpProxy(HttpProxyConfig{
		BaseURL: "http://localhost:99999", // Non-existent server
	})

	req := &mockProxyRequest{
		method: "GET",
		path:   "/test",
	}

	res := &mockProxyResponse{}

	err := proxy.Handle(req, res, "/test")
	if err != nil {
		t.Fatalf("Expected proxy to handle target server error, got %v", err)
	}

	if res.statusCode != http.StatusBadGateway {
		t.Errorf("Expected status 502 for target server error, got %d", res.statusCode)
	}

	errorBody, ok := res.body.(map[string]any)
	if !ok {
		t.Fatal("Expected error response body")
	}

	if errorBody["error"] == nil {
		t.Error("Expected error message in response body")
	}
}

func TestHttpProxy_InvalidJSONResponse(t *testing.T) {
	// Target server returns invalid JSON
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("invalid json response"))
	}))
	defer targetServer.Close()

	proxy := NewHttpProxy(HttpProxyConfig{
		BaseURL: targetServer.URL,
	})

	req := &mockProxyRequest{
		method: "GET",
		path:   "/test",
	}

	res := &mockProxyResponse{}

	bodyModifier := func(req HttpRequest, body *map[string]any) error {
		return nil
	}

	err := proxy.HandleWithBodyHook(req, res, "/test", bodyModifier)
	if err != nil {
		t.Fatalf("Expected proxy to handle invalid JSON, got %v", err)
	}

	if res.statusCode != http.StatusInternalServerError {
		t.Errorf("Expected status 500 for invalid JSON, got %d", res.statusCode)
	}

	errorBody, ok := res.body.(map[string]any)
	if !ok {
		t.Fatal("Expected error response body")
	}

	if !strings.Contains(errorBody["error"].(string), "Invalid JSON") {
		t.Error("Expected error message about invalid JSON")
	}
}

func TestHttpProxyConfig_Struct(t *testing.T) {
	config := HttpProxyConfig{
		BaseURL: "https://api.example.com",
		Rewrites: map[string]string{
			"/v1":  "/v2",
			"/old": "/new",
		},
		Headers: map[string]string{
			"Authorization": "Bearer token",
			"User-Agent":    "ProxyClient/1.0",
		},
	}

	if config.BaseURL != "https://api.example.com" {
		t.Errorf("Expected BaseURL 'https://api.example.com', got %s", config.BaseURL)
	}

	if config.Rewrites["/v1"] != "/v2" {
		t.Error("Expected rewrite rule to be set")
	}

	if config.Headers["Authorization"] != "Bearer token" {
		t.Error("Expected header to be set")
	}
}

func TestProxyRequestHook_Type(t *testing.T) {
	var hook ProxyRequestHook = func(req HttpRequest, proxyReq *http.Request) error {
		proxyReq.Header.Set("X-Hook", "executed")
		return nil
	}

	if hook == nil {
		t.Error("Expected hook to be assignable")
	}

	// Test hook execution
	mockReq := &mockProxyRequest{}
	httpReq := &http.Request{Header: make(http.Header)}

	err := hook(mockReq, httpReq)
	if err != nil {
		t.Errorf("Expected no error from hook, got %v", err)
	}

	if httpReq.Header.Get("X-Hook") != "executed" {
		t.Error("Expected hook to modify request")
	}
}

func TestProxyResponseHook_Type(t *testing.T) {
	var hook ProxyResponseHook = func(req HttpRequest, proxyRes *http.Response) error {
		proxyRes.Header.Set("X-Response-Hook", "executed")
		return nil
	}

	if hook == nil {
		t.Error("Expected hook to be assignable")
	}

	// Test hook execution
	mockReq := &mockProxyRequest{}
	httpResp := &http.Response{Header: make(http.Header)}

	err := hook(mockReq, httpResp)
	if err != nil {
		t.Errorf("Expected no error from hook, got %v", err)
	}

	if httpResp.Header.Get("X-Response-Hook") != "executed" {
		t.Error("Expected hook to modify response")
	}
}

func TestBodyModifierHook_Type(t *testing.T) {
	var hook BodyModifierHook = func(req HttpRequest, body *map[string]any) error {
		(*body)["modified"] = true
		return nil
	}

	if hook == nil {
		t.Error("Expected hook to be assignable")
	}

	// Test hook execution
	mockReq := &mockProxyRequest{}
	body := map[string]any{"original": "data"}

	err := hook(mockReq, &body)
	if err != nil {
		t.Errorf("Expected no error from hook, got %v", err)
	}

	if body["modified"] != true {
		t.Error("Expected hook to modify body")
	}
}
