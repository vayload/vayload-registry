package httpi

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/goccy/go-json"
	"github.com/vayload/plug-registry/pkg/crypto"
)

type RequestInterceptor func(req *http.Request) error
type ResponseInterceptor func(res *http.Response, req *http.Request) error
type EventHandler func(id string, req *http.Request, res *http.Response, err error)
type EventName string

const (
	EventRequest  EventName = "request"
	EventResponse EventName = "response"
	EventError    EventName = "error"
	EventAlways   EventName = "always"
)

type HttpClient struct {
	BaseURL              string
	HTTPClient           *http.Client
	Headers              map[string]string
	RequestInterceptors  []RequestInterceptor
	ResponseInterceptors []ResponseInterceptor
	events               map[EventName][]EventHandler
	Params               map[string]string
	Auth                 *BasicAuth
	mutex                sync.RWMutex // Para events
	configMutex          sync.RWMutex // Para headers, params, interceptors
	requestAt            time.Time
}

type BasicAuth struct {
	Username string
	Password string
}

type HttpClientConfig struct {
	BaseURL string
	Timeout time.Duration
	Headers map[string]string
	Params  map[string]string
	Auth    *BasicAuth
}

func NewHttpClient(config ...HttpClientConfig) *HttpClient {
	var baseURL string
	var timeout time.Duration = 30 * time.Second
	var headers map[string]string = make(map[string]string)
	var params map[string]string
	var auth *BasicAuth

	if len(config) > 0 {
		baseURL = config[0].BaseURL
		if config[0].Timeout > 0 {
			timeout = config[0].Timeout
		}
		if config[0].Headers != nil {
			headers = make(map[string]string)
			maps.Copy(headers, config[0].Headers)
		}
		params = config[0].Params
		auth = config[0].Auth
	}

	return &HttpClient{
		BaseURL:    baseURL,
		HTTPClient: &http.Client{Timeout: timeout},
		Headers:    headers,
		events:     make(map[EventName][]EventHandler),
		Params:     params,
		Auth:       auth,
	}
}

func (c *HttpClient) UseRequestInterceptor(interceptor RequestInterceptor) {
	c.configMutex.Lock()
	defer c.configMutex.Unlock()
	if c.RequestInterceptors == nil {
		c.RequestInterceptors = []RequestInterceptor{}
	}
	c.RequestInterceptors = append(c.RequestInterceptors, interceptor)
}

func (c *HttpClient) UseResponseInterceptor(interceptor ResponseInterceptor) {
	c.configMutex.Lock()
	defer c.configMutex.Unlock()
	if c.ResponseInterceptors == nil {
		c.ResponseInterceptors = []ResponseInterceptor{}
	}
	c.ResponseInterceptors = append(c.ResponseInterceptors, interceptor)
}

func (c *HttpClient) getHeaders() map[string]string {
	c.configMutex.RLock()
	defer c.configMutex.RUnlock()

	headers := make(map[string]string)
	maps.Copy(headers, c.Headers)
	return headers
}

func (c *HttpClient) getParams() map[string]string {
	c.configMutex.RLock()
	defer c.configMutex.RUnlock()

	params := make(map[string]string)
	maps.Copy(params, c.Params)
	return params
}

func (c *HttpClient) request(ctx context.Context, method, path string, body any, config ...HttpClientConfig) (*http.Response, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	fullURL := buildURL(c.BaseURL, path)
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.HTTPClient.Timeout)
		defer cancel()
	}

	var bodyReader io.Reader
	var contentType string = "application/json"

	if body != nil {
		headers := c.getHeaders()
		if ct, exists := headers["Content-Type"]; exists {
			contentType = ct
		}

		var err error
		bodyReader, contentType, err = getBodyReader(contentType, body)
		if err != nil {
			return nil, err
		}
	}

	fullURL = c.buildURLWithParams(fullURL)

	request, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return nil, err
	}

	// Add unique request ID
	request_id := request.Header.Get("X-Request-ID")
	if request_id == "" || len(request_id) < (crypto.NANOID_LENGTH-10) {
		request_id = crypto.GenerateNanoID()
		request.Header.Set("X-Request-ID", request_id)
	}

	// Set auth
	if c.Auth != nil {
		request.SetBasicAuth(c.Auth.Username, c.Auth.Password)
	}

	headers := c.getHeaders()
	for key, value := range headers {
		request.Header.Set(key, value)
	}

	// Override with config headers
	if len(config) > 0 && config[0].Headers != nil {
		for key, value := range config[0].Headers {
			request.Header.Set(key, value)
		}
	}

	// Execute request interceptors
	c.configMutex.RLock()
	interceptors := make([]RequestInterceptor, len(c.RequestInterceptors))
	copy(interceptors, c.RequestInterceptors)
	c.configMutex.RUnlock()

	for _, interceptor := range interceptors {
		if intercepErr := interceptor(request); intercepErr != nil {
			c.publish(EventError, request_id, request, nil, intercepErr)
			return nil, intercepErr
		}
	}

	var response *http.Response

	c.publish(EventRequest, request_id, request, nil, nil)
	defer func() {
		c.publish(EventAlways, request_id, request, response, err)
	}()

	// Only available content, override Content-Type if body is not nil
	if body != nil {
		request.Header.Set("Content-Type", contentType)
	}

	c.requestAt = time.Now().UTC()
	response, err = c.HTTPClient.Do(request)

	if err != nil {
		c.publish(EventError, request_id, request, response, err)
		return response, err
	}

	// Execute response interceptors
	c.configMutex.RLock()
	responseInterceptors := make([]ResponseInterceptor, len(c.ResponseInterceptors))
	copy(responseInterceptors, c.ResponseInterceptors)
	c.configMutex.RUnlock()

	for _, interceptor := range responseInterceptors {
		if err := interceptor(response, request); err != nil {
			c.publish(EventError, request_id, request, response, err)
			return response, err
		}
	}

	c.publish(EventResponse, request_id, request, response, nil)
	return response, nil
}

func (c *HttpClient) buildURLWithParams(fullURL string) string {
	params := c.getParams()
	if len(params) == 0 {
		return fullURL
	}

	parsedURL, err := url.Parse(fullURL)
	if err != nil {
		return fullURL // Fallback
	}

	query := parsedURL.Query()
	for key, value := range params {
		query.Set(key, value)
	}

	parsedURL.RawQuery = query.Encode()
	return parsedURL.String()
}

func (c *HttpClient) Get(ctx context.Context, path string, headers ...HttpClientConfig) (*http.Response, error) {
	return c.request(ctx, http.MethodGet, path, nil, headers...)
}

func (c *HttpClient) Post(ctx context.Context, path string, data any, headers ...HttpClientConfig) (*http.Response, error) {
	return c.request(ctx, http.MethodPost, path, data, headers...)
}

func (c *HttpClient) Put(ctx context.Context, path string, data any, headers ...HttpClientConfig) (*http.Response, error) {
	return c.request(ctx, http.MethodPut, path, data, headers...)
}

func (c *HttpClient) Delete(ctx context.Context, path string, headers ...HttpClientConfig) (*http.Response, error) {
	return c.request(ctx, http.MethodDelete, path, nil, headers...)
}

func (c *HttpClient) Patch(ctx context.Context, path string, data any, headers ...HttpClientConfig) (*http.Response, error) {
	return c.request(ctx, http.MethodPatch, path, data, headers...)
}

func (c *HttpClient) PostForm(ctx context.Context, path string, formData string, headers ...HttpClientConfig) (*http.Response, error) {
	// Create temp config
	config := HttpClientConfig{
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
	}

	// Merge con headers proporcionados
	if len(headers) > 0 && headers[0].Headers != nil {
		maps.Copy(config.Headers, headers[0].Headers)
	}

	return c.request(ctx, http.MethodPost, path, formData, config)
}

func (c *HttpClient) Subscribe(eventName EventName, handler EventHandler) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if _, exists := c.events[eventName]; !exists {
		c.events[eventName] = []EventHandler{}
	}

	c.events[eventName] = append(c.events[eventName], handler)
}

func (c *HttpClient) publish(eventName EventName, id string, req *http.Request, res *http.Response, err error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if handlers, exists := c.events[eventName]; exists {
		for _, handler := range handlers {
			handler(id, req, res, err)
		}
	}
}

func (c *HttpClient) GetElapsedTime() time.Duration {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	if c.requestAt.IsZero() {
		return 0
	}
	return time.Since(c.requestAt)
}

func (c *HttpClient) GetRequestAt() time.Time {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.requestAt
}

func (c *HttpClient) GetBaseURL() string {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.BaseURL
}

// Clone creates a deep copy of the HttpClient with the same configuration
// The new client will have independent interceptors and event handlers
func (c *HttpClient) Clone() *HttpClient {
	c.configMutex.RLock()
	c.mutex.RLock()
	defer c.configMutex.RUnlock()
	defer c.mutex.RUnlock()

	// Clone headers
	headers := make(map[string]string)
	maps.Copy(headers, c.Headers)

	// Clone params
	params := make(map[string]string)
	maps.Copy(params, c.Params)

	// Clone auth
	var auth *BasicAuth
	if c.Auth != nil {
		auth = &BasicAuth{
			Username: c.Auth.Username,
			Password: c.Auth.Password,
		}
	}

	// Create new client with same HTTP client timeout
	newClient := &HttpClient{
		BaseURL:    c.BaseURL,
		HTTPClient: &http.Client{Timeout: c.HTTPClient.Timeout},
		Headers:    headers,
		Params:     params,
		Auth:       auth,
		events:     make(map[EventName][]EventHandler),
		requestAt:  time.Time{}, // Reset request time
	}

	// Clone request interceptors
	if c.RequestInterceptors != nil {
		newClient.RequestInterceptors = make([]RequestInterceptor, len(c.RequestInterceptors))
		copy(newClient.RequestInterceptors, c.RequestInterceptors)
	}

	// Clone response interceptors
	if c.ResponseInterceptors != nil {
		newClient.ResponseInterceptors = make([]ResponseInterceptor, len(c.ResponseInterceptors))
		copy(newClient.ResponseInterceptors, c.ResponseInterceptors)
	}

	// Clone event handlers
	for eventName, handlers := range c.events {
		newClient.events[eventName] = make([]EventHandler, len(handlers))
		copy(newClient.events[eventName], handlers)
	}

	return newClient
}

// Copy creates a shallow copy of the HttpClient
// The new client shares the same HTTP client instance but has independent configuration
func (c *HttpClient) Copy() *HttpClient {
	c.configMutex.RLock()
	c.mutex.RLock()
	defer c.configMutex.RUnlock()
	defer c.mutex.RUnlock()

	// Copy headers
	headers := make(map[string]string)
	maps.Copy(headers, c.Headers)

	// Copy params
	params := make(map[string]string)
	maps.Copy(params, c.Params)

	// Copy auth
	var auth *BasicAuth
	if c.Auth != nil {
		auth = &BasicAuth{
			Username: c.Auth.Username,
			Password: c.Auth.Password,
		}
	}

	// Create new client sharing the same HTTP client instance
	newClient := &HttpClient{
		BaseURL:    c.BaseURL,
		HTTPClient: c.HTTPClient, // Shared HTTP client
		Headers:    headers,
		Params:     params,
		Auth:       auth,
		events:     make(map[EventName][]EventHandler),
		requestAt:  time.Time{}, // Reset request time
	}

	return newClient
}

func buildURL(baseURL, path string) string {
	base := strings.TrimSuffix(baseURL, "/")
	path = strings.TrimPrefix(path, "/")
	if base == "" {
		return path
	}

	return base + "/" + path
}

// Create a reader based on the content type
// Supports application/x-www-form-urlencoded, multipart/form-data, and JSON
func getBodyReader(contentType string, body any) (io.Reader, string, error) {
	contentType = strings.Split(contentType, ";")[0]
	contentType = strings.TrimSpace(contentType)

	switch contentType {
	case "application/x-www-form-urlencoded":
		if bodyStr, ok := body.(string); ok {
			return strings.NewReader(bodyStr), "application/x-www-form-urlencoded", nil
		}
		return nil, "", fmt.Errorf("expected body to be a string for application/x-www-form-urlencoded")

	case "multipart/form-data":
		buf := new(bytes.Buffer)
		writer := multipart.NewWriter(buf)

		if formData, ok := body.(map[string]any); ok {
			for key, value := range formData {
				if file, ok := value.(FormFile); ok {
					part, err := writer.CreateFormFile(key, file.FileName)
					if err != nil {
						writer.Close()
						return nil, "", err
					}
					if _, err := io.Copy(part, file.Content); err != nil {
						writer.Close()
						return nil, "", err
					}
				} else if strValue, ok := value.(string); ok {
					if err := writer.WriteField(key, strValue); err != nil {
						writer.Close()
						return nil, "", err
					}
				} else if intValue, ok := value.(int); ok {
					if err := writer.WriteField(key, fmt.Sprintf("%d", intValue)); err != nil {
						writer.Close()
						return nil, "", err
					}
				} else if floatValue, ok := value.(float64); ok {
					if err := writer.WriteField(key, fmt.Sprintf("%f", floatValue)); err != nil {
						writer.Close()
						return nil, "", err
					}
				} else if boolValue, ok := value.(bool); ok {
					if err := writer.WriteField(key, fmt.Sprintf("%t", boolValue)); err != nil {
						writer.Close()
						return nil, "", err
					}
				} else if int64Value, ok := value.(int64); ok {
					if err := writer.WriteField(key, fmt.Sprintf("%d", int64Value)); err != nil {
						writer.Close()
						return nil, "", err
					}
				} else {
					writer.Close()
					return nil, "", fmt.Errorf("unsupported type for multipart/form-data: %T", value)
				}
			}
		}

		// Close the writer to finalize the form data
		if err := writer.Close(); err != nil {
			return nil, "", err
		}
		return buf, writer.FormDataContentType(), nil

	default:
		b, err := json.Marshal(body)
		if err != nil {
			return nil, "", err
		}
		return bytes.NewBuffer(b), "application/json; charset=utf-8", nil
	}
}

type FormFile struct {
	FieldName string
	FileName  string
	Content   io.Reader
}

type HttpClientErr struct {
	Status  int    `json:"status"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Cause   error  `json:"-"`
}

func (e *HttpClientErr) Error() string {
	return fmt.Sprintf("[%d] %s: %s (cause: %v)", e.Status, e.Code, e.Message, e.Cause)
}

type APIErrorCode string

func (f *APIErrorCode) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*f = APIErrorCode(s)
		return nil
	}

	var n json.Number
	if err := json.Unmarshal(b, &n); err == nil {
		*f = APIErrorCode(n.String())
		return nil
	}

	*f = ""
	return nil
}

type APIError struct {
	Code    APIErrorCode `json:"code"`
	Message string       `json:"message"`
}

type APIResponse[T any] struct {
	Status   string    `json:"status"`
	Error    *APIError `json:"error,omitempty"`
	Data     *T        `json:"data,omitempty"`
	Response *http.Response
}

func UnwrapBody[T any](response *http.Response, err error) (*APIResponse[T], error) {
	apiResponse := APIResponse[T]{Response: response}
	if err != nil {
		return &apiResponse, err
	}

	if err := json.NewDecoder(response.Body).Decode(&apiResponse); err != nil {
		return &apiResponse, &HttpClientErr{
			Status:  response.StatusCode,
			Code:    "HTTP_CLIENT_ERROR",
			Message: "failed to decode API response",
			Cause:   err,
		}
	}

	if apiResponse.Error != nil {
		return &apiResponse, &HttpClientErr{
			Status:  response.StatusCode,
			Code:    string(apiResponse.Error.Code),
			Message: apiResponse.Error.Message,
		}
	}

	if apiResponse.Status == "error" {
		if apiResponse.Error != nil {
			return &apiResponse, &HttpClientErr{
				Status:  response.StatusCode,
				Code:    string(apiResponse.Error.Code),
				Message: apiResponse.Error.Message,
			}
		}

		return &apiResponse, &HttpClientErr{
			Status:  response.StatusCode,
			Code:    "HTTP_CLIENT_ERROR",
			Message: "unknown API error",
		}
	}

	return &apiResponse, nil
}
