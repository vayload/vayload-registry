package httpi

import (
	"bufio"
	"context"
	"io"
	"mime/multipart"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/vayload/plug-registry/internal/domain"
)

const (
	HTTP_AUTH_KEY      = "__auth__"
	HTTP_USER_KEY      = "__user__"
	HTTP_API_TOKEN_KEY = "__api_token__"
)

type HttpMethod string

const (
	GET     HttpMethod = "GET"
	POST    HttpMethod = "POST"
	PUT     HttpMethod = "PUT"
	DELETE  HttpMethod = "DELETE"
	PATCH   HttpMethod = "PATCH"
	OPTIONS HttpMethod = "OPTIONS"
	HEAD    HttpMethod = "HEAD"
)

type HttpAuth struct {
	UserId      domain.UserID `json:"user_id"`
	Role        string        `json:"role"`
	AccessToken string        `json:"access_token,omitempty"` // Optional access token for the user
}

type HttpHandler func(req HttpRequest, res HttpResponse) error
type HttpRoute struct {
	Path           string
	Method         HttpMethod
	Handler        HttpHandler
	Middleware     []HttpHandler
	PermissionRule string // Optional permission rule for authorization
	Public         bool   // Indicates if the route is public
}

type Controller interface {
	Routes() []HttpRoute
	Middlewares() []HttpHandler
	Path() string
}

type Cookie struct {
	Name        string    `json:"name"`
	Value       string    `json:"value"`
	Path        string    `json:"path"`
	Domain      string    `json:"domain"`
	MaxAge      int       `json:"max_age"`
	Expires     time.Time `json:"expires"`
	Secure      bool      `json:"secure"`
	HttpOnly    bool      `json:"http_only"`
	SameSite    string    `json:"same_site"`
	SessionOnly bool      `json:"session_only"`
}

type HttpRequest interface {
	GetParam(key string, defaultValue ...string) string
	GetParamInt(key string, defaultValue ...int) (int, error)
	GetBody() []byte
	GetHeader(key string) string
	GetHeaders() map[string]string
	GetMethod() string
	GetPath() string
	GetQuery(key string, defaultValue ...string) string
	GetQueryInt(key string, defaultValue ...int) int
	Queries() map[string]string
	GetIP() string
	GetUserAgent() string
	GetHost() string
	ParseBody(any) error
	File(key string) (*multipart.FileHeader, error)
	FormData(key string) []string
	SaveFile(file *multipart.FileHeader, destination string) error
	GetCookie(name string) string
	Context() context.Context
	SetAuth(auth *HttpAuth)
	Auth() *HttpAuth
	TryAuth() (*HttpAuth, error)
	Locals(key string, value any) any
	GetLocal(key string) any
	Next() error
	Validate(any) error     // Validate the request body using a validator
	ValidateBody(any) error // Parse and validate the request body
	FiberCtx() *fiber.Ctx
}

type HttpResponse interface {
	SetStatus(status int)
	SetHeader(key string, value string)
	Send(data []byte) error
	JSON(data any) error
	Json(data any) error
	File(path string) error
	Stream(stream io.Reader) error
	Status(status int) HttpResponse
	Redirect(path string, status int) error
	SetBodyStreamWriter(writer StreamWriter) error
	Cookie(cookie *Cookie) HttpResponse
	Cookies(cookies ...*Cookie) HttpResponse
}

type Body struct {
	Status string `json:"status"`
	Data   any    `json:"data"`
	Meta   any    `json:"meta,omitempty"`
}

type HttpError struct {
	Code       string `json:"code"`
	Reason     string `json:"reason,omitempty"`
	Message    string `json:"message"`
	Details    any    `json:"details,omitempty"`
	StatusCode int    `json:"-,omitempty"` // HTTP status code, not included in JSON response
	Cause      error  `json:"-"`           // Original error, not included in JSON response
}

type Error struct {
	Status string    `json:"status"`
	Error  HttpError `json:"error"`
	Meta   any       `json:"meta,omitempty"`
}

// RequestBody is a generic structure for HTTP request bodies.
type RequestBody[T any] struct {
	Data     T        `json:"data"`
	Metadata Metadata `json:"metadata"`
}

type Metadata struct {
	RequestID string `json:"request_id"`
}

// ResponseBody is a generic structure for HTTP response bodies.
type ResponseBody[T any] struct {
	Status   string    `json:"status"` // always "success"
	Data     T         `json:"data"`
	Metadata *RespMeta `json:"metadata,omitempty"`
}

type RespMeta struct {
	RequestID string `json:"request_id"`
	Status    int    `json:"status"`
	Message   string `json:"message"`
}

func NewResponseBody[T any](data T) *ResponseBody[T] {
	return &ResponseBody[T]{
		Status: "success",
		Data:   data,
	}
}

func (r *ResponseBody[T]) SetMeta(meta *RespMeta) {
	r.Metadata = meta
}

// ErrorResponse is a structure for HTTP error responses.
type ErrorResponse struct {
	Status string    `json:"status"` // always "error"
	Error  HttpError `json:"error"`
	Meta   any       `json:"meta,omitempty"`
}

type StreamWriter func(w *bufio.Writer) error
