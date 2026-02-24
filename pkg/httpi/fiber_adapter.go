package httpi

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
	"github.com/vayload/plug-registry/internal/domain"
	"github.com/vayload/plug-registry/pkg/logger"
)

type httpRequest struct {
	Ctx *fiber.Ctx
}

func NewHttpRequest(ctx *fiber.Ctx) HttpRequest {
	return &httpRequest{
		Ctx: ctx,
	}
}

func (request *httpRequest) GetParam(key string, defaultValue ...string) string {
	return request.Ctx.Params(key, defaultValue...)
}

func (request *httpRequest) GetParamInt(key string, defaultValue ...int) (int, error) {
	return request.Ctx.ParamsInt(key, defaultValue...)
}

func (request *httpRequest) GetBody() []byte {
	return request.Ctx.Body()
}

func (request *httpRequest) GetHeader(key string) string {
	return request.Ctx.Get(key)
}

func (request *httpRequest) GetHeaders() map[string]string {
	headers := make(map[string]string)
	for key, values := range request.Ctx.GetReqHeaders() {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}
	return headers
}

func (request *httpRequest) GetMethod() string {
	return request.Ctx.Method()
}

func (request *httpRequest) GetPath() string {
	return request.Ctx.Path()
}

func (request *httpRequest) GetQuery(key string, defaultValue ...string) string {
	return request.Ctx.Query(key, defaultValue...)
}

func (request *httpRequest) GetQueryInt(key string, defaultValue ...int) int {
	return request.Ctx.QueryInt(key, defaultValue...)

}

func (request *httpRequest) Queries() map[string]string {
	return request.Ctx.Queries()
}

func (request *httpRequest) GetIP() string {
	return request.Ctx.IP()
}

func (request *httpRequest) GetUserAgent() string {
	return string(request.Ctx.Context().UserAgent())
}

func (request *httpRequest) GetHost() string {
	return request.Ctx.GetReqHeaders()["Host"][0]
}

func (request *httpRequest) ParseBody(any any) error {
	return request.Ctx.BodyParser(any)
}

func (request *httpRequest) File(key string) (*multipart.FileHeader, error) {
	return request.Ctx.FormFile(key)
}

func (request *httpRequest) FormData(key string) []string {
	values := request.Ctx.FormValue(key)
	return strings.Split(values, ",")
}

func (request *httpRequest) SaveFile(file *multipart.FileHeader, destination string) error {
	return request.Ctx.SaveFile(file, destination)
}

func (request *httpRequest) GetCookie(name string) string {
	cookie := request.Ctx.Cookies(name)
	if cookie == "" {
		return ""
	}
	return cookie
}

func (request *httpRequest) Context() context.Context {
	return request.Ctx.Context()
}

func (request *httpRequest) Validate(any any) error {
	if err := validate.Struct(any); err != nil {
		return ErrValidation(err)
	}
	return nil
}

func (request *httpRequest) ValidateBody(any any) error {
	if err := request.ParseBody(any); err != nil {
		logger.E(err, logger.Fields{"context": "ValidateBody", "action": "parse body"})
		return ErrBadRequest(err)
	}

	if err := validate.Struct(any); err != nil {
		logger.E(err, logger.Fields{"context": "ValidateBody", "action": "validation"})
		if errs, ok := err.(validator.ValidationErrors); ok {
			fields := make(map[string][]string)
			for _, e := range errs {
				fields[e.Field()] = append(fields[e.Field()], e.Tag())
			}

			return ErrValidation(err, fields)
		}

		return ErrValidation(err)
	}

	return nil
}

func (request *httpRequest) SetAuth(auth *HttpAuth) {
	request.Ctx.Locals(HTTP_AUTH_KEY, auth)
}

func (request *httpRequest) Auth() *HttpAuth {
	authToken := request.Ctx.Locals(HTTP_AUTH_KEY)
	auth, ok := authToken.(*HttpAuth)
	if !ok {
		return &HttpAuth{
			UserId:      domain.UserID{},
			Role:        "",
			AccessToken: "",
		}
	}

	return auth
}

func (request *httpRequest) TryAuth() (*HttpAuth, error) {
	authToken := request.Ctx.Locals(HTTP_AUTH_KEY)
	auth, ok := authToken.(*HttpAuth)
	if !ok {
		return nil, ErrUnauthorized(nil, "Unauthorized")
	}

	return auth, nil
}

func (request *httpRequest) GetLocal(key string) any {
	return request.Ctx.Locals(key)
}

func (request *httpRequest) Locals(key string, value any) any {
	if value != nil {
		request.Ctx.Locals(key, value)
		return value
	}

	return request.Ctx.Locals(key)
}

func (request *httpRequest) Next() error {
	return request.Ctx.Next()
}

func (request *httpRequest) FiberCtx() *fiber.Ctx {
	return request.Ctx
}

type httpResponse struct {
	ctx *fiber.Ctx
}

func NewHttpResponse(ctx *fiber.Ctx) HttpResponse {
	return &httpResponse{
		ctx: ctx,
	}
}

func (response *httpResponse) SetStatus(status int) {
	response.ctx.Status(status)
}

func (response *httpResponse) SetHeader(key string, value string) {
	response.ctx.Set(key, value)
}

func (response *httpResponse) Send(body []byte) error {
	return response.ctx.Send(body)
}

func (response *httpResponse) JSON(data any) error {
	return response.ctx.JSON(data)
}

func (response *httpResponse) Json(body any) error {
	return response.ctx.JSON(body)
}

func (response *httpResponse) File(path string) error {
	return response.ctx.SendFile(path)
}

func (response *httpResponse) Stream(stream io.Reader) error {
	return response.ctx.SendStream(stream)
}

func (response *httpResponse) Status(status int) HttpResponse {
	response.ctx.Status(status)
	return response
}

func (response *httpResponse) Redirect(path string, status int) error {
	return response.ctx.Redirect(path, status)
}

func (response *httpResponse) SetBodyStreamWriter(writer StreamWriter) error {
	response.ctx.Context().SetBodyStreamWriter(fasthttp.StreamWriter(func(w *bufio.Writer) {
		writer(w)
	}))

	return nil
}

func (response *httpResponse) Cookie(cookie *Cookie) HttpResponse {
	fiberCookie := fiber.Cookie{
		Name:        cookie.Name,
		Value:       cookie.Value,
		Path:        cookie.Path,
		Domain:      cookie.Domain,
		MaxAge:      cookie.MaxAge,
		Expires:     cookie.Expires,
		Secure:      cookie.Secure,
		HTTPOnly:    cookie.HttpOnly,
		SameSite:    cookie.SameSite,
		SessionOnly: cookie.SessionOnly,
	}
	response.ctx.Cookie(&fiberCookie)
	return response
}

func (response *httpResponse) Cookies(cookies ...*Cookie) HttpResponse {
	for _, c := range cookies {
		fiberCookie := fiber.Cookie{
			Name:        c.Name,
			Value:       c.Value,
			Path:        c.Path,
			Domain:      c.Domain,
			MaxAge:      c.MaxAge,
			Expires:     c.Expires,
			Secure:      c.Secure,
			HTTPOnly:    c.HttpOnly,
			SameSite:    c.SameSite,
			SessionOnly: c.SessionOnly,
		}
		response.ctx.Cookie(&fiberCookie)
	}
	return response
}

func FiberWrap(handler HttpHandler) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		req := NewHttpRequest(ctx)
		res := NewHttpResponse(ctx)

		if err := handler(req, res); err != nil {
			return err
		}

		return nil
	}
}

func RegisterController(router fiber.Router, c Controller) {
	group := router.Group(c.Path())

	if len(c.Middlewares()) > 0 {
		for _, mw := range c.Middlewares() {
			group.Use(FiberWrap(mw))
		}
	}

	for _, route := range c.Routes() {
		handlers := []fiber.Handler{}
		if len(route.Middleware) > 0 {
			for _, mw := range route.Middleware {
				handlers = append(handlers, FiberWrap(mw))
			}
		}

		handlers = append(handlers, FiberWrap(route.Handler))
		routePath := strings.TrimPrefix(route.Path, "/")
		if routePath == "" {
			routePath = "/"
		}

		group.Add(string(route.Method), routePath, handlers...)
		LogRegisteredRoute(string(route.Method), fmt.Sprintf("%s/%s", c.Path(), strings.TrimLeft(route.Path, "/")))
	}
}

// ANSI colores
const (
	green  = "\033[32m"
	yellow = "\033[33m"
	cyan   = "\033[36m"
	reset  = "\033[0m"
)

// PrintRegisteredRoutes imprime las rutas registradas con colores
func PrintRegisteredRoutes(app *fiber.App) {
	fmt.Println(cyan + "📦 Rutas registradas:" + reset)
	for _, route := range app.GetRoutes() {
		methodColor := methodToColor(route.Method)
		fmt.Printf("  %s%-6s%s %s\n", methodColor, route.Method, reset, route.Path)
	}
}

func LogRegisteredRoute(method, path string) {
	methodColor := methodToColor(method)
	fmt.Printf("  %s%-6s%s %s\n", methodColor, method, reset, path)
}

func methodToColor(method string) string {
	switch method {
	case "GET":
		return green
	case "POST":
		return yellow
	default:
		return cyan
	}
}
