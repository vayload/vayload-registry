package middleware

import (
	"github.com/vayload/plug-registry/pkg/httpi"
)

// CsrfGuard protects against CSRF attacks by requiring a custom header for state-changing requests.
func NewCsrfGuard() httpi.HttpHandler {
	return func(req httpi.HttpRequest, res httpi.HttpResponse) error {
		method := req.GetMethod()

		if method == "GET" || method == "HEAD" || method == "OPTIONS" || method == "TRACE" {
			return req.Next()
		}

		auth := req.Auth()
		if auth != nil && auth.AuthType == httpi.ApiToken {
			return req.Next()
		}

		if req.GetHeader("X-Vayload-Request") != "true" {
			return httpi.ErrForbidden(nil, "CSRF protection: missing or invalid header")
		}

		return req.Next()
	}
}
