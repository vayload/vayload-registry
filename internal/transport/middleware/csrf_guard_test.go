package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/vayload/plug-registry/pkg/httpi"
)

func TestCsrfGuard(t *testing.T) {
	app := fiber.New()

	// Register CSRF Guard
	app.Use(httpi.FiberWrap(NewCsrfGuard()))

	app.Get("/test", func(c *fiber.Ctx) error {
		return c.SendString("ok")
	})

	app.Post("/test", func(c *fiber.Ctx) error {
		return c.SendString("ok")
	})

	tests := []struct {
		name           string
		method         string
		headerName     string
		headerValue    string
		authType       httpi.AuthType
		expectedStatus int
	}{
		{
			name:           "GET requests should pass without header",
			method:         "GET",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "POST requests should fail without header",
			method:         "POST",
			expectedStatus: http.StatusInternalServerError, // because this handle is managed by global error handler
		},
		{
			name:           "POST requests should pass with valid header",
			method:         "POST",
			headerName:     "X-Vayload-Request",
			headerValue:    "true",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "POST requests should fail with invalid header value",
			method:         "POST",
			headerName:     "X-Vayload-Request",
			headerValue:    "false",
			expectedStatus: http.StatusInternalServerError, // because this handle is managed by global error handler
		},
		{
			name:           "POST requests should pass with ApiToken auth even without header",
			method:         "POST",
			authType:       httpi.ApiToken,
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Special handling for ApiToken auth type in this test
			// Since we are testing the middleware in isolation, we need to mock the Auth behavior
			// However, Fiber / httpi abstraction makes this a bit tricky without a full guard chain.
			// Let's create a specialized app for the ApiToken case if needed, or just rely on the Logic.

			var localApp *fiber.App
			if tt.authType == httpi.ApiToken {
				localApp = fiber.New()
				localApp.Use(func(c *fiber.Ctx) error {
					req := httpi.NewHttpRequest(c)
					req.SetAuth(&httpi.HttpAuth{
						AuthType: httpi.ApiToken,
					})
					return c.Next()
				})
				localApp.Use(httpi.FiberWrap(NewCsrfGuard()))
				localApp.Post("/test", func(c *fiber.Ctx) error {
					return c.SendString("ok")
				})
			} else {
				localApp = app
			}

			req := httptest.NewRequest(tt.method, "/test", nil)
			if tt.headerName != "" {
				req.Header.Set(tt.headerName, tt.headerValue)
			}

			resp, _ := localApp.Test(req)

			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, resp.StatusCode)
			}
		})
	}
}
