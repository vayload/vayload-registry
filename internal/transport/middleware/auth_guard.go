package middleware

import (
	"strings"

	"github.com/vayload/plug-registry/internal/domain"
	"github.com/vayload/plug-registry/internal/infrastructure/security"
	"github.com/vayload/plug-registry/internal/services"
	"github.com/vayload/plug-registry/internal/shared/container"
	"github.com/vayload/plug-registry/internal/shared/identity"
	"github.com/vayload/plug-registry/pkg/httpi"
)

func NewAuthGuard(registry *container.Container) httpi.HttpHandler {
	jwtManager, err := container.MapTo[domain.TokenManager](registry, security.JWT_SERVICE_NAME)
	if err != nil {
		panic(err)
	}

	return func(req httpi.HttpRequest, res httpi.HttpResponse) error {
		rawToken := req.GetHeader("Authorization")
		if rawToken == "" {
			rawToken = req.GetCookie(domain.SessionKey)
		}
		if rawToken == "" {
			return httpi.ErrUnauthorized(nil, "Unauthorized")
		}

		token := strings.TrimPrefix(rawToken, "Bearer ")
		claims, err := jwtManager.Parse(token)
		if err != nil {
			return httpi.ErrUnauthorized(nil, "Unauthorized")
		}

		userID, err := identity.FromString(claims.Sub)
		if err != nil {
			return httpi.ErrUnauthorized(nil, "Unauthorized")
		}

		req.SetAuth(&httpi.HttpAuth{
			UserId:      domain.UserID{ID: userID},
			AccessToken: token,
			AuthType:    httpi.BearerAuth,
		})

		return req.Next()
	}
}

func NewPublishGuard(registry *container.Container) httpi.HttpHandler {
	jwtManager, err := container.MapTo[domain.TokenManager](registry, security.JWT_SERVICE_NAME)
	if err != nil {
		panic(err)
	}

	apiTokenVerifier, err := container.MapTo[domain.ApiTokenVerifier](registry, services.AUTH_SERVICE_NAME)
	if err != nil {
		panic(err)
	}

	return func(req httpi.HttpRequest, res httpi.HttpResponse) error {
		rawToken := req.GetHeader("Authorization")
		if rawToken == "" {
			rawToken = req.GetCookie(domain.SessionKey)
		}
		if rawToken == "" {
			return httpi.ErrUnauthorized(nil, "Unauthorized")
		}

		token := strings.TrimPrefix(rawToken, "Bearer ")

		if strings.HasPrefix(token, domain.ApiTokenPrefix) {
			apiToken, err := apiTokenVerifier.VerifyApiToken(req.Context(), token)
			if err != nil {
				return httpi.ErrUnauthorized(err, "Unauthorized")
			}

			userId, _ := identity.FromString(apiToken.UserID)

			req.SetAuth(&httpi.HttpAuth{
				UserId:      domain.UserID{ID: userId},
				AccessToken: token,
				AuthType:    httpi.ApiToken,
				Scope:       apiToken.Scope,
				Data:        apiToken.PluginID,
			})

			return req.Next()
		}

		claims, err := jwtManager.Parse(token)
		if err != nil {
			return httpi.ErrUnauthorized(err, "Unauthorized")
		}

		userID, err := identity.FromString(claims.Sub)
		if err != nil {
			return httpi.ErrUnauthorized(err, "Unauthorized")
		}

		req.SetAuth(&httpi.HttpAuth{
			UserId:      domain.UserID{ID: userID},
			AccessToken: token,
			AuthType:    httpi.BearerAuth,
			// Authenticated user always has global read-write access
			Scope: domain.KeyScope{
				Prefix:     "global",
				Permission: domain.ScopeReadWrite,
			},
		})

		return req.Next()
	}
}
