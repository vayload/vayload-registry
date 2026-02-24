package middleware

import (
	"strings"

	"github.com/vayload/plug-registry/internal/domain"
	"github.com/vayload/plug-registry/internal/shared/container"
	"github.com/vayload/plug-registry/internal/shared/entity"
	"github.com/vayload/plug-registry/pkg/httpi"
)

func NewAuthGuard(registry *container.Container) httpi.HttpHandler {
	jwtManager, err := container.MapTo[domain.TokenManager](registry, "jwtManager")
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

		userID, err := entity.FromString(claims.Sub)
		if err != nil {
			return httpi.ErrUnauthorized(nil, "Unauthorized")
		}

		req.SetAuth(&httpi.HttpAuth{
			UserId:      domain.UserID{ID: userID},
			AccessToken: token,
		})

		return nil
	}
}

func NewPublishGuard(registry *container.Container) httpi.HttpHandler {
	jwtManager, err := container.MapTo[domain.TokenManager](registry, "jwt_manager")
	if err != nil {
		panic(err)
	}

	apiTokenVerifier, err := container.MapTo[domain.ApiTokenVerifier](registry, "api_token_service")
	if err != nil {
		panic(err)
	}

	return func(req httpi.HttpRequest, res httpi.HttpResponse) error {
		// Normal authenticated user
		rawToken := req.GetHeader("Authorization")
		if rawToken == "" {
			rawToken = req.GetCookie(domain.SessionKey)
		}
		if rawToken == "" {
			return httpi.ErrUnauthorized(nil, "Unauthorized")
		}

		token := strings.TrimPrefix(rawToken, "Bearer ")

		// First check token is api_token
		if strings.HasPrefix(token, domain.ApiTokenPrefix) {
			apiToken, err := apiTokenVerifier.VerifyApiToken(req.Context(), token)
			if err != nil {
				return httpi.ErrUnauthorized(err, "Unauthorized")
			}

			req.Locals(httpi.HTTP_API_TOKEN_KEY, apiToken)

			return nil
		}

		// Otherwise it is access_token
		claims, err := jwtManager.Parse(token)
		if err != nil {
			return httpi.ErrUnauthorized(err, "Unauthorized")
		}

		userID, err := entity.FromString(claims.Sub)
		if err != nil {
			return httpi.ErrUnauthorized(err, "Unauthorized")
		}

		req.SetAuth(&httpi.HttpAuth{
			UserId:      domain.UserID{ID: userID},
			AccessToken: token,
		})

		return nil
	}
}
