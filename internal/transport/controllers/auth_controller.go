package controllers

import (
	"fmt"
	"time"

	"github.com/vayload/plug-registry/config"
	"github.com/vayload/plug-registry/internal/domain"
	"github.com/vayload/plug-registry/internal/services"
	"github.com/vayload/plug-registry/internal/shared/container"
	"github.com/vayload/plug-registry/internal/transport/dtos"
	"github.com/vayload/plug-registry/internal/transport/middleware"
	"github.com/vayload/plug-registry/pkg/httpi"
)

type AuthController struct {
	authService *services.AuthService
	userService *services.UserService
	container   *container.Container
	config      *config.Config
}

func NewAuthController(authService *services.AuthService, userService *services.UserService, container *container.Container, config *config.Config) *AuthController {
	return &AuthController{
		authService: authService,
		userService: userService,
		container:   container,
		config:      config,
	}
}

func (c *AuthController) Path() string {
	return "/auth"
}

func (c *AuthController) Middlewares() []httpi.HttpHandler {
	return nil
}

func (c *AuthController) Routes() []httpi.HttpRoute {
	authGuard := middleware.NewAuthGuard(c.container)

	return []httpi.HttpRoute{
		{
			Path:    "/register",
			Method:  httpi.POST,
			Handler: c.Register,
		},
		{
			Path:    "/login",
			Method:  httpi.POST,
			Handler: c.Login,
		},
		{
			Path:    "/refresh-token",
			Method:  httpi.POST,
			Handler: c.Refresh,
		},
		{
			Path:    "/oauth/:provider",
			Method:  httpi.POST,
			Handler: c.GetOAuthAuthorizationURL,
		},
		{
			Path:    "/oauth/:provider/callback",
			Method:  httpi.GET,
			Handler: c.ExchangeOAuthCode,
		},
		{
			Path:    "/oauth/:provider/exchange",
			Method:  httpi.POST,
			Handler: c.ExchangeOAuthCodeRaw,
		},
		{
			Path:       "/logout",
			Method:     httpi.POST,
			Handler:    c.Logout,
			Middleware: []httpi.HttpHandler{authGuard},
		},
		{
			Path:       "/me",
			Method:     httpi.GET,
			Handler:    c.GetMe,
			Middleware: []httpi.HttpHandler{authGuard},
		},
		{
			Path:       "/me/password",
			Method:     httpi.PATCH,
			Handler:    c.UpdatePassword,
			Middleware: []httpi.HttpHandler{authGuard},
		},
	}
}

// Register godoc
// @Summary      Register a new user
// @Description  Create a new user account
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        body  body      dtos.RegisterRequest  true  "Register request"
// @Success      200   {object}  map[string]any
// @Failure      400   {object}  httpi.ErrorResponse
// @Router       /auth/register [post]
func (c *AuthController) Register(req httpi.HttpRequest, res httpi.HttpResponse) error {
	body := dtos.RegisterRequest{}
	if err := req.ParseBody(&body); err != nil {
		return httpi.ErrBadRequest(err)
	}

	email, password, username, err := body.ToValueObjects()
	if err != nil {
		return httpi.ErrValidation(err)
	}

	user, token, err := c.authService.Register(req.Context(), *username, *email, *password)
	if err != nil {
		return httpi.MapFromAppException(err)
	}

	c.setAuthCookies(res, user, token)

	return res.JSON(map[string]any{
		"user":  user,
		"token": token,
	})
}

// Login godoc
// @Summary      Login
// @Description  Authenticate a user and return tokens
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        body  body      dtos.LoginRequest  true  "Login request"
// @Success      200   {object}  map[string]any
// @Failure      400   {object}  httpi.ErrorResponse
// @Failure      401   {object}  httpi.ErrorResponse
// @Router       /auth/login [post]
func (c *AuthController) Login(req httpi.HttpRequest, res httpi.HttpResponse) error {
	body := dtos.LoginRequest{}
	if err := req.ParseBody(&body); err != nil {
		return httpi.ErrBadRequest(err)
	}

	if err := body.Validate(); err != nil {
		return httpi.ErrValidation(err)
	}

	user, token, err := c.authService.Login(req.Context(), body.Email, body.Password)
	if err != nil {
		return httpi.MapFromAppException(err)
	}

	c.setAuthCookies(res, user, token)

	return res.JSON(map[string]any{
		"user":  user,
		"token": token,
	})
}

func (c *AuthController) Refresh(req httpi.HttpRequest, res httpi.HttpResponse) error {
	var refreshToken string

	refreshToken = req.GetCookie(domain.RefreshKey)

	if refreshToken == "" {
		var body dtos.RefreshTokenRequest
		if err := req.ParseBody(&body); err != nil || body.RefreshToken == nil {
			return httpi.ErrBadRequest(err)
		}

		refreshToken = *body.RefreshToken
	}

	if refreshToken == "" {
		return httpi.ErrUnauthorized(nil)
	}

	token, err := c.authService.RefreshToken(req.Context(), refreshToken)
	if err != nil {
		return httpi.MapFromAppException(err)
	}

	if req.GetCookie(domain.RefreshKey) != "" {
		c.updateRefreshCookies(res, token)
	}

	return res.JSON(token)
}

func (c *AuthController) Logout(req httpi.HttpRequest, res httpi.HttpResponse) error {
	auth := req.Auth()
	if auth == nil || auth.UserId.IsZero() {
		return httpi.ErrUnauthorized(nil)
	}

	err := c.authService.Logout(req.Context(), auth.UserId)
	if err != nil {
		return httpi.MapFromAppException(err)
	}

	c.clearAuthCookies(res)
	return res.Status(200).JSON(map[string]any{"message": "Logged out successfully"})
}

func (c *AuthController) GetMe(req httpi.HttpRequest, res httpi.HttpResponse) error {
	auth := req.Auth()
	if auth == nil || auth.UserId.IsZero() {
		return httpi.ErrUnauthorized(nil)
	}

	user, err := c.userService.GetUser(req.Context(), auth.UserId)
	if err != nil {
		return httpi.MapFromAppException(err)
	}
	return res.JSON(user)
}

func (c *AuthController) UpdatePassword(req httpi.HttpRequest, res httpi.HttpResponse) error {
	var body dtos.UpdatePasswordRequest
	if err := req.ParseBody(&body); err != nil {
		return httpi.MapFromAppException(err)
	}

	return res.Status(501).JSON(map[string]any{"error": "Not implemented"})
}

func (c *AuthController) GetOAuthAuthorizationURL(req httpi.HttpRequest, res httpi.HttpResponse) error {
	providerStr := req.GetParam("provider")
	provider, err := domain.ParseOAuthProvider(providerStr)
	if err != nil {
		return httpi.ErrValidation(err)
	}

	var body dtos.OAuthParams
	if err := req.ParseBody(&body); err != nil {
		return httpi.ErrBadRequest(err)
	}

	clientType, err := domain.ParseClientType(body.ClientType)
	if err != nil {
		return httpi.ErrValidation(err)
	}

	state := domain.OAuthState{
		State:         body.State,
		OriginURI:     body.OriginURI,
		RedirectURI:   body.RedirectURI,
		CodeChallenge: body.CodeChallenge,
		ClientType:    clientType,
	}

	url, err := c.authService.GetOAuthAuthenticationURI(req.Context(), provider, state)
	if err != nil {
		return httpi.MapFromAppException(err)
	}

	return res.JSON(dtos.OAuthResponse{AuthorizationURI: url})
}

func (c *AuthController) ExchangeOAuthCode(req httpi.HttpRequest, res httpi.HttpResponse) error {
	providerStr := req.GetParam("provider")
	provider, err := domain.ParseOAuthProvider(providerStr)
	if err != nil {
		return httpi.MapFromAppException(err)
	}

	code := req.GetQuery("code")
	stateStr := req.GetQuery("state")

	state, err := domain.ParseOAuthState(stateStr)
	if err != nil {
		return httpi.ErrValidation(err)
	}

	user, token, err := c.authService.LoginWithOAuth(req.Context(), provider, code, state)
	if err != nil {
		return httpi.MapFromAppException(err)
	}

	c.setAuthCookies(res, user, token)

	return res.Redirect(state.OriginURI, 302)
}

func (c *AuthController) ExchangeOAuthCodeRaw(req httpi.HttpRequest, res httpi.HttpResponse) error {
	providerStr := req.GetParam("provider")
	provider, err := domain.ParseOAuthProvider(providerStr)
	if err != nil {
		return httpi.MapFromAppException(err)
	}

	var body dtos.OAuthExchangeParams
	if err := req.ParseBody(&body); err != nil {
		return httpi.MapFromAppException(err)
	}

	state, err := domain.ParseOAuthState(body.State)
	if err != nil {
		return httpi.ErrValidation(err)
	}

	_, token, err := c.authService.LoginWithOAuth(req.Context(), provider, body.Code, state)
	if err != nil {
		return httpi.MapFromAppException(err)
	}

	return res.JSON(dtos.OAuthDataResponse{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    token.ExpiresIn,
	})
}

func (c *AuthController) setAuthCookies(res httpi.HttpResponse, user *domain.User, token *domain.AuthToken) {
	domainName := c.config.Server.CookieDomain
	expiresAt := time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	refreshExpiresAt := time.Now().Add(time.Duration(token.RefreshTokenExpiresIn) * time.Second)

	res.Cookie(&httpi.Cookie{
		Name:     domain.IsLoggedInKey,
		Value:    "true",
		Expires:  expiresAt,
		Domain:   domainName,
		Path:     "/",
		HttpOnly: false,
		Secure:   true,
		SameSite: "None",
	})

	if user.AvatarURL != nil {
		res.Cookie(&httpi.Cookie{
			Name:     domain.AvatarURLKey,
			Value:    *user.AvatarURL,
			Expires:  refreshExpiresAt,
			Domain:   domainName,
			Path:     "/",
			HttpOnly: false,
			Secure:   true,
			SameSite: "None",
		})
	}

	res.Cookie(&httpi.Cookie{
		Name:     domain.SessionKey,
		Value:    fmt.Sprintf("Bearer %s", token.AccessToken),
		Expires:  expiresAt,
		Domain:   domainName,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: "None",
	})

	res.Cookie(&httpi.Cookie{
		Name:     domain.RefreshKey,
		Value:    token.RefreshToken,
		Expires:  refreshExpiresAt,
		Domain:   domainName,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: "None",
	})
}

func (c *AuthController) updateRefreshCookies(res httpi.HttpResponse, token *domain.AuthToken) {
	domainName := c.config.Server.CookieDomain
	expiresAt := time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	refreshExpiresAt := time.Now().Add(time.Duration(token.RefreshTokenExpiresIn) * time.Second)

	res.Cookie(&httpi.Cookie{
		Name:     domain.SessionKey,
		Value:    fmt.Sprintf("Bearer %s", token.AccessToken),
		Expires:  expiresAt,
		Domain:   domainName,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: "None",
	})

	res.Cookie(&httpi.Cookie{
		Name:     domain.RefreshKey,
		Value:    token.RefreshToken,
		Expires:  refreshExpiresAt,
		Domain:   domainName,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: "None",
	})
}

func (c *AuthController) clearAuthCookies(res httpi.HttpResponse) {
	domainName := c.config.Server.CookieDomain
	past := time.Now().Add(-24 * time.Hour)

	keys := []string{domain.IsLoggedInKey, domain.AvatarURLKey, domain.SessionKey, domain.RefreshKey}
	for _, key := range keys {
		res.Cookie(&httpi.Cookie{
			Name:     key,
			Value:    "",
			Expires:  past,
			Domain:   domainName,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: "None",
		})
	}
}
