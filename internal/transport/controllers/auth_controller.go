package controllers

import (
	"context"
	"fmt"
	"time"

	"github.com/vayload/plug-registry/config"
	"github.com/vayload/plug-registry/internal/domain"
	"github.com/vayload/plug-registry/internal/services"
	"github.com/vayload/plug-registry/internal/shared/container"
	"github.com/vayload/plug-registry/internal/shared/errors"
	"github.com/vayload/plug-registry/internal/shared/identity"
	"github.com/vayload/plug-registry/internal/transport/dtos"
	"github.com/vayload/plug-registry/internal/transport/middleware"
	"github.com/vayload/plug-registry/pkg/httpi"
)

type AuthController struct {
	authService  *services.AuthService
	userService  *services.UserService
	statsService *services.StatsService
	container    *container.Container
	config       *config.Config
}

func NewAuthController(authService *services.AuthService, userService *services.UserService, statsService *services.StatsService, container *container.Container, config *config.Config) *AuthController {
	return &AuthController{
		authService:  authService,
		userService:  userService,
		statsService: statsService,
		container:    container,
		config:       config,
	}
}

func (c *AuthController) Routes() *httpi.HttpRoutesGroup {
	authGuard := middleware.NewAuthGuard(c.container)

	return &httpi.HttpRoutesGroup{
		Prefix: "/auth",
		Routes: []httpi.HttpRoute{
			{
				Path:    "/register",
				Method:  httpi.POST,
				Handler: c.Register,
			},
			{
				Path:    "/login",
				Method:  httpi.POST,
				Handler: c.LoginWithPassword,
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
				Path:    "/refresh-token",
				Method:  httpi.POST,
				Handler: c.Refresh,
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
			{
				Path:       "/me/api-tokens",
				Method:     httpi.GET,
				Handler:    c.ListApiTokens,
				Middleware: []httpi.HttpHandler{authGuard},
			},
			{
				Path:       "/me/api-tokens",
				Method:     httpi.POST,
				Handler:    c.CreateApiToken,
				Middleware: []httpi.HttpHandler{authGuard},
			},
			{
				Path:       "/me/api-tokens/:id",
				Method:     httpi.DELETE,
				Handler:    c.DeleteApiToken,
				Middleware: []httpi.HttpHandler{authGuard},
			},
			{
				Path:       "/me/api-tokens/:id/revoke",
				Method:     httpi.PATCH,
				Handler:    c.RevokeApiToken,
				Middleware: []httpi.HttpHandler{authGuard},
			},
			{
				Path:    "/verify-email",
				Method:  httpi.GET,
				Handler: c.VerifyEmailAndLogin,
			},
			{
				Path:       "/send-email-token",
				Method:     httpi.POST,
				Handler:    c.SendVerificationEmail,
				Middleware: []httpi.HttpHandler{authGuard},
			},
			{
				Path:       "/me/stats",
				Method:     httpi.GET,
				Handler:    c.GetStats,
				Middleware: []httpi.HttpHandler{authGuard},
			},
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

	requestMeta := services.TransportMeta{
		UserAgent: req.GetUserAgent(),
		IPAddress: req.GetIP(),
	}

	if err := c.authService.Register(req.Context(), *username, *email, *password, requestMeta); err != nil {
		return httpi.MappingErrToHttp(err)
	}

	return res.NoContent()
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
func (c *AuthController) LoginWithPassword(req httpi.HttpRequest, res httpi.HttpResponse) error {
	body := dtos.LoginRequest{}
	if err := req.ParseBody(&body); err != nil {
		return httpi.ErrBadRequest(err)
	}

	if err := body.Validate(); err != nil {
		return httpi.ErrValidation(err)
	}

	requestMeta := services.TransportMeta{
		UserAgent: req.GetUserAgent(),
		IPAddress: req.GetIP(),
	}

	user, token, err := c.authService.LoginWithPassword(req.Context(), body.Email, body.Password, requestMeta)
	if err != nil {
		return httpi.MappingErrToHttp(err)
	}

	c.setAuthCookies(res, user, token)

	return res.Status(200).Json(httpi.NewResponseBody(map[string]any{
		"user":  user,
		"token": token,
	}))
}

func (c *AuthController) Refresh(req httpi.HttpRequest, res httpi.HttpResponse) error {
	var refreshToken string

	refreshToken = req.GetCookie(domain.RefreshKey)
	isVayloadCLI := false

	if refreshToken == "" {
		var body dtos.RefreshTokenRequest
		if err := req.ParseBody(&body); err != nil || body.RefreshToken == nil {
			return httpi.ErrBadRequest(err)
		}

		refreshToken = *body.RefreshToken
		isVayloadCLI = true
	}

	if refreshToken == "" {
		return httpi.ErrUnauthorized(nil)
	}

	requestMeta := services.TransportMeta{
		UserAgent: req.GetUserAgent(),
		IPAddress: req.GetIP(),
	}

	token, err := c.authService.RefreshToken(req.Context(), refreshToken, requestMeta)
	if err != nil {
		return httpi.MappingErrToHttp(err)
	}

	// if vayload CLI, return token in body (because it doesn't support cookies)
	if isVayloadCLI {
		return res.Status(200).Json(httpi.NewResponseBody(token))
	}

	c.updateRefreshCookies(res, &token.Token)

	return res.NoContent()
}

func (c *AuthController) Logout(req httpi.HttpRequest, res httpi.HttpResponse) error {
	auth := req.Auth()
	if auth == nil || auth.UserId.IsZero() {
		return httpi.ErrUnauthorized(nil)
	}

	err := c.authService.Logout(req.Context(), auth.UserId)
	if err != nil {
		return httpi.MappingErrToHttp(err)
	}

	c.clearAuthCookies(res)

	return res.Status(200).Json(httpi.NewResponseBody(map[string]any{"message": "Logged out successfully"}))
}

func (c *AuthController) VerifyEmailAndLogin(req httpi.HttpRequest, res httpi.HttpResponse) error {
	requestToken := req.GetQuery("token")
	if requestToken == "" {
		return httpi.ErrBadRequest(errors.New("token is required"))
	}

	user, token, err := c.authService.VerifyEmailAndLogin(req.Context(), requestToken)
	if err != nil {
		return httpi.MappingErrToHttp(err)
	}

	c.setAuthCookies(res, user, token)

	return res.Status(200).Json(httpi.NewResponseBody(map[string]any{"message": "Email verified successfully"}))
}

func (c *AuthController) SendVerificationEmail(req httpi.HttpRequest, res httpi.HttpResponse) error {
	auth, err := req.TryAuth()
	if err != nil {
		return httpi.ErrUnauthorized(err)
	}

	if err := c.authService.SendVerificationEmail(req.Context(), auth.UserId); err != nil {
		return httpi.MappingErrToHttp(err)
	}

	return res.Status(200).Json(httpi.NewResponseBody(map[string]any{"message": "Verification email sent"}))
}

func (c *AuthController) GetMe(req httpi.HttpRequest, res httpi.HttpResponse) error {
	auth := req.Auth()
	if auth == nil || auth.UserId.IsZero() {
		return httpi.ErrUnauthorized(nil)
	}

	user, err := c.userService.GetUser(req.Context(), auth.UserId)
	if err != nil {
		return httpi.MappingErrToHttp(err)
	}

	return res.Status(200).Json(httpi.NewResponseBody(user.ToResponse()))
}

func (c *AuthController) GetStats(req httpi.HttpRequest, res httpi.HttpResponse) error {
	auth := req.Auth()
	if auth == nil || auth.UserId.IsZero() {
		return httpi.ErrUnauthorized(nil)
	}

	stats, err := c.statsService.GetUserStats(req.Context(), auth.UserId)
	if err != nil {
		return httpi.MappingErrToHttp(err)
	}

	return res.Status(200).Json(httpi.NewResponseBody(stats))
}

func (c *AuthController) UpdatePassword(req httpi.HttpRequest, res httpi.HttpResponse) error {
	var body dtos.UpdatePasswordRequest
	if err := req.ParseBody(&body); err != nil {
		return httpi.MappingErrToHttp(err)
	}

	return res.Status(501).Json(httpi.NewResponseBody(map[string]any{"error": "Not implemented"}))
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
	input := services.OauthInput{
		Provider: provider,
		State:    state,
	}

	url, err := c.authService.GetOAuthAuthenticationURI(req.Context(), input)
	if err != nil {
		return httpi.MappingErrToHttp(err)
	}

	return res.Status(200).Json(httpi.NewResponseBody(dtos.OAuthResponse{AuthorizationURI: url}))
}

type oauthRequest struct {
	Provider string
	Code     string
	State    string
}

func (c *AuthController) handleOauthLogin(ctx context.Context, req httpi.HttpRequest, args oauthRequest) (*domain.User, *domain.AuthToken, *domain.OAuthState, error) {
	provider, err := domain.ParseOAuthProvider(args.Provider)
	if err != nil {
		return nil, nil, nil, httpi.MappingErrToHttp(err)
	}

	code := args.Code
	stateStr := args.State

	state, err := domain.ParseOAuthState(stateStr)
	if err != nil {
		return nil, nil, nil, httpi.ErrValidation(err)
	}

	oauthInput := services.OauthInput{
		Provider: provider,
		State:    state,
		Code:     code,
	}
	requestMeta := services.TransportMeta{
		UserAgent: req.GetUserAgent(),
		IPAddress: req.GetIP(),
	}

	user, token, err := c.authService.LoginWithOAuth(ctx, oauthInput, requestMeta)
	if err != nil {
		return nil, nil, nil, httpi.MappingErrToHttp(err)
	}

	return user, token, &state, nil
}

// Process oauth sent from browser (GET)
func (c *AuthController) ExchangeOAuthCode(req httpi.HttpRequest, res httpi.HttpResponse) error {
	args := oauthRequest{
		Provider: req.GetParam("provider"),
		Code:     req.GetQuery("code"),
		State:    req.GetQuery("state"),
	}

	user, token, state, err := c.handleOauthLogin(req.Context(), req, args)
	if err != nil {
		return err
	}

	c.setAuthCookies(res, user, token)
	return res.Redirect(state.OriginURI, 302)
}

// Process oauth sent from CLI (POST)
func (c *AuthController) ExchangeOAuthCodeRaw(req httpi.HttpRequest, res httpi.HttpResponse) error {
	var body dtos.OAuthExchangeParams
	if err := req.ParseBody(&body); err != nil {
		return httpi.MappingErrToHttp(err)
	}

	args := oauthRequest{
		Provider: req.GetParam("provider"),
		Code:     body.Code,
		State:    body.State,
	}

	_, token, _, err := c.handleOauthLogin(req.Context(), req, args)
	if err != nil {
		return err
	}

	return res.Status(200).Json(httpi.NewResponseBody(dtos.OAuthDataResponse{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    token.ExpiresIn,
	}))
}

func (c *AuthController) ListApiTokens(req httpi.HttpRequest, res httpi.HttpResponse) error {
	auth, err := req.TryAuth()
	if err != nil {
		return httpi.ErrUnauthorized(err)
	}

	tokens, err := c.authService.ListApiTokens(req.Context(), auth.UserId)
	if err != nil {
		return httpi.MappingErrToHttp(err)
	}

	response := make([]dtos.ApiTokenResponse, len(tokens))
	for i, t := range tokens {
		response[i] = c.mapToApiTokenResponse(t)
	}

	return res.Status(200).Json(httpi.NewResponseBody(response))
}

func (c *AuthController) CreateApiToken(req httpi.HttpRequest, res httpi.HttpResponse) error {
	auth, err := req.TryAuth()
	if err != nil {
		return httpi.ErrUnauthorized(err)
	}

	body := dtos.CreateApiTokenRequest{}
	if err := req.ParseBody(&body); err != nil {
		return httpi.ErrBadRequest(err)
	}

	// Is posible to asign any permission, because previous validate authentication
	var scope *domain.KeyScope
	if len(body.Scope) > 0 {
		var err error
		scope, err = domain.ParseKeyScope(body.Scope, body.PluginID)
		if err != nil {
			scope = &domain.KeyScope{Prefix: "global", Permission: domain.ScopeReadOnly}
		}
	} else {
		scope = &domain.KeyScope{Prefix: "global", Permission: domain.ScopeReadOnly}
	}

	token, raw, err := c.authService.CreateApiToken(req.Context(), auth.UserId, body.Name, *scope)
	if err != nil {
		return httpi.MappingErrToHttp(err)
	}

	response := c.mapToApiTokenResponse(token)
	response.Key = &raw

	return res.Status(200).Json(httpi.NewResponseBody(response))
}

func (c *AuthController) DeleteApiToken(req httpi.HttpRequest, res httpi.HttpResponse) error {
	auth, err := req.TryAuth()
	if err != nil {
		return httpi.ErrUnauthorized(err)
	}

	tokenID, err := identity.FromString(req.GetParam("id"))
	if err != nil {
		return httpi.ErrValidation(err)
	}

	err = c.authService.DeleteApiToken(req.Context(), auth.UserId, tokenID.String())
	if err != nil {
		return httpi.MappingErrToHttp(err)
	}

	return res.Status(200).Json(httpi.NewResponseBody(map[string]any{"message": "API token deleted successfully"}))
}

func (c *AuthController) RevokeApiToken(req httpi.HttpRequest, res httpi.HttpResponse) error {
	auth, err := req.TryAuth()
	if err != nil {
		return httpi.ErrUnauthorized(err)
	}

	tokenID, err := identity.FromString(req.GetParam("id"))
	if err != nil {
		return httpi.ErrValidation(err)
	}

	err = c.authService.RevokeApiToken(req.Context(), auth.UserId, tokenID.String())
	if err != nil {
		return httpi.MappingErrToHttp(err)
	}

	return res.Status(200).Json(httpi.NewResponseBody(map[string]any{"message": "API token revoked successfully"}))
}

func (c *AuthController) mapToApiTokenResponse(t domain.ApiToken) dtos.ApiTokenResponse {
	scope := []string{t.Scope.String()}

	var plugin *dtos.ApiTokenPluginResponse
	if t.PluginID != nil {
		plugin = &dtos.ApiTokenPluginResponse{
			ID:   *t.PluginID,
			Name: "Unknown", // Repository/Domain should ideally provide this or service should fetch it
		}
	}

	return dtos.ApiTokenResponse{
		ID:            t.ID.String(),
		Name:          t.Name.String(),
		KeyMask:       t.KeyMask,
		Scope:         scope,
		Plugin:        plugin,
		Enabled:       !t.IsRevoked() && !t.IsExpired(),
		CreatedAt:     t.CreatedAt,
		LastUsedAt:    t.LastUsed,
		ExpiresAt:     t.ExpiresAt,
		RevokedAt:     t.RevokedAt,
		RevokedReason: t.RevokedReason,
	}
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
		SameSite: "Lax",
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
			SameSite: "Lax",
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
		SameSite: "Lax",
	})

	res.Cookie(&httpi.Cookie{
		Name:     domain.RefreshKey,
		Value:    token.RefreshToken,
		Expires:  refreshExpiresAt,
		Domain:   domainName,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: "Lax",
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
		SameSite: "Lax",
	})

	res.Cookie(&httpi.Cookie{
		Name:     domain.RefreshKey,
		Value:    token.RefreshToken,
		Expires:  refreshExpiresAt,
		Domain:   domainName,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: "Lax",
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
			SameSite: "Lax",
		})
	}
}
