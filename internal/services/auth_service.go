package services

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/vayload/plug-registry/internal/domain"
	"github.com/vayload/plug-registry/internal/infrastructure/security"
	"github.com/vayload/plug-registry/internal/shared/entity"
	"github.com/vayload/plug-registry/pkg/ids"
)

type AuthService struct {
	repository    domain.UserRepository
	tokenRepo     domain.ApiTokenRepository
	hashing       domain.HashingStrategy
	oauthStrategy domain.OAuthStrategy
	jwtManager    domain.TokenManager
}

func NewAuthService(
	repository domain.UserRepository,
	tokenRepo domain.ApiTokenRepository,
	hashing domain.HashingStrategy,
	oauthStrategy domain.OAuthStrategy,
	jwtManager domain.TokenManager,
) *AuthService {
	return &AuthService{
		repository:    repository,
		tokenRepo:     tokenRepo,
		hashing:       hashing,
		oauthStrategy: oauthStrategy,
		jwtManager:    jwtManager,
	}
}

func (s *AuthService) Register(ctx context.Context, username domain.Username, email domain.Email, password domain.PasswordHash) (*domain.User, *domain.AuthToken, error) {
	// Check if already exists
	existing, _ := s.repository.GetByEmail(ctx, email.String())
	if existing != nil {
		return nil, nil, domain.NewAlreadyExistsError("Email already registered")
	}

	existingUser, _ := s.repository.GetByUsername(ctx, username.String())
	if existingUser != nil {
		return nil, nil, domain.NewAlreadyExistsError("Username already taken")
	}

	pwdHash, err := s.hashing.Hash(password.String())
	if err != nil {
		return nil, nil, err
	}

	userID := domain.NewUserID()
	user := domain.NewUser(
		userID,
		username,
		email,
		nil,
		domain.AuthProviderPassword,
		userID.String(),
		nil,
	)
	var ph = domain.PasswordHash(pwdHash)
	user.PasswordHash = &ph

	createdUser, err := s.repository.Create(ctx, *user)
	if err != nil {
		return nil, nil, err
	}
	createdUser.UnsetPassword()

	token, err := s.jwtManager.Sign(domain.TokenPayload{
		UserID: userID.String(),
		Email:  email.String(),
		Role:   createdUser.Role.String(),
	})
	if err != nil {
		return nil, nil, err
	}

	if err := s.saveRefreshToken(ctx, userID, token); err != nil {
		return nil, nil, err
	}

	return &createdUser, &token, nil
}

func (s *AuthService) Login(ctx context.Context, emailStr, password string) (*domain.User, *domain.AuthToken, error) {
	user, err := s.repository.GetByEmail(ctx, emailStr)
	if err != nil || user == nil {
		return nil, nil, domain.NewUnauthorizedError("Invalid credentials")
	}

	if user.PasswordHash == nil || !s.hashing.Verify(password, user.PasswordHash.String()) {
		return nil, nil, domain.NewUnauthorizedError("Invalid credentials")
	}

	user.UnsetPassword()
	token, err := s.jwtManager.Sign(domain.TokenPayload{
		UserID: user.ID.String(),
		Email:  user.Email.String(),
		Role:   string(user.Role),
	})
	if err != nil {
		return nil, nil, err
	}

	if err := s.saveRefreshToken(ctx, user.ID, token); err != nil {
		return nil, nil, err
	}

	_ = s.repository.UpdateLastLogin(ctx, user.ID, time.Now().UTC())

	return user, &token, nil
}

func (s *AuthService) GetOAuthAuthenticationURI(ctx context.Context, provider domain.OAuthProvider, state domain.OAuthState) (string, error) {
	return s.oauthStrategy.GetAuthenticationURI(provider, state)
}

func (s *AuthService) LoginWithOAuth(ctx context.Context, provider domain.OAuthProvider, code string, state domain.OAuthState) (*domain.User, *domain.AuthToken, error) {
	oauthUser, err := s.oauthStrategy.ExchangeCode(provider, state.ClientType, code)
	if err != nil {
		return nil, nil, err
	}

	authProvider, err := domain.ParseAuthProvider(string(provider))
	if err != nil {
		return nil, nil, err
	}

	user, _ := s.repository.GetByProvider(ctx, authProvider, oauthUser.SID)
	if user == nil {
		user, _ = s.repository.GetByEmail(ctx, oauthUser.Email)
	}

	if user == nil {
		// Create new user
		userID := domain.NewUserID()
		email, _ := domain.NewEmail(oauthUser.Email)
		username, _ := domain.NewUsername(strings.ToLower(strings.ReplaceAll(oauthUser.Name, " ", "_")))

		now := time.Now().UTC()
		user = domain.NewUser(
			userID,
			username,
			email,
			&oauthUser.AvatarURL,
			authProvider,
			oauthUser.SID,
			&now,
		)
		created, err := s.repository.Create(ctx, *user)
		if err != nil {
			return nil, nil, err
		}
		user = &created
	}

	user.UnsetPassword()
	token, err := s.jwtManager.Sign(domain.TokenPayload{
		UserID: user.ID.String(),
		Email:  user.Email.String(),
		Role:   string(user.Role),
	})
	if err != nil {
		return nil, nil, err
	}

	if err := s.saveRefreshToken(ctx, user.ID, token); err != nil {
		return nil, nil, err
	}

	return user, &token, nil
}

func (s *AuthService) RefreshToken(ctx context.Context, refreshTokenStr string) (*domain.AuthToken, error) {
	bytes, err := base64.RawURLEncoding.DecodeString(refreshTokenStr)
	if err != nil {
		return nil, domain.NewUnauthorizedError("Invalid refresh token")
	}
	hasher := sha256.New()
	hasher.Write(bytes)
	tokenHash := fmt.Sprintf("%x", hasher.Sum(nil))

	storedToken, err := s.repository.FindRefreshTokenByHash(ctx, tokenHash)
	if err != nil || storedToken == nil {
		return nil, domain.NewUnauthorizedError("Refresh token not found")
	}

	if storedToken.IsRevoked() || storedToken.IsExpired() {
		return nil, domain.NewUnauthorizedError("Expired or revoked token")
	}

	rawUserID, err := entity.FromString(storedToken.UserID)
	if err != nil {
		return nil, domain.NewUnauthorizedError("Invalid refresh token")
	}

	userID := domain.UserID{ID: rawUserID}
	user, err := s.repository.GetByID(ctx, userID)
	if err != nil || user == nil {
		return nil, domain.NewNotFoundError("User not found")
	}

	if err := s.repository.RemoveRefreshToken(ctx, userID, storedToken.TokenHash); err != nil {
		return nil, err
	}

	newToken, err := s.jwtManager.Sign(domain.TokenPayload{
		UserID: userID.String(),
		Email:  user.Email.String(),
		Role:   string(user.Role),
	})
	if err != nil {
		return nil, err
	}

	if err := s.saveRefreshToken(ctx, userID, newToken); err != nil {
		return nil, err
	}

	return &newToken, nil
}

func (s *AuthService) saveRefreshToken(ctx context.Context, userID domain.UserID, token domain.AuthToken) error {
	expiresAt := time.Now().UTC().Add(time.Duration(token.RefreshTokenExpiresIn) * time.Second)
	refreshToken := domain.NewRefreshToken(
		ids.New().String(),
		userID.String(),
		token.RefreshTokenHash,
		&expiresAt,
	)
	return s.repository.UpsertRefreshToken(ctx, userID, &refreshToken)
}

func (s *AuthService) Logout(ctx context.Context, userID domain.UserID) error {
	return s.repository.UpdateLastLogin(ctx, userID, time.Now().UTC())
}

func (s *AuthService) CreateApiToken(ctx context.Context, userID domain.UserID, nameStr string, scope domain.KeyScope) (domain.ApiToken, string, error) {
	name, err := domain.NewKeyName(nameStr)
	if err != nil {
		return domain.ApiToken{}, "", err
	}

	rawKey := security.GenerateOpaqueApiToken(domain.ApiTokenPrefix)
	apiTokenID := domain.ApiTokenId(ids.New().String())

	apiToken := domain.NewApiToken(
		apiTokenID,
		userID.String(),
		domain.KeyHash(rawKey.Hashed),
		rawKey.Raw,
		rawKey.Mask,
		name,
		scope,
	)

	created, err := s.tokenRepo.Create(ctx, apiToken)
	return created, rawKey.Raw, err
}

func (s *AuthService) VerifyApiToken(ctx context.Context, rawToken string) (*domain.ApiToken, error) {
	token, err := security.OpaqueApiTokenFrom(rawToken)
	if err != nil {
		return nil, err
	}

	storedToken, err := s.tokenRepo.GetByHash(ctx, token.Hashed)
	if err != nil || storedToken == nil {
		return nil, domain.NewNotFoundError("API token not found")
	}

	if storedToken.IsRevoked() || storedToken.IsExpired() {
		return nil, domain.NewUnauthorizedError("Expired or revoked token")
	}

	return storedToken, nil
}

func (s *AuthService) RevokeApiToken(ctx context.Context, userID domain.UserID, apiTokenID string) error {
	token, err := s.tokenRepo.GetByID(ctx, domain.ApiTokenId(apiTokenID))
	if err != nil || token == nil {
		return domain.NewNotFoundError("API token not found")
	}

	if token.UserID != userID.String() {
		return domain.NewForbiddenError()
	}

	return s.tokenRepo.Revoke(ctx, domain.ApiTokenId(apiTokenID))
}

func (s *AuthService) MarkApiTokenAsUsed(ctx context.Context, apiTokenID string) error {
	return s.tokenRepo.UpdateLastUsed(ctx, domain.ApiTokenId(apiTokenID))
}
