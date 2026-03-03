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
	"github.com/vayload/plug-registry/internal/shared/errors"
	"github.com/vayload/plug-registry/internal/shared/identity"
	"github.com/vayload/plug-registry/pkg/crypto"
	"github.com/vayload/plug-registry/pkg/logger"
	"github.com/vayload/plug-registry/pkg/queue"
)

const AUTH_SERVICE_NAME = "auth_service"

type TransportMeta struct {
	UserAgent string
	IPAddress string
}

type AuthService struct {
	userRespository domain.UserRepository
	tokenRepository domain.ApiTokenRepository
	hashing         domain.HashingStrategy
	oauthStrategy   domain.OAuthStrategy
	jwtManager      domain.TokenManager
	verifier        *security.VerificationTokenManager
	producer        queue.Producer
}

func NewAuthService(
	userRespository domain.UserRepository,
	tokenRepository domain.ApiTokenRepository,
	hashing domain.HashingStrategy,
	oauthStrategy domain.OAuthStrategy,
	jwtManager domain.TokenManager,
	verifier *security.VerificationTokenManager,
	producer queue.Producer,
) *AuthService {
	service := &AuthService{
		userRespository: userRespository,
		tokenRepository: tokenRepository,
		hashing:         hashing,
		oauthStrategy:   oauthStrategy,
		jwtManager:      jwtManager,
		verifier:        verifier,
		producer:        producer,
	}

	return service
}

func (service *AuthService) Register(ctx context.Context, username domain.Username, email domain.Email, password domain.PasswordHash, meta TransportMeta) error {
	// Check if already exists
	existing, _ := service.userRespository.FindUserBy(ctx, domain.UserFilterBy{Email: &email})
	if existing != nil {
		return errors.AlreadyExists("Email already registered")
	}

	existingUser, _ := service.userRespository.FindUserBy(ctx, domain.UserFilterBy{Username: &username})
	if existingUser != nil {
		return errors.AlreadyExists("Username already taken")
	}

	pwdHash, err := service.hashing.Hash(password.String())
	if err != nil {
		return errors.Internal("Failed to hash password").Cause(err)
	}

	userID := domain.NewUserID()
	user := domain.NewUser(
		userID,
		username,
		email,
		domain.AuthProviderPassword,
		userID.String(),
	)
	user.SetPassword(domain.PasswordHash(pwdHash))

	expiration := time.Now().Add(time.Minute * 15)
	unverifiedToken := domain.UnverifiedToken{
		Token: service.verifier.Generate(userID.String(), expiration),
		Exp:   time.Duration(expiration.Minute()),
	}

	createdUser, err := service.userRespository.CreateUnverifiedUser(ctx, *user, unverifiedToken)
	if err != nil {
		return errors.Internal("Failed to create unverified user").Cause(err)
	}
	createdUser.UnsetPassword()

	go func() {
		job := queue.NewJob(crypto.GenerateNanoID(), queue.JobTypeEmailVerification, map[string]any{
			"email":    email.String(),
			"username": username.String(),
			"token":    unverifiedToken.Token,
		})

		if err := service.producer.Publish(context.Background(), job); err != nil {
			logger.E(err, logger.Fields{"msg": "Failed to publish email verification job", "email": email.String(), "job": job})
		}
	}()

	return nil
}

func (service *AuthService) SendVerificationEmail(ctx context.Context, userID domain.UserID) error {
	user, err := service.userRespository.FindUserBy(ctx, domain.UserFilterBy{ID: &userID})
	if err != nil || user == nil {
		return errors.NotFound("User not found")
	}

	if user.EmailVerified {
		return errors.Validation("Email already verified")
	}

	expiresAt := time.Now().UTC().Add(24 * time.Hour)
	token := service.verifier.Generate(userID.String(), expiresAt)

	go func() {
		job := queue.NewJob(crypto.GenerateNanoID(), queue.JobTypeEmailVerification, map[string]any{
			"email":    user.Email.String(),
			"username": user.Username.String(),
			"token":    token,
		})

		if err := service.producer.Publish(context.Background(), job); err != nil {
			logger.E(err, logger.Fields{"msg": "Failed to publish email verification job", "email": user.Email.String(), "job": job})
		}
	}()

	return nil
}

func (service *AuthService) VerifyEmailAndLogin(ctx context.Context, rawToken string) (*domain.User, *domain.AuthToken, error) {
	userIDStr, err := service.verifier.Validate(rawToken)
	if err != nil {
		return nil, nil, errors.Unauthorized("Invalid or expired verification token").Cause(err)
	}

	rawID, err := identity.FromString(userIDStr)
	if err != nil {
		return nil, nil, errors.Unauthorized("Invalid or malformed token").Cause(err)
	}

	userID := domain.UserID{ID: rawID}

	user, err := service.userRespository.FindByVerificationToken(ctx, userID, rawToken)
	if err != nil || user == nil {
		return nil, nil, errors.NotFound("User not found or token mismatch").Cause(err)
	}

	if user.EmailVerified {
		return nil, nil, errors.Conflict("Email already verified")
	}

	if err := service.userRespository.MarkEmailVerified(ctx, domain.UserID{ID: rawID}); err != nil {
		return nil, nil, errors.Internal("Failed to mark email verified").Cause(err)
	}

	token, err := service.jwtManager.Sign(domain.TokenPayload{
		UserID: userID.String(),
		Email:  user.Email.String(),
		Role:   string(user.Role),
	})
	if err != nil {
		return nil, nil, errors.Internal("Failed to generate token").Cause(err)
	}

	return user, &token, nil
}

func (service *AuthService) LoginWithPassword(ctx context.Context, emailStr, password string, meta TransportMeta) (*domain.User, *domain.AuthToken, error) {
	user, err := service.userRespository.FindUserBy(ctx, domain.NewUserFilterBy().WithEmail(domain.Email(emailStr)))
	if err != nil || user == nil {
		return nil, nil, errors.Unauthorized("Invalid credentials").Cause(err)
	}

	// If user is using OAuth, use it again
	if user.Provider != domain.AuthProviderPassword {
		return nil, nil, errors.Unauthorized("You are using OAuth to login, use it again")
	}

	if user.PasswordHash == nil || !service.hashing.Verify(password, user.PasswordHash.String()) {
		return nil, nil, errors.Unauthorized("Invalid credentials")
	}

	user.UnsetPassword()
	token, err := service.jwtManager.Sign(domain.TokenPayload{
		UserID: user.ID.String(),
		Email:  user.Email.String(),
		Role:   string(user.Role),
	})
	if err != nil {
		return nil, nil, errors.Internal("Failed to generate token").Cause(err)
	}

	if err := service.storeRefreshToken(ctx, user.ID, token, meta); err != nil {
		return nil, nil, errors.Internal("Failed to store refresh token").Cause(err)
	}

	// This case only log, because it's not critical
	if err := service.userRespository.UpdateLastLogin(ctx, user.ID, time.Now().UTC()); err != nil {
		logger.E(err, logger.Fields{"msg": "Failed to update last login", "user_id": user.ID.String()})
	}

	return user, &token, nil
}

type OauthInput struct {
	Provider domain.OAuthProvider
	State    domain.OAuthState
	Code     string // when need for exchange code
}

func (service *AuthService) GetOAuthAuthenticationURI(ctx context.Context, input OauthInput) (string, error) {
	return service.oauthStrategy.GetAuthenticationURI(input.Provider, input.State)
}

func (service *AuthService) LoginWithOAuth(ctx context.Context, input OauthInput, meta TransportMeta) (*domain.User, *domain.AuthToken, error) {
	oauthUser, err := service.oauthStrategy.ExchangeCode(input.Provider, input.State.ClientType, input.Code)

	if err != nil {
		return nil, nil, err
	}

	authProvider, err := domain.ParseAuthProvider(string(input.Provider))
	if err != nil {
		return nil, nil, err
	}

	user, err := service.userRespository.FindUserBy(ctx, domain.NewUserFilterBy().WithEmail(domain.Email(oauthUser.Email)))
	if err != nil {
		return nil, nil, err
	}

	// When user not exists, create
	isNewUser := user == nil
	if user == nil {
		userID := domain.NewUserID()
		email, _ := domain.NewEmail(oauthUser.Email)
		username, _ := domain.NewUsername(strings.ToLower(strings.ReplaceAll(oauthUser.Name, " ", "_")))

		now := time.Now().UTC()
		user = domain.NewUser(
			userID,
			username,
			email,
			authProvider,
			oauthUser.SID,
		)
		if oauthUser.AvatarURL != "" {
			user.SetAvatarURL(&oauthUser.AvatarURL)
		}
		user.SetVerifiedAt(&now)

		created, err := service.userRespository.Create(ctx, *user)
		if err != nil {
			return nil, nil, err
		}
		user = &created
	}

	user.UnsetPassword()
	token, err := service.jwtManager.Sign(domain.TokenPayload{
		UserID: user.ID.String(),
		Email:  user.Email.String(),
		Role:   string(user.Role),
	})
	if err != nil {
		return nil, nil, err
	}

	if err := service.storeRefreshToken(ctx, user.ID, token, meta); err != nil {
		return nil, nil, err
	}

	// If user is new, send welcome email
	if isNewUser {
		job := queue.NewJob(crypto.GenerateNanoID(), queue.JobTypeEmailWelcome, map[string]any{
			"email":    user.Email.String(),
			"username": user.Username.String(),
		})

		if err := service.producer.Publish(context.Background(), job); err != nil {
			logger.E(err, logger.Fields{"msg": "Failed to publish email welcome job", "user_id": user.ID.String()})
		}
	}

	return user, &token, nil
}

type RefreshTokenOutput struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`

	Token domain.AuthToken `json:"-"`
}

func (service *AuthService) RefreshToken(ctx context.Context, token string, meta TransportMeta) (*RefreshTokenOutput, error) {
	bytes, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, errors.Unauthorized("Invalid refresh token").Cause(err)
	}

	// Hasing for search in database the hash
	hasher := sha256.New()
	hasher.Write(bytes)
	tokenHash := fmt.Sprintf("%x", hasher.Sum(nil))

	storedToken, err := service.userRespository.FindRefreshTokenByHash(ctx, tokenHash)
	if err != nil || storedToken == nil {
		return nil, errors.Unauthorized("Refresh token not found").Cause(err)
	}

	if storedToken.IsUsed() {
		service.userRespository.RevokeRefreshTokenFamily(ctx, storedToken.FamilyID, "reuse_detected")
		return nil, errors.Unauthorized("this token is comprom").Cause(err)
	}

	if !storedToken.IsValid() {
		return nil, errors.Unauthorized("Expired or revoked token").Cause(err)
	}

	rawUserID, err := identity.FromString(storedToken.UserID)
	if err != nil {
		return nil, errors.Unauthorized("Invalid refresh token").Cause(err)
	}

	userID := domain.UserID{ID: rawUserID}
	user, err := service.userRespository.FindUserBy(ctx, domain.UserFilterBy{ID: &userID})
	if err != nil || user == nil {
		return nil, errors.NotFound("User not found").Cause(err)
	}

	// Mark token as used
	if err := service.userRespository.MarkRefreshTokenUsed(ctx, storedToken.ID); err != nil {
		return nil, err
	}

	newToken, err := service.jwtManager.Sign(domain.TokenPayload{
		UserID: userID.String(),
		Email:  user.Email.String(),
		Role:   string(user.Role),
	})
	if err != nil {
		return nil, err
	}

	// Create new refresh token
	expiresAt := time.Now().UTC().Add(time.Duration(newToken.RefreshTokenExpiresIn) * time.Second)
	refreshToken := domain.NewRotatedRefreshToken(
		identity.MustNew().String(),
		userID.String(),
		newToken.RefreshTokenHash,
		storedToken.FamilyID,
		storedToken.ID,
		expiresAt,
		&meta.UserAgent,
		&meta.IPAddress,
	)

	if err := service.userRespository.CreateRefreshToken(ctx, &refreshToken); err != nil {
		return nil, err
	}

	return &RefreshTokenOutput{
		AccessToken:  newToken.AccessToken,
		RefreshToken: newToken.RefreshToken,
		TokenType:    "Bearer ",
		ExpiresIn:    newToken.ExpiresAt.Second(),
		Token:        newToken,
	}, nil
}

// Create token, generate when user is logged in
func (service *AuthService) storeRefreshToken(ctx context.Context, userID domain.UserID, token domain.AuthToken, meta TransportMeta) error {
	expiresAt := time.Now().UTC().Add(time.Duration(token.RefreshTokenExpiresIn) * time.Second)
	refreshToken := domain.NewRefreshToken(
		identity.MustNew().String(),
		userID.String(),
		token.RefreshTokenHash,
		identity.MustNew().String(),
		expiresAt,
		&meta.UserAgent,
		&meta.IPAddress,
	)

	return service.userRespository.CreateRefreshToken(ctx, &refreshToken)
}

func (service *AuthService) Logout(ctx context.Context, userID domain.UserID) error {
	return service.userRespository.UpdateLastLogin(ctx, userID, time.Now().UTC())
}

func (service *AuthService) CreateApiToken(ctx context.Context, userID domain.UserID, nameStr string, scope domain.KeyScope) (domain.ApiToken, string, error) {
	name, err := domain.NewKeyName(nameStr)
	if err != nil {
		return domain.ApiToken{}, "", err
	}

	rawKey := security.GenerateOpaqueApiToken(domain.ApiTokenPrefix)
	apiTokenID := domain.ApiTokenId(identity.MustNew().String())

	apiToken := domain.NewApiToken(
		apiTokenID,
		userID.String(),
		domain.KeyHash(rawKey.Hashed),
		rawKey.Raw,
		rawKey.Mask,
		name,
		scope,
	)

	created, err := service.tokenRepository.Create(ctx, apiToken)
	return created, rawKey.Raw, err
}

func (service *AuthService) VerifyApiToken(ctx context.Context, rawToken string) (*domain.ApiToken, error) {
	token, err := security.OpaqueApiTokenFrom(rawToken)
	if err != nil {
		return nil, err
	}

	storedToken, err := service.tokenRepository.GetByHash(ctx, token.Hashed)
	if err != nil || storedToken == nil {
		return nil, errors.NotFound("API token not found").Cause(err)
	}

	if storedToken.IsRevoked() || storedToken.IsExpired() {
		return nil, errors.Unauthorized("Expired or revoked token").Cause(err)
	}

	return storedToken, nil
}

func (service *AuthService) RevokeApiToken(ctx context.Context, userID domain.UserID, apiTokenID string) error {
	token, err := service.tokenRepository.GetByID(ctx, domain.ApiTokenId(apiTokenID))
	if err != nil || token == nil {
		return errors.NotFound("API token not found").Cause(err)
	}

	if token.UserID != userID.String() {
		return errors.Forbidden("You are not the owner of this token")
	}

	return service.tokenRepository.Revoke(ctx, domain.ApiTokenId(apiTokenID))
}

func (service *AuthService) ListApiTokens(ctx context.Context, userID domain.UserID) ([]domain.ApiToken, error) {
	return service.tokenRepository.ListByUser(ctx, userID.String())
}

func (service *AuthService) DeleteApiToken(ctx context.Context, userID domain.UserID, apiTokenID string) error {
	token, err := service.tokenRepository.GetByID(ctx, domain.ApiTokenId(apiTokenID))
	if err != nil || token == nil {
		return errors.NotFound("API token not found").Cause(err)
	}

	if token.UserID != userID.String() {
		return errors.Forbidden("You are not the owner of this token")
	}

	return service.tokenRepository.Delete(ctx, domain.ApiTokenId(apiTokenID))
}

func (service *AuthService) MarkApiTokenAsUsed(ctx context.Context, apiTokenID string) error {
	return service.tokenRepository.UpdateLastUsed(ctx, domain.ApiTokenId(apiTokenID))
}
