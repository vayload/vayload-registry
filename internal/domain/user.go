package domain

import (
	"context"
	"strings"
	"time"

	"github.com/vayload/plug-registry/internal/shared/entity"
)

const (
	SessionKey    = "__access_token__"
	RefreshKey    = "__refresh_token__"
	AvatarURLKey  = "__avatar_url__"
	IsLoggedInKey = "__is_logged_in__"
)

// ======================== Value Objects ========================

type UserID struct {
	entity.ID
}

func NewUserID() UserID {
	return UserID{ID: entity.New()}
}

func (id UserID) Equals(other UserID) bool {
	return id.ID.Equals(other.ID)
}

func (id UserID) Unwrap() entity.ID {
	return id.ID
}

type Email string

func NewEmail(email string) (Email, error) {
	if email == "" {
		return "", NewValidationError("Email cannot be empty")
	}
	if !IsValidEmail(email) {
		return "", NewValidationError("Invalid email format")
	}

	return Email(email), nil
}

func IsValidEmail(email string) bool {
	if email == "" {
		return false
	}
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}
	localPart, domain := parts[0], parts[1]
	if localPart == "" || domain == "" {
		return false
	}
	if strings.ContainsAny(localPart, " !\"#$%&'()*+,/:;<=>?@[\\]^`{|}~") {
		return false
	}
	if strings.Contains(domain, " ") || !strings.Contains(domain, ".") {
		return false
	}
	return true
}

func (e Email) String() string {
	return string(e)
}

type Username string

func NewUsername(username string) (Username, error) {
	if username == "" {
		return "", NewValidationError("Username cannot be empty")
	}
	if len(username) < 3 && len(username) > 32 && strings.ContainsAny(username, " !\"#$%&'()*+,/:;<=>?@[\\]^`{|}~ ") {
		return "", NewValidationError("Invalid username format")
	}

	return Username(username), nil
}

func (u Username) String() string {
	return string(u)
}

const (
	MinPasswordLength = 8
)

type PasswordHash string

func NewPasswordHash(password string) (PasswordHash, error) {
	if password == "" {
		return "", NewValidationError("Password cannot be empty")
	}
	if len(password) < MinPasswordLength {
		return "", NewValidationError("Password is too short")
	}

	return PasswordHash(password), nil
}

func (h PasswordHash) String() string {
	return string(h)
}

type AuthProvider string

const (
	AuthProviderPassword AuthProvider = "password"
	AuthProviderGitHub   AuthProvider = "github"
	AuthProviderGoogle   AuthProvider = "google"
)

func (p AuthProvider) String() string {
	return string(p)
}

func ParseAuthProvider(s string) (AuthProvider, error) {
	switch strings.ToLower(s) {
	case "password":
		return AuthProviderPassword, nil
	case "github":
		return AuthProviderGitHub, nil
	case "google":
		return AuthProviderGoogle, nil
	default:
		return "", NewValidationError("Invalid auth provider")
	}
}

type UserRole string

const (
	UserRoleDeveloper  UserRole = "developer"
	UserRoleMaintainer UserRole = "maintainer"
	UserRoleAdmin      UserRole = "admin" // for future
)

func (r UserRole) String() string {
	return string(r)
}

// ======================== Entities ========================

type User struct {
	ID           UserID
	Username     Username
	Email        Email
	Role         UserRole
	PasswordHash *PasswordHash
	AvatarURL    *string
	Provider     AuthProvider
	ProviderID   string
	VerifiedAt   *time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
	LastLoginAt  *time.Time
	IsActive     bool
}

func NewUser(
	id UserID,
	username Username,
	email Email,
	avatarURL *string,
	provider AuthProvider,
	providerID string,
	verifiedAt *time.Time,
) *User {
	return &User{
		ID:          id,
		Username:    username,
		Email:       email,
		AvatarURL:   avatarURL,
		Provider:    provider,
		ProviderID:  providerID,
		VerifiedAt:  verifiedAt,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
		LastLoginAt: nil,
		IsActive:    true,
		Role:        UserRoleDeveloper,
	}
}

func (u *User) SetPassword(hash PasswordHash) {
	u.PasswordHash = &hash
}

func (u *User) UnsetPassword() {
	u.PasswordHash = nil
}

type RefreshToken struct {
	ID            string
	UserID        string
	TokenHash     string
	ExpiresAt     *time.Time
	RevokedAt     *time.Time
	RevokedReason *string
	CreatedAt     time.Time
}

func NewRefreshToken(id, userID, tokenHash string, expiresAt *time.Time) RefreshToken {
	return RefreshToken{
		ID:        id,
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
		RevokedAt: nil,
		CreatedAt: time.Now().UTC(),
	}
}

func (t RefreshToken) IsRevoked() bool {
	return t.RevokedAt != nil
}

func (t RefreshToken) IsExpired() bool {
	return t.ExpiresAt.Before(time.Now().UTC())
}

type AuthToken struct {
	AccessToken           string
	RefreshToken          string
	RefreshTokenHash      string
	RefreshTokenExpiresIn uint64
	ExpiresAt             time.Time
	ExpiresIn             uint64
}

type AuthUser struct {
	User  User
	Token AuthToken
}

// ======================== Repositories ========================

type UserRepository interface {
	Create(ctx context.Context, user User) (User, error)
	GetByID(ctx context.Context, id UserID) (*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	GetByUsername(ctx context.Context, username string) (*User, error)
	GetByProvider(ctx context.Context, provider AuthProvider, providerID string) (*User, error)
	UpdatePassword(ctx context.Context, email Email, password PasswordHash) error
	UpdateUsername(ctx context.Context, id UserID, username Username) error
	UpdateEmail(ctx context.Context, id UserID, email string) error
	VerifyEmail(ctx context.Context, id UserID) error
	UpdateLastLogin(ctx context.Context, id UserID, at time.Time) error

	UpsertRefreshToken(ctx context.Context, userID UserID, token *RefreshToken) error
	RemoveRefreshToken(ctx context.Context, id UserID, token string) error
	GetRefreshToken(ctx context.Context, id UserID, token string) (*RefreshToken, error)
	FindRefreshTokenByHash(ctx context.Context, tokenHash string) (*RefreshToken, error)
}
