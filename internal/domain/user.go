package domain

import (
	"context"
	"strings"
	"time"

	"github.com/vayload/plug-registry/internal/shared/errors"
	"github.com/vayload/plug-registry/internal/shared/identity"
)

const (
	SessionKey    = "__access_token__"
	RefreshKey    = "__refresh_token__"
	AvatarURLKey  = "__avatar_url__"
	IsLoggedInKey = "__is_logged_in__"
)

// ======================== Value Objects ========================

type UserID struct {
	identity.ID
}

func NewUserID() UserID {
	return UserID{ID: identity.MustNew()}
}

func (id UserID) Equals(other UserID) bool {
	return id.ID.Equals(other.ID)
}

func (id UserID) Unwrap() identity.ID {
	return id.ID
}

type Email string

func NewEmail(email string) (Email, error) {
	if email == "" {
		return "", errors.Validation("Email cannot be empty")
	}
	if !IsValidEmail(email) {
		return "", errors.Validation("Invalid email format")
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
		return "", errors.Validation("Username cannot be empty")
	}
	if len(username) < 3 && len(username) > 32 && strings.ContainsAny(username, " !\"#$%&'()*+,/:;<=>?@[\\]^`{|}~ ") {
		return "", errors.Validation("Invalid username format")
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
		return "", errors.Validation("Password cannot be empty")
	}
	if len(password) < MinPasswordLength {
		return "", errors.Validation("Password is too short")
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
		return "", errors.Validation("Invalid auth provider")
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
	ID            UserID `json:"id"`
	Username      Username
	Email         Email
	Role          UserRole
	PasswordHash  *PasswordHash
	AvatarURL     *string
	Provider      AuthProvider
	ProviderID    string
	VerifiedAt    *time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
	LastLoginAt   *time.Time
	IsActive      bool
	EmailVerified bool
}

func NewUser(
	id UserID,
	username Username,
	email Email,
	provider AuthProvider,
	providerID string,
) *User {
	return &User{
		ID:          id,
		Username:    username,
		Email:       email,
		AvatarURL:   nil,
		Provider:    provider,
		ProviderID:  providerID,
		VerifiedAt:  nil,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
		LastLoginAt: nil,
		IsActive:    true,
		Role:        UserRoleDeveloper,
	}
}

func (u *User) SetAvatarURL(avatarURL *string) {
	u.AvatarURL = avatarURL
}

func (u *User) SetVerifiedAt(verifiedAt *time.Time) {
	u.VerifiedAt = verifiedAt
	if verifiedAt != nil {
		u.EmailVerified = true
	}
}

func (u *User) SetPassword(hash PasswordHash) {
	u.PasswordHash = &hash
}

func (u *User) UnsetPassword() {
	u.PasswordHash = nil
}

type UserResponse struct {
	ID            string     `json:"id"`
	Username      string     `json:"username"`
	Email         string     `json:"email"`
	Role          string     `json:"role"`
	Provider      string     `json:"provider"`
	ProviderID    string     `json:"provider_id"`
	AvatarURL     *string    `json:"avatar_url,omitempty"`
	VerifiedAt    *time.Time `json:"verified_at,omitempty"`
	EmailVerified bool       `json:"email_verified"`
	CreatedAt     time.Time  `json:"created_at"`
	LastLoginAt   *time.Time `json:"last_login_at,omitempty"`
}

func (u *User) ToResponse() UserResponse {
	return UserResponse{
		ID:            u.ID.String(),
		Username:      u.Username.String(),
		Email:         u.Email.String(),
		Role:          u.Role.String(),
		Provider:      u.Provider.String(),
		ProviderID:    u.ProviderID,
		AvatarURL:     u.AvatarURL,
		VerifiedAt:    u.VerifiedAt,
		EmailVerified: u.EmailVerified,
		CreatedAt:     u.CreatedAt,
		LastLoginAt:   u.LastLoginAt,
	}
}

type RefreshToken struct {
	ID            string
	UserID        string
	TokenHash     string
	FamilyID      string
	ParentID      *string
	UsedAt        *time.Time
	RevokedAt     *time.Time
	RevokedReason *string
	ExpiresAt     time.Time
	CreatedAt     time.Time
	UserAgent     *string
	IPAddress     *string
}

func NewRefreshToken(
	id string,
	userID string,
	tokenHash string,
	familyID string,
	expiresAt time.Time,
	userAgent *string,
	ipAddress *string,
) RefreshToken {
	now := time.Now().UTC()

	return RefreshToken{
		ID:        id,
		UserID:    userID,
		TokenHash: tokenHash,
		FamilyID:  familyID,
		ParentID:  nil,

		UsedAt:        nil,
		RevokedAt:     nil,
		RevokedReason: nil,

		ExpiresAt: expiresAt,
		CreatedAt: now,

		UserAgent: userAgent,
		IPAddress: ipAddress,
	}
}

func NewRotatedRefreshToken(
	id string,
	userID string,
	tokenHash string,
	familyID string,
	parentID string,
	expiresAt time.Time,
	userAgent *string,
	ipAddress *string,
) RefreshToken {
	now := time.Now().UTC()

	return RefreshToken{
		ID:            id,
		UserID:        userID,
		TokenHash:     tokenHash,
		FamilyID:      familyID,
		ParentID:      &parentID,
		UsedAt:        nil,
		RevokedAt:     nil,
		RevokedReason: nil,
		ExpiresAt:     expiresAt,
		CreatedAt:     now,
		UserAgent:     userAgent,
		IPAddress:     ipAddress,
	}
}

func (t RefreshToken) IsUsed() bool {
	return t.UsedAt != nil
}

func (t RefreshToken) IsRevoked() bool {
	return t.RevokedAt != nil
}

func (t RefreshToken) IsExpired() bool {
	return time.Now().UTC().After(t.ExpiresAt)
}

func (t RefreshToken) IsValid() bool {
	return !t.IsRevoked() &&
		!t.IsExpired() &&
		!t.IsUsed()
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

type UnverifiedToken struct {
	Token string
	Exp   time.Duration
}

// ======================== Filters ========================

type UserFilterBy struct {
	ID       *UserID
	Username *Username
	Email    *Email
	Role     *UserRole
}

func NewUserFilterBy() UserFilterBy {
	return UserFilterBy{}
}

func (f UserFilterBy) WithID(id UserID) UserFilterBy {
	f.ID = &id
	return f
}

func (f UserFilterBy) WithUsername(username Username) UserFilterBy {
	f.Username = &username
	return f
}

func (f UserFilterBy) WithEmail(email Email) UserFilterBy {
	f.Email = &email
	return f
}

func (f UserFilterBy) WithRole(role UserRole) UserFilterBy {
	f.Role = &role
	return f
}

// ======================== Repositories ========================

type UserRepository interface {
	Create(ctx context.Context, user User) (User, error)
	CreateUnverifiedUser(ctx context.Context, user User, token UnverifiedToken) (User, error)
	FindUserBy(ctx context.Context, filter UserFilterBy) (*User, error)
	FindByVerificationToken(ctx context.Context, userID UserID, token string) (*User, error)
	GetByProvider(ctx context.Context, provider AuthProvider, providerID string) (*User, error)
	UpdatePassword(ctx context.Context, email Email, password PasswordHash) error
	UpdateUsername(ctx context.Context, id UserID, username Username) error
	UpdateEmail(ctx context.Context, id UserID, email string) error
	VerifyEmail(ctx context.Context, id UserID) error
	MarkEmailVerified(ctx context.Context, id UserID) error
	UpdateLastLogin(ctx context.Context, id UserID, at time.Time) error

	CreateRefreshToken(ctx context.Context, token *RefreshToken) error
	MarkRefreshTokenUsed(ctx context.Context, tokenID string) error
	RevokeRefreshTokenFamily(ctx context.Context, familyID string, reason string) error
	FindRefreshTokenByHash(ctx context.Context, tokenHash string) (*RefreshToken, error)
}
