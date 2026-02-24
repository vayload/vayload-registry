package persistence

import (
	"database/sql"
	"time"

	"github.com/vayload/plug-registry/internal/domain"
	"github.com/vayload/plug-registry/internal/shared/entity"
	"github.com/vayload/plug-registry/pkg/operator"
)

type UserModel struct {
	ID           entity.ID      `db:"id"`
	Username     string         `db:"username"`
	Email        string         `db:"email"`
	PasswordHash sql.NullString `db:"password_hash"`
	AvatarURL    sql.NullString `db:"avatar_url"`
	Provider     string         `db:"provider"`
	ProviderID   string         `db:"provider_id"`
	IsActive     int            `db:"is_active"`
	Role         string         `db:"role"`
	VerifiedAt   *time.Time     `db:"verified_at"`
	CreatedAt    time.Time      `db:"created_at"`
	UpdatedAt    time.Time      `db:"updated_at"`
	LastLoginAt  *time.Time     `db:"last_login_at"`
}

func NewUserModel(user *domain.User) *UserModel {
	var pwdHash string
	var pwdHashValid bool
	if user.PasswordHash != nil {
		pwdHash = user.PasswordHash.String()
		pwdHashValid = true
	}

	var avatarURL string
	var avatarURLValid bool
	if user.AvatarURL != nil {
		avatarURL = *user.AvatarURL
		avatarURLValid = true
	}

	return &UserModel{
		ID:           user.ID.Unwrap(),
		Username:     user.Username.String(),
		Email:        user.Email.String(),
		PasswordHash: sql.NullString{String: pwdHash, Valid: pwdHashValid},
		AvatarURL:    sql.NullString{String: avatarURL, Valid: avatarURLValid},
		Provider:     user.Provider.String(),
		ProviderID:   user.ProviderID,
		IsActive:     operator.When(user.IsActive, 1, 0),
		Role:         user.Role.String(),
		VerifiedAt:   user.VerifiedAt,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
		LastLoginAt:  user.LastLoginAt,
	}
}

func (m *UserModel) MapToDomain() *domain.User {
	var pwdHash *domain.PasswordHash
	if m.PasswordHash.Valid {
		h := domain.PasswordHash(m.PasswordHash.String)
		pwdHash = &h
	}
	var avatarURL *string
	if m.AvatarURL.Valid {
		avatarURL = &m.AvatarURL.String
	}

	return &domain.User{
		ID:           domain.UserID{ID: m.ID},
		Username:     domain.Username(m.Username),
		Email:        domain.Email(m.Email),
		PasswordHash: pwdHash,
		AvatarURL:    avatarURL,
		Provider:     domain.AuthProvider(m.Provider),
		ProviderID:   m.ProviderID,
		VerifiedAt:   m.VerifiedAt,
		CreatedAt:    m.CreatedAt,
		UpdatedAt:    m.UpdatedAt,
		LastLoginAt:  m.LastLoginAt,
		IsActive:     m.IsActive == 1,
		Role:         domain.UserRole(m.Role), // is safe, because in database store only allowed values
	}
}

type RefreshTokenModel struct {
	ID            string         `db:"id"`
	UserID        string         `db:"user_id"`
	TokenHash     string         `db:"token_hash"`
	ExpiresAt     *time.Time     `db:"expires_at"`
	CreatedAt     time.Time      `db:"created_at"`
	RevokedAt     *time.Time     `db:"revoked_at"`
	RevokedReason sql.NullString `db:"revoked_reason"`
}

func NewRefreshTokenModel(token *domain.RefreshToken) *RefreshTokenModel {
	var reason string
	var reasonValid bool
	if token.RevokedReason != nil {
		reason = *token.RevokedReason
		reasonValid = true
	}

	return &RefreshTokenModel{
		ID:            token.ID,
		UserID:        token.UserID,
		TokenHash:     token.TokenHash,
		ExpiresAt:     token.ExpiresAt,
		CreatedAt:     token.CreatedAt,
		RevokedAt:     token.RevokedAt,
		RevokedReason: sql.NullString{String: reason, Valid: reasonValid},
	}
}

func (m *RefreshTokenModel) MapToDomain() *domain.RefreshToken {
	var reason *string
	if m.RevokedReason.Valid {
		reason = &m.RevokedReason.String
	}
	return &domain.RefreshToken{
		ID:            m.ID,
		UserID:        m.UserID,
		TokenHash:     m.TokenHash,
		ExpiresAt:     m.ExpiresAt,
		CreatedAt:     m.CreatedAt,
		RevokedAt:     m.RevokedAt,
		RevokedReason: reason,
	}
}
