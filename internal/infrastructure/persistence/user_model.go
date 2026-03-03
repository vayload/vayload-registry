package persistence

import (
	"database/sql"

	"github.com/vayload/plug-registry/internal/domain"
	"github.com/vayload/plug-registry/internal/shared"
	"github.com/vayload/plug-registry/internal/shared/identity"
	"github.com/vayload/plug-registry/pkg/operator"
)

type UserModel struct {
	ID            identity.ID         `db:"id"`
	Username      string              `db:"username"`
	Email         string              `db:"email"`
	PasswordHash  sql.NullString      `db:"password_hash"`
	VefifyToken   sql.NullString      `db:"verification_token"`
	AvatarURL     sql.NullString      `db:"avatar_url"`
	Provider      string              `db:"provider"`
	ProviderID    string              `db:"provider_id"`
	IsActive      int                 `db:"is_active"`
	Role          string              `db:"role"`
	EmailVerified int                 `db:"email_verified"`
	VerifiedAt    shared.NullUnixTime `db:"verified_at"`
	CreatedAt     shared.UnixTime     `db:"created_at"`
	UpdatedAt     shared.UnixTime     `db:"updated_at"`
	LastLoginAt   shared.NullUnixTime `db:"last_login_at"`
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
		ID:            user.ID.Unwrap(),
		Username:      user.Username.String(),
		Email:         user.Email.String(),
		PasswordHash:  sql.NullString{String: pwdHash, Valid: pwdHashValid},
		AvatarURL:     sql.NullString{String: avatarURL, Valid: avatarURLValid},
		Provider:      user.Provider.String(),
		ProviderID:    user.ProviderID,
		IsActive:      operator.When(user.IsActive, 1, 0),
		Role:          user.Role.String(),
		EmailVerified: operator.When(user.EmailVerified, 1, 0),
		VerifiedAt:    shared.NewNullUnixTime(user.VerifiedAt),
		CreatedAt:     shared.UnixTime(user.CreatedAt),
		UpdatedAt:     shared.UnixTime(user.UpdatedAt),
		LastLoginAt:   shared.NewNullUnixTime(user.LastLoginAt),
	}
}

func (m *UserModel) SetUnverifiedToken(token string) {
	m.VefifyToken = sql.NullString{String: token, Valid: true}
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
		ID:            domain.UserID{ID: m.ID},
		Username:      domain.Username(m.Username),
		Email:         domain.Email(m.Email),
		PasswordHash:  pwdHash,
		AvatarURL:     avatarURL,
		Provider:      domain.AuthProvider(m.Provider),
		ProviderID:    m.ProviderID,
		VerifiedAt:    m.VerifiedAt.Ptr(),
		CreatedAt:     m.CreatedAt.Time(),
		UpdatedAt:     m.UpdatedAt.Time(),
		LastLoginAt:   m.LastLoginAt.Ptr(),
		IsActive:      m.IsActive == 1,
		EmailVerified: m.EmailVerified == 1,
		Role:          domain.UserRole(m.Role), // is safe, because in database store only allowed values
	}
}

type RefreshTokenModel struct {
	ID            string              `db:"id"`
	UserID        string              `db:"user_id"`
	TokenHash     string              `db:"token_hash"`
	FamilyID      string              `db:"family_id"`
	ParentID      sql.NullString      `db:"parent_id"`
	UsedAt        shared.NullUnixTime `db:"used_at"`
	RevokedAt     shared.NullUnixTime `db:"revoked_at"`
	RevokedReason sql.NullString      `db:"revoked_reason"`
	ExpiresAt     shared.UnixTime     `db:"expires_at"`
	CreatedAt     shared.UnixTime     `db:"created_at"`
	UserAgent     sql.NullString      `db:"user_agent"`
	IPAddress     sql.NullString      `db:"ip_address"`
}

func NewRefreshTokenModel(token *domain.RefreshToken) *RefreshTokenModel {
	var parentID sql.NullString
	if token.ParentID != nil {
		parentID = sql.NullString{
			String: *token.ParentID,
			Valid:  true,
		}
	}

	var revokedReason sql.NullString
	if token.RevokedReason != nil {
		revokedReason = sql.NullString{
			String: *token.RevokedReason,
			Valid:  true,
		}
	}

	var userAgent sql.NullString
	if token.UserAgent != nil {
		userAgent = sql.NullString{
			String: *token.UserAgent,
			Valid:  true,
		}
	}

	var ipAddress sql.NullString
	if token.IPAddress != nil {
		ipAddress = sql.NullString{
			String: *token.IPAddress,
			Valid:  true,
		}
	}

	return &RefreshTokenModel{
		ID:            token.ID,
		UserID:        token.UserID,
		TokenHash:     token.TokenHash,
		FamilyID:      token.FamilyID,
		ParentID:      parentID,
		UsedAt:        shared.NewNullUnixTime(token.UsedAt),
		RevokedAt:     shared.NewNullUnixTime(token.RevokedAt),
		RevokedReason: revokedReason,
		ExpiresAt:     shared.UnixTime(token.ExpiresAt),
		CreatedAt:     shared.UnixTime(token.CreatedAt),
		UserAgent:     userAgent,
		IPAddress:     ipAddress,
	}
}

func (m *RefreshTokenModel) MapToDomain() *domain.RefreshToken {
	var parentID *string
	if m.ParentID.Valid {
		parentID = &m.ParentID.String
	}

	var revokedReason *string
	if m.RevokedReason.Valid {
		revokedReason = &m.RevokedReason.String
	}

	var userAgent *string
	if m.UserAgent.Valid {
		userAgent = &m.UserAgent.String
	}

	var ipAddress *string
	if m.IPAddress.Valid {
		ipAddress = &m.IPAddress.String
	}

	return &domain.RefreshToken{
		ID:            m.ID,
		UserID:        m.UserID,
		TokenHash:     m.TokenHash,
		FamilyID:      m.FamilyID,
		ParentID:      parentID,
		UsedAt:        m.UsedAt.Ptr(),
		RevokedAt:     m.RevokedAt.Ptr(),
		RevokedReason: revokedReason,
		ExpiresAt:     m.ExpiresAt.Time(),
		CreatedAt:     m.CreatedAt.Time(),
		UserAgent:     userAgent,
		IPAddress:     ipAddress,
	}
}
