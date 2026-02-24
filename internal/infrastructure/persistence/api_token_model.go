package persistence

import (
	"time"

	"github.com/vayload/plug-registry/internal/domain"
)

type apiTokenModel struct {
	ID        string     `db:"id"`
	UserID    string     `db:"user_id"`
	KeyHash   string     `db:"key_hash"`
	KeyName   string     `db:"key_name"`
	KeyScope  string     `db:"key_scope"`
	CreatedAt time.Time  `db:"created_at"`
	ExpiresAt *time.Time `db:"expires_at"`
	LastUsed  *time.Time `db:"last_used_at"`
	RevokedAt *time.Time `db:"revoked_at"`
}

func NewApiTokenModel(token *domain.ApiToken) *apiTokenModel {
	return &apiTokenModel{
		ID:        token.ID.String(),
		UserID:    token.UserID,
		KeyHash:   token.KeyHash.String(),
		KeyName:   token.Name.String(),
		KeyScope:  token.Scope.String(),
		CreatedAt: token.CreatedAt,
		ExpiresAt: token.ExpiresAt,
		LastUsed:  token.LastUsed,
		RevokedAt: token.RevokedAt,
	}
}

func (m *apiTokenModel) MapToDomain() *domain.ApiToken {
	scope, _ := domain.ParseKeyScope(m.KeyScope)

	return &domain.ApiToken{
		ID:        domain.ApiTokenId(m.ID),
		UserID:    m.UserID,
		KeyHash:   domain.KeyHash(m.KeyHash),
		Name:      domain.KeyName(m.KeyName),
		Scope:     scope,
		CreatedAt: m.CreatedAt,
		LastUsed:  m.LastUsed,
		ExpiresAt: m.ExpiresAt,
		RevokedAt: m.RevokedAt,
	}
}
