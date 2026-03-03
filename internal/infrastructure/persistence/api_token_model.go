package persistence

import (
	"database/sql"
	"time"

	"github.com/vayload/plug-registry/internal/domain"
	"github.com/vayload/plug-registry/internal/shared"
)

type apiTokenModel struct {
	ID            string              `db:"id"`
	UserID        string              `db:"user_id"`
	KeyHash       string              `db:"key_hash"`
	PluginID      sql.NullString      `db:"plugin_id"`
	KeyMask       string              `db:"key_mask"`
	Name          string              `db:"name"`
	Scope         string              `db:"scope"`
	Description   string              `db:"description"`
	Enabled       int                 `db:"enabled"`
	CreatedAt     shared.UnixTime     `db:"created_at"`
	LastUsed      shared.NullUnixTime `db:"last_used_at"`
	ExpiresAt     shared.NullUnixTime `db:"expires_at"`
	RevokedAt     shared.NullUnixTime `db:"revoked_at"`
	RevokedReason sql.NullString      `db:"revoked_reason"`
}

func NewApiTokenModel(token *domain.ApiToken) *apiTokenModel {
	return &apiTokenModel{
		ID:        token.ID.String(),
		UserID:    token.UserID,
		KeyHash:   token.KeyHash.String(),
		Name:      token.Name.String(),
		Scope:     token.Scope.String(),
		CreatedAt: shared.UnixTime(token.CreatedAt),
		ExpiresAt: toNullTime(token.ExpiresAt),
		LastUsed:  toNullTime(token.LastUsed),
		RevokedAt: toNullTime(token.RevokedAt),
	}
}

func (m *apiTokenModel) MapToDomain() *domain.ApiToken {
	scope, err := domain.ParseKeyScope(m.Scope, nullStringPtr(m.PluginID))
	if err != nil {
		// !TODO: Check this, security risk
		scope = &domain.KeyScope{
			Prefix: "global",
		}
	}

	return &domain.ApiToken{
		ID:        domain.ApiTokenId(m.ID),
		UserID:    m.UserID,
		KeyHash:   domain.KeyHash(m.KeyHash),
		Name:      domain.KeyName(m.Name),
		Scope:     *scope,
		CreatedAt: m.CreatedAt.Time(),
		LastUsed:  fromNullTime(m.LastUsed),
		ExpiresAt: fromNullTime(m.ExpiresAt),
		RevokedAt: fromNullTime(m.RevokedAt),
	}
}

func toNullTime(t *time.Time) shared.NullUnixTime {
	if t == nil {
		return shared.NullUnixTime{}
	}
	return shared.NullUnixTime{
		Time:  *t,
		Valid: true,
	}
}

func fromNullTime(nt shared.NullUnixTime) *time.Time {
	if !nt.Valid {
		return nil
	}
	return &nt.Time
}
