package domain

import (
	"context"
	"fmt"
	"strings"
	"time"
)

const ApiTokenPrefix = "vpr_"

// ======================== Value Objects ========================

type ApiTokenId string

func (id ApiTokenId) String() string {
	return string(id)
}

type KeyHash string

func (h KeyHash) String() string {
	return string(h)
}

type KeyName string

func NewKeyName(name string) (KeyName, error) {
	if name == "" {
		return "", NewValidationError("Key name cannot be empty")
	}
	return KeyName(name), nil
}

func (n KeyName) String() string {
	return string(n)
}

type KeyScope struct {
	Type     string // "global" or "plugin"
	PluginID string
}

func (s KeyScope) String() string {
	if s.Type == "global" {
		return "global"
	}
	return fmt.Sprintf("plugin:%s", s.PluginID)
}

func ParseKeyScope(s string) (KeyScope, error) {
	if s == "global" {
		return KeyScope{Type: "global"}, nil
	}
	if strings.HasPrefix(s, "plugin:") {
		pluginID := s[7:]
		if pluginID == "" {
			return KeyScope{}, NewValidationError("Plugin ID cannot be empty")
		}
		return KeyScope{Type: "plugin", PluginID: pluginID}, nil
	}
	return KeyScope{}, NewValidationError("Invalid key scope")
}

// ======================== Entities ========================

type ApiToken struct {
	ID            ApiTokenId
	UserID        string
	KeyHash       KeyHash
	KeyRaw        string
	KeyMask       string
	Name          KeyName
	Scope         KeyScope
	PluginID      *string
	Description   string
	CreatedAt     time.Time
	LastUsed      *time.Time
	ExpiresAt     *time.Time
	RevokedAt     *time.Time
	RevokedReason *string
}

func NewApiToken(
	id ApiTokenId,
	userID string,
	keyHash KeyHash,
	keyRaw string,
	keyMask string,
	name KeyName,
	scope KeyScope,
) ApiToken {
	return ApiToken{
		ID:          id,
		UserID:      userID,
		KeyHash:     keyHash,
		KeyRaw:      keyRaw,
		KeyMask:     keyMask,
		Name:        name,
		Scope:       scope,
		Description: "",
		CreatedAt:   time.Now().UTC(),
	}
}

func (t *ApiToken) IsRevoked() bool {
	return t.RevokedAt != nil
}

func (t *ApiToken) IsExpired() bool {
	if t.ExpiresAt == nil {
		return false
	}
	return t.ExpiresAt.Before(time.Now().UTC())
}

// ======================== Repository ========================

type ApiTokenRepository interface {
	Create(ctx context.Context, apiToken ApiToken) (ApiToken, error)
	GetByID(ctx context.Context, id ApiTokenId) (*ApiToken, error)
	GetByHash(ctx context.Context, hash string) (*ApiToken, error)
	ListByUser(ctx context.Context, userID string) ([]ApiToken, error)
	Revoke(ctx context.Context, id ApiTokenId) error
	Delete(ctx context.Context, id ApiTokenId) error
	UpdateLastUsed(ctx context.Context, id ApiTokenId) error
}
