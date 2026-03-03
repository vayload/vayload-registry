package domain

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/vayload/plug-registry/internal/shared/errors"
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
		return "", errors.Validation("Key name cannot be empty")
	}
	return KeyName(name), nil
}

func (n KeyName) String() string {
	return string(n)
}

type ScopePermission string

const (
	ScopeReadWrite ScopePermission = "read-write"
	ScopeReadOnly  ScopePermission = "read-only"
)

type KeyScope struct {
	Prefix     string          // "global" o "plugin"
	PluginID   *string         // only if Prefix == "plugin"
	Permission ScopePermission // read-write / read-only
}

func (s *KeyScope) String() string {
	return s.Prefix + ":" + string(s.Permission)
}

func ParseKeyScope(raw string, pluginID *string) (*KeyScope, error) {
	parts := strings.Split(raw, ":")
	if len(parts) < 2 {
		return nil, errors.Validation(fmt.Sprintf("invalid scope: %s", raw))
	}

	prefix := parts[0]
	perm := ScopePermission(parts[len(parts)-1])

	if perm != ScopeReadWrite && perm != ScopeReadOnly {
		return nil, errors.Validation(fmt.Sprintf("invalid permission: %s", perm))
	}

	switch prefix {
	case "global":
		return &KeyScope{
			Prefix:     "global",
			Permission: perm,
		}, nil
	case "plugin":
		if pluginID == nil {
			return nil, errors.Validation("pluginID must be provided for plugin scope")
		}
		return &KeyScope{
			Prefix:     "plugin",
			PluginID:   pluginID,
			Permission: perm,
		}, nil
	default:
		return nil, errors.Validation(fmt.Sprintf("invalid scope prefix: %s", prefix))
	}
}

func (s *KeyScope) HasScope(requiredPermission ScopePermission, pluginID *string) bool {
	if s.Prefix == "plugin" {
		// Reject when pluginId not matches
		if s.PluginID == nil || pluginID == nil || *s.PluginID != *pluginID {
			return false
		}
	}

	// When permission is read-write return always true
	if s.Permission == ScopeReadWrite {
		return true
	}

	return s.Permission == requiredPermission
}

func (s *KeyScope) MarshalJSON() ([]byte, error) {
	return []byte(s.String()), nil
}

func (s *KeyScope) UnmarshalJSON(b []byte) error {
	scope := string(b)
	parsed, err := ParseKeyScope(scope, nil)
	if err != nil {
		return err
	}

	*s = *parsed
	return nil
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
