package dtos

import "time"

type UserProfileResponse struct {
	ID          string     `json:"id"`
	Username    string     `json:"username"`
	Email       string     `json:"email"`
	AvatarURL   *string    `json:"avatar_url"`
	Provider    string     `json:"provider"`
	ProviderID  string     `json:"provider_id"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLoginAt *time.Time `json:"last_login_at"`
}

type CreateApiTokenRequest struct {
	Name        string   `json:"name" validate:"required"`
	Description *string  `json:"description"`
	Scope       []string `json:"scope"`
	ExpiresAt   *string  `json:"expires_at"`
	PluginID    *string  `json:"plugin_id"`
}

type ApiTokenResponse struct {
	ID            string                  `json:"id"`
	Name          string                  `json:"name"`
	KeyMask       string                  `json:"key_mask"`
	Scope         []string                `json:"scope"`
	Plugin        *ApiTokenPluginResponse `json:"plugin"`
	Enabled       bool                    `json:"enabled"`
	CreatedAt     time.Time               `json:"created_at"`
	LastUsedAt    *time.Time              `json:"last_used_at"`
	ExpiresAt     *time.Time              `json:"expires_at"`
	RevokedAt     *time.Time              `json:"revoked_at"`
	RevokedReason *string                 `json:"revoked_reason"`
	Key           *string                 `json:"key,omitempty"` // Only present on creation
}

type ApiTokenPluginResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type UpdateProfileDto struct {
	Username  *string `json:"username"`
	AvatarURL *string `json:"avatar_url"`
}
