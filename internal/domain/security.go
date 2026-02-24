package domain

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
)

type HashingStrategy interface {
	Hash(password string) (string, error)
	Verify(password, hash string) bool
}

type OpaqueToken struct {
	Raw    string
	Hashed string
}

type ClientType string

const (
	ClientTypeWeb ClientType = "web"
	ClientTypeCli ClientType = "cli"
)

func ParseClientType(s string) (ClientType, error) {
	switch strings.ToLower(s) {
	case "web", "":
		return ClientTypeWeb, nil
	case "cli":
		return ClientTypeCli, nil
	default:
		return ClientTypeWeb, NewValidationError("Invalid client type")
	}
}

type OAuthState struct {
	State         string
	OriginURI     string
	RedirectURI   *string
	CodeChallenge string
	ClientType    ClientType
}

func (s OAuthState) ToBase64() string {
	redirectURI := ""
	if s.RedirectURI != nil {
		redirectURI = *s.RedirectURI
	}
	raw := fmt.Sprintf("%s|%s|%s|%s|%s",
		s.State,
		s.OriginURI,
		redirectURI,
		s.CodeChallenge,
		string(s.ClientType),
	)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func ParseOAuthState(s string) (OAuthState, error) {
	bytes, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return OAuthState{}, NewValidationError(fmt.Sprintf("Invalid base64: %v", err))
	}

	parts := strings.Split(string(bytes), "|")
	if len(parts) != 5 {
		return OAuthState{}, NewValidationError("Invalid state format")
	}

	clientType, _ := ParseClientType(parts[4])

	var redirectURI *string
	if parts[2] != "" {
		redirectURI = &parts[2]
	}

	return OAuthState{
		State:         parts[0],
		OriginURI:     parts[1],
		RedirectURI:   redirectURI,
		CodeChallenge: parts[3],
		ClientType:    clientType,
	}, nil
}

type OAuthUser struct {
	SID           string
	Email         string
	EmailVerified bool
	Name          string
	FirstName     string
	LastName      string
	AvatarURL     string
}

type OAuthProvider string

const (
	OAuthProviderGoogle OAuthProvider = "google"
	OAuthProviderGitHub OAuthProvider = "github"
)

func ParseOAuthProvider(s string) (OAuthProvider, error) {
	switch strings.ToLower(s) {
	case "google":
		return OAuthProviderGoogle, nil
	case "github":
		return OAuthProviderGitHub, nil
	default:
		return "", NewConflictError("Invalid OAuth provider")
	}
}

type OAuthStrategy interface {
	GetAuthenticationURI(provider OAuthProvider, state OAuthState) (string, error)
	ExchangeCode(provider OAuthProvider, clientType ClientType, code string) (OAuthUser, error)
}

type Claims struct {
	Aud string
	Sub string
	Exp uint64
	Iat uint64

	// Custom claims
	Email string
	Role  string
}

type TokenPayload struct {
	UserID string
	Email  string
	Role   string
}

type TokenManager interface {
	Sign(payload TokenPayload) (AuthToken, error)
	Parse(token string) (Claims, error)
}

type ApiTokenVerifier interface {
	VerifyApiToken(ctx context.Context, rawToken string) (*ApiToken, error)
}
