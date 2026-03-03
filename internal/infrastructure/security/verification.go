package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// VerificationTokenManager handles secure token generation and validation.
type VerificationTokenManager struct {
	secret []byte
}

func NewVerificationTokenManager(secret string) *VerificationTokenManager {
	return &VerificationTokenManager{secret: []byte(secret)}
}

// Generate creates a signed token containing the userID and expiration.
func (m *VerificationTokenManager) Generate(userID string, expiresAt time.Time) string {
	payload := fmt.Sprintf("%s:%d", userID, expiresAt.Unix())
	signature := m.sign(payload)
	return base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", payload, signature)))
}

// Validate checks the token signature and expiration, returns userID if valid.
func (m *VerificationTokenManager) Validate(token string) (string, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", fmt.Errorf("invalid token format")
	}

	parts := strings.Split(string(decoded), ":")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid token structure")
	}

	userID := parts[0]
	expiresUnix := parts[1]
	signature := parts[2]

	payload := fmt.Sprintf("%s:%s", userID, expiresUnix)
	if m.sign(payload) != signature {
		return "", fmt.Errorf("invalid signature")
	}

	var exp int64
	fmt.Sscanf(expiresUnix, "%d", &exp)
	if time.Now().UTC().Unix() > exp {
		return "", fmt.Errorf("token expired")
	}

	return userID, nil
}

func (m *VerificationTokenManager) sign(payload string) string {
	h := hmac.New(sha256.New, m.secret)
	h.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
