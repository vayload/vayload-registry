package security

import (
	"crypto/ed25519"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/vayload/plug-registry/internal/domain"
)

type jwtManager struct {
	privateKey      ed25519.PrivateKey
	publicKey       ed25519.PublicKey
	accessTokenDur  time.Duration
	refreshTokenDur time.Duration
	audience        string
}

func NewJwtManager(privateKeyRaw, publicKeyRaw []byte, accessTokenDur, refreshTokenDur time.Duration) (domain.TokenManager, error) {
	// Parse Private Key (expect PKCS#8)
	privKey, err := x509.ParsePKCS8PrivateKey(privateKeyRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	edPriv, ok := privKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not ed25519")
	}

	// Parse Public Key (expect PKIX)
	pubKey, err := x509.ParsePKIXPublicKey(publicKeyRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	edPub, ok := pubKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not ed25519")
	}

	return &jwtManager{
		privateKey:      edPriv,
		publicKey:       edPub,
		accessTokenDur:  accessTokenDur,
		refreshTokenDur: refreshTokenDur,
		audience:        "vayload_registry",
	}, nil
}

type UserClaims struct {
	jwt.RegisteredClaims
	UserID string `json:"user_id"`
	Role   string `json:"role"`
	Email  string `json:"email"`
}

func (m *jwtManager) Sign(payload domain.TokenPayload) (domain.AuthToken, error) {
	now := time.Now().UTC()
	exp := now.Add(m.accessTokenDur)

	accessClaims := UserClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(now),
			Audience:  []string{m.audience},
			Subject:   payload.UserID,
		},
		UserID: payload.UserID,
		Role:   payload.Role,
		Email:  payload.Email,
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodEdDSA, accessClaims)
	accessTokenStr, err := accessToken.SignedString(m.privateKey)
	if err != nil {
		return domain.AuthToken{}, err
	}

	// Refresh Token (Opaque and Hashed via utility)
	opaque := GenerateOpaqueToken()

	return domain.AuthToken{
		AccessToken:           accessTokenStr,
		RefreshToken:          opaque.Raw,
		RefreshTokenHash:      opaque.Hashed,
		RefreshTokenExpiresIn: uint64(m.refreshTokenDur.Seconds()),
		ExpiresAt:             exp,
		ExpiresIn:             uint64(m.accessTokenDur.Seconds()),
	}, nil
}

func (m *jwtManager) Parse(tokenStr string) (domain.Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &UserClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.publicKey, nil
	})

	if err != nil {
		return domain.Claims{}, err
	}

	claims, ok := token.Claims.(*UserClaims)
	if !ok || !token.Valid {
		return domain.Claims{}, fmt.Errorf("invalid token")
	}

	aud := ""
	if len(claims.Audience) > 0 {
		aud = claims.Audience[0]
	}

	return domain.Claims{
		Aud:   aud,
		Sub:   claims.UserID,
		Exp:   uint64(claims.ExpiresAt.Unix()),
		Iat:   uint64(claims.IssuedAt.Unix()),
		Email: claims.Email,
		Role:  claims.Role,
	}, nil
}
