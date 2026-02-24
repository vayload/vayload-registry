package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/vayload/plug-registry/internal/domain"
)

func GenerateOpaqueToken() domain.OpaqueToken {
	bytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		panic(err) // entropy failure is fatal
	}

	raw := base64.RawURLEncoding.EncodeToString(bytes)

	hasher := sha256.New()
	hasher.Write(bytes)
	hashed := fmt.Sprintf("%x", hasher.Sum(nil))

	return domain.OpaqueToken{
		Raw:    raw,
		Hashed: hashed,
	}
}

type OpaqueApiToken struct {
	Raw    string
	Hashed string
	Mask   string
}

func GenerateOpaqueApiToken(prefix string) OpaqueApiToken {
	bytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		panic(err)
	}

	randomPart := base64.RawURLEncoding.EncodeToString(bytes)
	raw := fmt.Sprintf("%s_%s", prefix, randomPart)

	hasher := sha256.New()
	hasher.Write([]byte(raw))
	hashed := fmt.Sprintf("%x", hasher.Sum(nil))

	// Mask: prefix_ + first 4 chars + ... + last 4 chars
	mask := fmt.Sprintf("%s_%s...%s", prefix, randomPart[:4], randomPart[len(randomPart)-4:])

	return OpaqueApiToken{
		Raw:    raw,
		Hashed: hashed,
		Mask:   mask,
	}
}

func OpaqueApiTokenFrom(raw string) (OpaqueApiToken, error) {
	parts := strings.Split(raw, "_")
	if len(parts) != 2 {
		return OpaqueApiToken{}, errors.New("invalid opaque API token format")
	}
	prefix := parts[0]
	randomPart := parts[1]
	hasher := sha256.New()
	hasher.Write([]byte(raw))
	hashed := fmt.Sprintf("%x", hasher.Sum(nil))
	mask := fmt.Sprintf("%s_%s...%s", prefix, randomPart[:4], randomPart[len(randomPart)-4:])

	return OpaqueApiToken{
		Raw:    raw,
		Hashed: hashed,
		Mask:   mask,
	}, nil
}
