package ids

import (
	"crypto/rand"
	mathrand "math/rand"
	"time"
)

const (
	alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	idLength = 32
)

const NANOID_LENGTH = 32

func GenerateNanoID(length ...int) string {
	nanoidLength := NANOID_LENGTH
	if len(length) > 0 {
		nanoidLength = length[0]
	}

	bytes := make([]byte, nanoidLength)
	_, err := rand.Read(bytes)
	if err != nil {
		seed := time.Now().UnixNano()
		localRand := mathrand.New(mathrand.NewSource(seed))
		for i := range bytes {
			bytes[i] = alphabet[localRand.Intn(len(alphabet))]
		}
	} else {
		for i := range idLength {
			bytes[i] = alphabet[bytes[i]%byte(len(alphabet))]
		}
	}

	return string(bytes)
}
