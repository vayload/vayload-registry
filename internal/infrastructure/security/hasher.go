/*
 * SPDX-License-Identifier: MIT
 *
 * Vayload - Container
 *
 * Copyright (c) 2026 Alex Zweiter
 */

package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/vayload/plug-registry/internal/domain"
	"golang.org/x/crypto/scrypt"
)

const (
	SaltByteSize    = 16
	HashKeySize     = 32
	HashIterations  = 32768
	HashBlockSize   = 8
	HashParallelism = 1
)

type scryptHasher struct{}

func NewScryptHasher() domain.HashingStrategy {
	return &scryptHasher{}
}

func (h *scryptHasher) Hash(password string) (string, error) {
	salt, err := GenerateRandomBytes(SaltByteSize)
	if err != nil {
		return "", err
	}

	key, err := scrypt.Key([]byte(password), salt, HashIterations, HashBlockSize, HashParallelism, HashKeySize)
	if err != nil {
		return "", fmt.Errorf("generating password hash: %w", err)
	}

	b64 := base64.RawURLEncoding

	saltB64 := b64.EncodeToString(salt)
	keyB64 := b64.EncodeToString(key)

	var buf strings.Builder
	buf.WriteString(strconv.Itoa(HashIterations))
	buf.WriteByte('$')
	buf.WriteString(strconv.Itoa(HashBlockSize))
	buf.WriteByte('$')
	buf.WriteString(strconv.Itoa(HashParallelism))
	buf.WriteByte('$')
	buf.WriteString(saltB64)
	buf.WriteByte('$')
	buf.WriteString(keyB64)

	return buf.String(), nil
}

func (h *scryptHasher) Verify(password, hash string) bool {
	parts := strings.SplitN(hash, "$", 5)
	if len(parts) != 5 {
		return false
	}

	n, err := strconv.Atoi(parts[0])
	if err != nil {
		return false
	}

	r, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}

	p, err := strconv.Atoi(parts[2])
	if err != nil {
		return false
	}

	saltB64, keyB64 := parts[3], parts[4]
	b64 := base64.RawURLEncoding

	salt, err := b64.DecodeString(saltB64)
	if err != nil {
		return false
	}

	key, err := b64.DecodeString(keyB64)
	if err != nil {
		return false
	}

	computedKey, err := scrypt.Key([]byte(password), salt, n, r, p, len(key))
	if err != nil {
		return false
	}

	return subtle.ConstantTimeCompare(computedKey, key) == 1
}

func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
