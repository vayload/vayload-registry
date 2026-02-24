/*
 * SPDX-License-Identifier: MIT
 *
 * Vayload - Container
 *
 * Copyright (c) 2026 Alex Zweiter
 */

package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/scrypt"
)

const (
	SaltByteSize    = 16
	HashKeySize     = 32
	HashIterations  = 32768
	HashBlockSize   = 8
	HashParallelism = 1
)

type Hasher interface {
	Generate(password []byte) ([]byte, error)
	Compare(store, password []byte) (bool, error)
}

type hash struct{}

func NewScryptHasher() Hasher {
	return &hash{}
}

func (h *hash) Generate(password []byte) ([]byte, error) {
	salt, err := GenerateRandomBytes(SaltByteSize)
	if err != nil {
		return nil, err
	}

	key, err := scrypt.Key(password, salt, HashIterations, HashBlockSize, HashParallelism, HashKeySize)
	if err != nil {
		return nil, fmt.Errorf("generating password hash: %w", err)
	}

	b64 := base64.RawURLEncoding

	saltB64 := b64.EncodeToString(salt)
	keyB64 := b64.EncodeToString(key)

	var buf []byte
	buf = strconv.AppendInt(buf, int64(HashIterations), 10)
	buf = append(buf, '$')
	buf = strconv.AppendInt(buf, int64(HashBlockSize), 10)
	buf = append(buf, '$')
	buf = strconv.AppendInt(buf, int64(HashParallelism), 10)
	buf = append(buf, '$')
	buf = append(buf, saltB64...)
	buf = append(buf, '$')
	buf = append(buf, keyB64...)

	return buf, nil
}

func (h *hash) Compare(hash, password []byte) (bool, error) {
	parts := strings.SplitN(string(hash), "$", 5)
	if len(parts) != 5 {
		return false, fmt.Errorf("invalid password hash format: missing or unknown algorithm")
	}

	n, err := strconv.Atoi(parts[0])
	if err != nil {
		return false, fmt.Errorf("invalid iterations: %w", err)
	}

	r, err := strconv.Atoi(parts[2])
	if err != nil {
		return false, fmt.Errorf("invalid block size: %w", err)
	}

	p, err := strconv.Atoi(parts[3])
	if err != nil {
		return false, fmt.Errorf("invalid parallelism: %w", err)
	}

	saltB64, keyB64 := parts[4], parts[5]
	b64 := base64.RawURLEncoding

	salt, err := b64.DecodeString(saltB64)
	if err != nil {
		return false, fmt.Errorf("decoding salt: %w", err)
	}

	key, err := b64.DecodeString(keyB64)
	if err != nil {
		return false, fmt.Errorf("decoding hash: %w", err)
	}

	computedKey, err := scrypt.Key(password, salt, n, r, p, len(key))
	if err != nil {
		return false, fmt.Errorf("generating password hash: %w", err)
	}

	return subtle.ConstantTimeCompare(computedKey, key) == 1, nil
}

// GenerateRandomBytes Generate random bytes for salt
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
