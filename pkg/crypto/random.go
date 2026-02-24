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
	mathrand "math/rand"
	"time"

	"github.com/google/uuid"
)

func GenerateUUID() string {
	return uuid.New().String()
}

const (
	alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	idLength = 32
)

const NANOID_LENGTH = 32

func GenerateNanoID() string {
	bytes := make([]byte, NANOID_LENGTH)
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
