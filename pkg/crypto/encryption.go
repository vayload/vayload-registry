/*
 * SPDX-License-Identifier: MIT
 *
 * Vayload - Container
 *
 * Copyright (c) 2026 Alex Zweiter
 */

package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"os"
)

type encryption struct {
	Key []byte
}

type fileEncryption struct {
	Key []byte
}

type Encryption interface {
	Encrypt(plainText string, useURL bool) (string, error)
	Decrypt(data string, useURL bool) (string, error)
}

type FileEncryption interface {
	EncryptBytes(plainText []byte) ([]byte, error)
	DecryptBytes(data []byte) ([]byte, error)

	// Encrypt file at the given path and save it with a .enc extension
	EncryptFile(filePath string, destPath string) error
	DecryptFile(filePath string, destPath string) error
}

func NewEncryption(secret string) *encryption {
	hash := sha256.Sum256([]byte(secret))
	return &encryption{
		Key: hash[:16], // AES-128 requires 16 bytes
	}
}

func (ac *encryption) Encrypt(plainText string, useURL bool) (string, error) {
	block, err := aes.NewCipher(ac.Key)
	if err != nil {
		return "", err
	}

	plainBytes := pkcs7Pad([]byte(plainText), aes.BlockSize)

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	cipherText := make([]byte, len(plainBytes))
	mode.CryptBlocks(cipherText, plainBytes)

	final := append(iv, cipherText...)

	if useURL {
		return base64.RawURLEncoding.EncodeToString(final), nil
	}
	return base64.StdEncoding.EncodeToString(final), nil
}

func (ac *encryption) Decrypt(data string, useURL bool) (string, error) {
	var raw []byte
	var err error

	if useURL {
		raw, err = base64.RawURLEncoding.DecodeString(data)
	} else {
		raw, err = base64.StdEncoding.DecodeString(data)
	}
	if err != nil {
		return "", err
	}

	if len(raw) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}

	iv := raw[:aes.BlockSize]
	cipherText := raw[aes.BlockSize:]

	block, err := aes.NewCipher(ac.Key)
	if err != nil {
		return "", err
	}

	if len(cipherText)%aes.BlockSize != 0 {
		return "", errors.New("ciphertext is not a multiple of block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plainPadded := make([]byte, len(cipherText))
	mode.CryptBlocks(plainPadded, cipherText)

	plain, err := pkcs7Unpad(plainPadded, aes.BlockSize)
	if err != nil {
		return "", err
	}

	return string(plain), nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - len(data)%blockSize
	pad := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, pad...)
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("invalid padding size")
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > blockSize {
		return nil, errors.New("invalid padding")
	}
	for _, b := range data[len(data)-padLen:] {
		if int(b) != padLen {
			return nil, errors.New("invalid padding content")
		}
	}
	return data[:len(data)-padLen], nil
}

func NewFileEncryption(secret string) *fileEncryption {
	hash := sha256.Sum256([]byte(secret))
	return &fileEncryption{
		Key: hash[:16], // AES-128 requires 16 bytes
	}
}

func (fe *fileEncryption) EncryptBytes(plainText []byte) ([]byte, error) {
	block, err := aes.NewCipher(fe.Key)
	if err != nil {
		return nil, err
	}

	plainBytes := pkcs7Pad(plainText, aes.BlockSize)

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	cipherText := make([]byte, len(plainBytes))
	mode.CryptBlocks(cipherText, plainBytes)

	final := append(iv, cipherText...)
	return final, nil
}

func (fe *fileEncryption) DecryptBytes(data []byte) ([]byte, error) {
	if len(data) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := data[:aes.BlockSize]
	cipherText := data[aes.BlockSize:]

	block, err := aes.NewCipher(fe.Key)
	if err != nil {
		return nil, err
	}

	if len(cipherText)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plainPadded := make([]byte, len(cipherText))
	mode.CryptBlocks(plainPadded, cipherText)

	plain, err := pkcs7Unpad(plainPadded, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	return plain, nil
}

func (fe *fileEncryption) EncryptFile(filePath string) error {
	fileBytes, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	encryptedBytes, err := fe.EncryptBytes(fileBytes)
	if err != nil {
		return err
	}

	err = os.WriteFile(filePath+".enc", encryptedBytes, 0600)
	if err != nil {
		return err
	}

	return nil
}

func (fe *fileEncryption) DecryptFile(filePath string) error {
	encryptedBytes, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	decryptedBytes, err := fe.DecryptBytes(encryptedBytes)
	if err != nil {
		return err
	}

	err = os.WriteFile(filePath+".dec", decryptedBytes, 0600)
	if err != nil {
		return err
	}

	return nil
}
