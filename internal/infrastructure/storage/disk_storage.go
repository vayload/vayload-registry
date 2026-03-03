//go:build !r2_storage
// +build !r2_storage

package storage

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/vayload/plug-registry/internal/domain"
)

type LocalStorage struct {
	BasePath string
	Secret   []byte
	BaseURL  string
}

// NewStorage creates a new instance of LocalStorage.
func NewStorage(cfg StorageConfig) (*LocalStorage, error) {
	return &LocalStorage{
		BasePath: fmt.Sprintf("%s/%s", cfg.BaseLocalPath, cfg.BucketName),
		Secret:   cfg.LocalHMACSecret,
		BaseURL:  cfg.LocalEndpoint,
	}, nil
}

func (l *LocalStorage) Put(ctx context.Context, key string, mimeType string, r io.Reader) error {
	path := filepath.Join(l.BasePath, key)
	os.MkdirAll(filepath.Dir(path), 0755)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, r)
	return err
}

func (l *LocalStorage) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	path := filepath.Join(l.BasePath, key)
	return os.Open(path)
}

func (l *LocalStorage) Delete(ctx context.Context, key string) error {
	path := filepath.Join(l.BasePath, key)
	return os.Remove(path)
}

func (l *LocalStorage) GetSignedURL(ctx context.Context, key string) (string, error) {
	exp := time.Now().Add(15 * time.Minute).Unix()
	msg := fmt.Sprintf("%s:%d", key, exp)
	mac := hmac.New(sha256.New, l.Secret)
	mac.Write([]byte(msg))
	sig := base64.URLEncoding.EncodeToString(mac.Sum(nil))

	u := fmt.Sprintf("%s%s?exp=%d&sig=%s", l.BaseURL, url.PathEscape(key), exp, url.QueryEscape(sig))
	return u, nil
}

var _ domain.IPluginStorage = (*LocalStorage)(nil)
