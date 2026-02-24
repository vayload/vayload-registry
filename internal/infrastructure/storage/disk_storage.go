package storage

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/vayload/plug-registry/internal/domain"
)

type diskStorage struct {
	basePath string
	baseURL  string // URL of the API to serve local files
}

func NewDiskStorage(basePath, baseURL string) domain.StorageProvider {
	return &diskStorage{
		basePath: basePath,
		baseURL:  baseURL,
	}
}

func (s *diskStorage) GetSignedURL(ctx context.Context, key string) (string, error) {
	// For local storage, we return a URL pointing to our internal storage handler
	// In a real app, we might add a temporal JWT token as a query parameter
	return fmt.Sprintf("%s/storage/get/%s", s.baseURL, key), nil
}

func (s *diskStorage) Upload(ctx context.Context, name, version string, data io.Reader) (string, int64, string, error) {
	filename := fmt.Sprintf("%s-%s.tar.gz", name, version)
	path := filepath.Join(s.basePath, filename)

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return "", 0, "", err
	}

	out, err := os.Create(path)
	if err != nil {
		return "", 0, "", err
	}
	defer out.Close()

	hasher := sha256.New()
	multi := io.MultiWriter(out, hasher)

	written, err := io.Copy(multi, data)
	if err != nil {
		return "", 0, "", err
	}

	sha256Hex := fmt.Sprintf("%x", hasher.Sum(nil))

	return filename, written, sha256Hex, nil
}

func (s *diskStorage) Fetch(ctx context.Context, name, version string) (io.ReadCloser, error) {
	filename := fmt.Sprintf("%s-%s.tar.gz", name, version)
	path := filepath.Join(s.basePath, filename)
	return os.Open(path)
}
