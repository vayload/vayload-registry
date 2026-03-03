package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/pelletier/go-toml/v2"
)

type Config struct {
	Server   ServerConfig   `toml:"server"`
	Security SecurityConfig `toml:"security"`
	Database DatabaseConfig `toml:"database"`
	OAuth    OAuthConfig    `toml:"oauth"`
	Storage  StorageConfig  `toml:"storage"`
	Email    EmailConfig    `toml:"email"`

	WorkDir string `toml:"-"`
	DataDir string `toml:"-"`
}

type ServerConfig struct {
	Host           string   `toml:"host"`
	Port           int      `toml:"port"`
	CookieDomain   string   `toml:"cookie_domain"`
	AllowOrigins   []string `toml:"origins"`
	TrustedProxies []string `toml:"trusted_proxies"`
	LogLevel       string   `toml:"log_level"`
}

type SecurityConfig struct {
	JwtPublicKeyBase64       string `toml:"jwt_public_key"`
	JwtPrivateKeyBase64      string `toml:"jwt_private_key"`
	JwtExpirationTime        int    `toml:"jwt_expiration_time"`
	JwtRefreshExpirationDays int    `toml:"jwt_refresh_expiration_days"`

	JwtPublicKey  []byte `toml:"-"`
	JwtPrivateKey []byte `toml:"-"`
}

type DatabaseConfig struct {
	URL   string `toml:"url"`
	Token string `toml:"token"`
}

type OAuthConfig struct {
	GithubWeb OauthProviderConfig `toml:"github_web"`
	GithubCli OauthProviderConfig `toml:"github_cli"`
	GoogleWeb OauthProviderConfig `toml:"google_web"`
	GoogleCli OauthProviderConfig `toml:"google_cli"`
}

type OauthProviderConfig struct {
	ClientID     string `toml:"client_id"`
	ClientSecret string `toml:"client_secret"`
	RedirectURL  string `toml:"redirect_url"`
}

type StorageConfig struct {
	BucketName     string `toml:"bucket_name"`
	LocalDir       string `toml:"local_dir"`
	LocalEndpoint  string `toml:"local_endpoint"`
	LocalSecret    string `toml:"local_secret"`
	LocalSecretKey []byte `toml:"-"`

	// Credentials for R2 storage
	R2Endpoint  string `toml:"r2_endpoint"`
	R2AccessKey string `toml:"r2_access_key"`
	R2SecretKey string `toml:"r2_secret_key"`
}

type EmailConfig struct {
	ResendAPIKey string `toml:"api_key"`
	FromEmail    string `toml:"email_from"`
	AppBaseURL   string `toml:"app_base_url"`
}

type CacheConfig struct {
	Addr      string `toml:"addr"`
	Password  string `toml:"password"`
	DB        int    `toml:"db"`
	Namespace string `toml:"namespace"`
}

func LoadConfig(path string) (*Config, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := toml.Unmarshal(file, &cfg); err != nil {
		return nil, err
	}

	if cfg.Security.JwtPublicKeyBase64 != "" {
		keyBytes, err := base64.StdEncoding.DecodeString(cfg.Security.JwtPublicKeyBase64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode jwt_public_key: %w", err)
		}
		cfg.Security.JwtPublicKey = keyBytes
	}

	if cfg.Security.JwtPrivateKeyBase64 != "" {
		keyBytes, err := base64.StdEncoding.DecodeString(cfg.Security.JwtPrivateKeyBase64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode jwt_private_key: %w", err)
		}
		cfg.Security.JwtPrivateKey = keyBytes
	}

	if cfg.Database.Token != "" {
		cfg.Database.URL = fmt.Sprintf("%s?authToken=%s", cfg.Database.URL, cfg.Database.Token)
	}

	cfg.Storage.LocalSecretKey = []byte(cfg.Storage.LocalSecret)

	return &cfg, nil
}

var (
	configOnce sync.Once
	config     *Config
)

func GetConfig(path string) (*Config, error) {
	var err error
	configOnce.Do(func() {
		workdir := os.Getenv("WORKDIR")
		if workdir == "" {
			workdir = "."
		}
		config, err = LoadConfig(filepath.Join(workdir, path))
		if err != nil {
			return
		}

		config.WorkDir = workdir
		config.DataDir = filepath.Join(workdir, "data")
	})

	return config, err
}

func MustConfig(path string) *Config {
	config, err := GetConfig(path)
	if err != nil {
		panic(err)
	}

	return config
}
