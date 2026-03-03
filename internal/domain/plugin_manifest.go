package domain

import (
	"fmt"
	"strings"
)

const (
	MANIFEST_FILENAME = "plugin.json"
	VKIGNORE_FILENAME = ".vkignore"
)

/*
   =========================
   PluginManifest
   =========================
*/

type PluginManifest struct {
	Name             string            `json:"name"`
	DisplayName      string            `json:"display_name"`
	Version          string            `json:"version"`
	Description      string            `json:"description"`
	Namespace        *string           `json:"namespace"`
	License          string            `json:"license"`
	Keywords         []string          `json:"keywords"`
	Tags             []string          `json:"tags"`
	Homepage         *string           `json:"homepage,omitempty"`
	Repository       *Repository       `json:"repository,omitempty"`
	Author           string            `json:"author"`
	Contributors     []string          `json:"contributors,omitempty"`
	Main             string            `json:"main"`
	Engines          Engines           `json:"engines"`
	Dependencies     map[string]string `json:"dependencies,omitempty"`
	DevDependencies  map[string]string `json:"dev_dependencies,omitempty"`
	HostDependencies map[string]string `json:"host_dependencies,omitempty"`
	Permissions      *Permissions      `json:"permissions,omitempty"`
	Config           *PluginConfig     `json:"config,omitempty"`
}

func (p *PluginManifest) SetName(name string) {
	p.Name = strings.ToLower(strings.ReplaceAll(name, " ", "-"))
	p.DisplayName = name
}

/*
   =========================
   Repository
   =========================
*/

type Repository struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

func DefaultRepository() *Repository {
	return &Repository{
		Type: "git",
		URL:  "",
	}
}

/*
   =========================
   Engines
   =========================
*/

type Engines struct {
	Lua  string `json:"lua"`
	Host string `json:"host"`
}

func DefaultEngines() Engines {
	return Engines{
		Lua:  "5.1",
		Host: "*",
	}
}

/*
   =========================
   Permissions
   =========================
*/

type Permissions struct {
	Filesystem *FileSystemPermission `json:"filesystem,omitempty"`
	Network    *NetworkPermission    `json:"network,omitempty"`
	Limits     *Limits               `json:"limits,omitempty"`
}

func DefaultPermissions() *Permissions {
	return &Permissions{
		Filesystem: DefaultFileSystemPermission(),
		Network:    DefaultNetworkPermission(),
		Limits:     DefaultLimits(),
	}
}

func NewPermissions(fs *FileSystemPermission, net *NetworkPermission, lim *Limits) *Permissions {
	return &Permissions{
		Filesystem: fs,
		Network:    net,
		Limits:     lim,
	}
}

/*
   =========================
   FileSystemPermission
   =========================
*/

type FileSystemPermission struct {
	Scope FileSystemScope `json:"scope"`
	Allow []string        `json:"allow"`
	Deny  []string        `json:"deny"`
}

func DefaultFileSystemPermission() *FileSystemPermission {
	return &FileSystemPermission{
		Scope: FSScopeNone,
		Allow: []string{},
		Deny:  []string{},
	}
}

type FileSystemScope string

const (
	FSScopeReadOnly  FileSystemScope = "read-only"
	FSScopeReadWrite FileSystemScope = "read-write"
	FSScopeNone      FileSystemScope = "none"
)

/*
   =========================
   NetworkPermission
   =========================
*/

type NetworkPermission struct {
	AllowOutbound []string `json:"allow_outbound"`
	AllowInbound  bool     `json:"allow_inbound"`
}

func DefaultNetworkPermission() *NetworkPermission {
	return &NetworkPermission{
		AllowOutbound: []string{},
		AllowInbound:  false,
	}
}

func NewNetworkPermission(outbound []string, inbound bool) *NetworkPermission {
	return &NetworkPermission{
		AllowOutbound: outbound,
		AllowInbound:  inbound,
	}
}

/*
   =========================
   Limits
   =========================
*/

type Limits struct {
	MaxMemoryMB        uint32 `json:"max_memory_mb"`
	MaxExecutionTimeMS uint64 `json:"max_execution_time_ms"`
	MaxThreads         uint16 `json:"max_threads"`
}

func DefaultLimits() *Limits {
	return &Limits{
		MaxMemoryMB:        128,
		MaxExecutionTimeMS: 10000,
		MaxThreads:         10,
	}
}

/*
   =========================
   PluginConfig
   =========================
*/

type PluginConfig struct {
	MaxFileSize   uint64 `json:"max_file_size"`
	ChunkSize     uint64 `json:"chunk_size"`
	RetryAttempts uint32 `json:"retry_attempts"`
}

func DefaultPluginConfig() *PluginConfig {
	return &PluginConfig{
		MaxFileSize:   5 * 1024 * 1024,
		ChunkSize:     4096,
		RetryAttempts: 3,
	}
}

/*
   =========================
   PluginAccess
   =========================
*/

type PluginAccess string

const (
	Public  PluginAccess = "public"
	Private PluginAccess = "private"
)

func (p PluginAccess) AsString() string {
	return string(p)
}

func PluginAccessFromString(s string) (PluginAccess, error) {
	switch s {
	case "public":
		return Public, nil
	case "private":
		return Private, nil
	default:
		return "", fmt.Errorf("invalid access level: %s", s)
	}
}
