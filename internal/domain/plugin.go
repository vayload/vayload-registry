package domain

import (
	"context"
	"io"
	"time"
)

type PluginId string

func (id PluginId) String() string {
	return string(id)
}

type PluginName string

func NewPluginName(name string) (PluginName, error) {
	if name == "" {
		return "", NewValidationError("Plugin name cannot be empty")
	}
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '@') {
			return "", NewValidationError("Plugin name can only contain alphanumeric characters and hyphens")
		}
	}
	return PluginName(name), nil
}

func (n PluginName) String() string {
	return string(n)
}

type PluginStatus string

const (
	PluginStatusDraft      PluginStatus = "draft"
	PluginStatusPublished  PluginStatus = "published"
	PluginStatusDeprecated PluginStatus = "deprecated"
	PluginStatusArchived   PluginStatus = "archived"
	PluginStatusYanked     PluginStatus = "yanked"
)

func (s PluginStatus) String() string {
	return string(s)
}

func ParsePluginStatus(s string) (PluginStatus, error) {
	switch s {
	case "draft":
		return PluginStatusDraft, nil
	case "published":
		return PluginStatusPublished, nil
	case "deprecated":
		return PluginStatusDeprecated, nil
	case "archived":
		return PluginStatusArchived, nil
	case "yanked":
		return PluginStatusYanked, nil
	default:
		return "", NewValidationError("Invalid plugin status")
	}
}

func (s PluginStatus) CanTransitionTo(next PluginStatus) bool {
	if s == next {
		return true
	}
	switch s {
	case PluginStatusDraft:
		return next == PluginStatusPublished || next == PluginStatusYanked
	case PluginStatusPublished:
		return next == PluginStatusDeprecated || next == PluginStatusArchived || next == PluginStatusYanked
	case PluginStatusDeprecated:
		return next == PluginStatusArchived || next == PluginStatusYanked
	default:
		return next == PluginStatusYanked
	}
}

type PluginVisibility string

const (
	PluginVisibilityPublic  PluginVisibility = "public"
	PluginVisibilityPrivate PluginVisibility = "private"
)

func (v PluginVisibility) String() string {
	return string(v)
}

func ParsePluginVisibility(s string) (PluginVisibility, error) {
	switch s {
	case "public":
		return PluginVisibilityPublic, nil
	case "private":
		return PluginVisibilityPrivate, nil
	default:
		return "", NewValidationError("Invalid plugin visibility")
	}
}

type PluginOwner struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

type Plugin struct {
	ID                  PluginId         `json:"id"`
	Name                PluginName       `json:"name"`
	Owner               PluginOwner      `json:"owner"`
	DisplayName         string           `json:"display_name"`
	Description         *string          `json:"description,omitempty"`
	HomepageURL         *string          `json:"homepage_url,omitempty"`
	RepoURL             *string          `json:"repo_url,omitempty"`
	DocumentationURL    *string          `json:"documentation_url,omitempty"`
	Readme              *string          `json:"readme,omitempty"`
	License             *string          `json:"license,omitempty"`
	LicenseType         *string          `json:"license_type,omitempty"`
	Visibility          PluginVisibility `json:"visibility"`
	Status              PluginStatus     `json:"status"`
	PricingType         string           `json:"pricing_type"`
	TotalDownloads      uint32           `json:"total_downloads"`
	Tags                []string         `json:"tags,omitempty"`
	CreatedAt           time.Time        `json:"created_at"`
	UpdatedAt           time.Time        `json:"updated_at"`
	LatestStableVersion *string          `json:"latest_stable_version,omitempty"`
	LatestBetaVersion   *string          `json:"latest_beta_version,omitempty"`
}

func (p *Plugin) UpdateLatestVersions(stable, beta string) {
	if stable != "" {
		p.LatestStableVersion = &stable
	}
	if beta != "" {
		p.LatestBetaVersion = &beta
	}
}

func NewPlugin(
	id PluginId,
	name PluginName,
	owner PluginOwner,
	description *string,
	homepageURL *string,
	repoURL *string,
	documentationURL *string,
	readme *string,
	license *string,
	visibility PluginVisibility,
	tags []string,
) *Plugin {
	now := time.Now().UTC()
	return &Plugin{
		ID:               id,
		Name:             name,
		Owner:            owner,
		DisplayName:      name.String(), // Default
		Description:      description,
		HomepageURL:      homepageURL,
		RepoURL:          repoURL,
		DocumentationURL: documentationURL,
		Readme:           readme,
		License:          license,
		Visibility:       visibility,
		Status:           PluginStatusDraft,
		PricingType:      "free",
		TotalDownloads:   0,
		Tags:             tags,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
}

type StorageProvider interface {
	Upload(ctx context.Context, name, version string, data io.Reader) (string, int64, string, error)
	GetSignedURL(ctx context.Context, key string) (string, error)
	Fetch(ctx context.Context, name, version string) (io.ReadCloser, error)
}

type PluginVersionStatus string

const (
	PluginVersionStatusDraft      PluginVersionStatus = "draft"
	PluginVersionStatusBeta       PluginVersionStatus = "beta"
	PluginVersionStatusStable     PluginVersionStatus = "stable"
	PluginVersionStatusDeprecated PluginVersionStatus = "deprecated"
)

func (s PluginVersionStatus) String() string {
	return string(s)
}

type PluginVersion struct {
	ID             string
	PluginID       PluginId
	Version        string
	PublishedAt    time.Time
	Yanked         bool
	YankReason     *string
	ManifestJSON   string
	SHA256         string
	Filename       string
	Status         PluginVersionStatus
	SizeBytes      uint64
	TotalFiles     int32
	DownloadsCount uint32
	MinAppVersion  *string
	MaxAppVersion  *string
	Changelog      *string
}

func NewPluginVersion(
	id string,
	pluginID PluginId,
	version string,
	manifest string,
	sha256 string,
	filename string,
	size uint64,
	totalFiles int32,
	minApp, maxApp, changelog *string,
) PluginVersion {
	return PluginVersion{
		ID:             id,
		PluginID:       pluginID,
		Version:        version,
		PublishedAt:    time.Now().UTC(),
		Status:         PluginVersionStatusStable,
		ManifestJSON:   manifest,
		SHA256:         sha256,
		Filename:       filename,
		SizeBytes:      size,
		TotalFiles:     totalFiles,
		DownloadsCount: 0,
		MinAppVersion:  minApp,
		MaxAppVersion:  maxApp,
		Changelog:      changelog,
	}
}

type VersionMatcher interface{}

type versionMatcherStable struct{}
type versionMatcherBeta struct{}
type versionMatcherExact struct{ version string }

func NewVersionMatcher(version *string) VersionMatcher {
	if version == nil {
		return versionMatcherStable{}
	}
	switch *version {
	case "beta":
		return versionMatcherBeta{}
	case "stable":
		return versionMatcherStable{}
	default:
		return versionMatcherExact{version: *version}
	}
}

type PluginFilter struct {
	Query      *string
	Category   *string
	PluginType *string // "free" or "paid"
	OwnerId    *string
	Limit      uint32
	Offset     uint32
}

type PluginTaskStatus string

const (
	PluginTaskStatusPending   PluginTaskStatus = "pending"
	PluginTaskStatusCompleted PluginTaskStatus = "completed"
	PluginTaskStatusFailed    PluginTaskStatus = "failed"
)

func (s PluginTaskStatus) String() string {
	return string(s)
}

type PluginTask struct {
	ID        string           `json:"id"`
	PluginID  PluginId         `json:"plugin_id"`
	Version   string           `json:"version"`
	UserID    string           `json:"user_id"`
	Status    PluginTaskStatus `json:"status"`
	Metadata  string           `json:"metadata"`
	Error     *string          `json:"error,omitempty"`
	CreatedAt time.Time        `json:"created_at"`
	UpdatedAt time.Time        `json:"updated_at"`
}

type PluginRepository interface {
	Create(ctx context.Context, plugin Plugin) (Plugin, error)
	GetByID(ctx context.Context, id PluginId) (*Plugin, error)
	GetByName(ctx context.Context, name PluginName) (*Plugin, error)
	GetByNameAndVersion(ctx context.Context, name PluginName, version string) (*Plugin, error)
	HasVersionUploaded(ctx context.Context, name PluginName, version string) (bool, error)
	ListByOwner(ctx context.Context, ownerID string) ([]Plugin, error)
	UpdateStatus(ctx context.Context, id PluginId, status PluginStatus) error
	Delete(ctx context.Context, id PluginId) error
	Search(ctx context.Context, query string) ([]Plugin, error)
	CreateVersion(ctx context.Context, version PluginVersion) (PluginVersion, error)
	GetVersion(ctx context.Context, pluginID PluginId, version string) (*PluginVersion, error)
	SearchWithFilters(ctx context.Context, filter PluginFilter) ([]Plugin, error)
	UpdateDownloads(ctx context.Context, pluginID PluginId, version string, downloads uint32) error
	UpdateLatestVersions(ctx context.Context, pluginID PluginId, latestVersions string) error

	// Task management
	CreateTask(ctx context.Context, task PluginTask) error
	UpdateTaskStatus(ctx context.Context, taskID string, status PluginTaskStatus, errMsg *string) error
	GetTask(ctx context.Context, taskID string) (*PluginTask, error)
}
