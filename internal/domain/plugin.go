package domain

import (
	"context"
	"crypto/sha256"
	"io"
	"time"

	"github.com/vayload/plug-registry/internal/shared/errors"
)

type PluginId string

func (id PluginId) String() string {
	return string(id)
}

type PluginName string

func NewPluginName(name string) (PluginName, error) {
	if name == "" {
		return "", errors.Validation("Plugin name cannot be empty")
	}
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '@') {
			return "", errors.Validation("Plugin name can only contain alphanumeric characters and hyphens")
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
		return "", errors.Validation("Invalid plugin status")
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
		return "", errors.Validation("Invalid plugin visibility")
	}
}

type PluginOwner struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

type Plugin struct {
	ID                  PluginId         `json:"id"`
	Name                PluginName       `json:"name"`
	Namespace           string           `json:"namespace"`
	Owner               PluginOwner      `json:"owner"`
	DisplayName         string           `json:"display_name"`
	Description         *string          `json:"description,omitempty"`
	HomepageURL         *string          `json:"homepage_url,omitempty"`
	RepoURL             *string          `json:"repo_url,omitempty"`
	DocumentationURL    *string          `json:"documentation_url,omitempty"`
	Readme              *string          `json:"readme,omitempty"`       // Latest readme content
	License             *string          `json:"license,omitempty"`      // latest license content
	LicenseType         *string          `json:"license_type,omitempty"` // latest license type
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
	visibility PluginVisibility,
	tags []string,
) *Plugin {
	now := time.Now().UTC()
	return &Plugin{
		ID:               id,
		Name:             name,
		Namespace:        name.String(),
		Owner:            owner,
		DisplayName:      name.String(), // Default
		Description:      description,
		HomepageURL:      homepageURL,
		RepoURL:          repoURL,
		DocumentationURL: documentationURL,
		Visibility:       visibility,
		Status:           PluginStatusDraft,
		PricingType:      "free",
		TotalDownloads:   0,
		Tags:             tags,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
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
	ManifestObject string
	ReadmeObject   *string
	LicenseObject  *string
	LicenseType    *string
	Integrity      [32]byte
	Filename       string
	Status         PluginVersionStatus
	SizeBytes      uint64
	TotalFiles     int32
	DownloadsCount uint32
	Changelog      *string
}

func NewPluginVersion(
	id string,
	pluginID PluginId,
	version string,
	integrity [32]byte,
	filename string,
	size uint64,
	totalFiles int32,
) PluginVersion {
	return PluginVersion{
		ID:             id,
		PluginID:       pluginID,
		Version:        version,
		PublishedAt:    time.Now().UTC(),
		Status:         PluginVersionStatusStable,
		Integrity:      integrity,
		Filename:       filename,
		SizeBytes:      size,
		TotalFiles:     totalFiles,
		DownloadsCount: 0,
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

type FindTypes uint8

const (
	FindTypeByName FindTypes = iota
	FindTypeByVersion
	FindTypeByCategory
	FindTypeByPluginType
	FindTypeByOwnerId
	FindTypeByStatus
)

type PluginFindBy struct {
	ID      *string
	Version *string
	Name    *string
	OwnerID *string
	Status  *string

	Limit  uint32
	Offset uint32
}

func NewPluginFindBy() *PluginFindBy {
	return &PluginFindBy{
		Limit:  10,
		Offset: 0,
	}
}

func (f *PluginFindBy) WithID(id string) *PluginFindBy {
	f.ID = &id
	return f
}

func (f *PluginFindBy) WithVersion(version string) *PluginFindBy {
	f.Version = &version
	return f
}

func (f *PluginFindBy) WithName(name string) *PluginFindBy {
	f.Name = &name
	return f
}

func (f *PluginFindBy) WithOwnerID(ownerID string) *PluginFindBy {
	f.OwnerID = &ownerID
	return f
}

func (f *PluginFindBy) WithStatus(status string) *PluginFindBy {
	f.Status = &status
	return f
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

func NewPluginTask(ID string, pluginID PluginId, version, userID string) *PluginTask {
	return &PluginTask{
		ID:        ID,
		PluginID:  pluginID,
		Version:   version,
		UserID:    userID,
		Status:    PluginTaskStatusPending,
		Metadata:  "",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
}

func (t *PluginTask) UpdateStatus(status PluginTaskStatus, errMsg *string) {
	t.Status = status
	t.Error = errMsg
	t.UpdatedAt = time.Now().UTC()
}

func (t *PluginTask) UpdateMetadata(metadata string) {
	t.Metadata = metadata
	t.UpdatedAt = time.Now().UTC()
}

type IPluginStorage interface {
	Put(ctx context.Context, key string, mimeType string, r io.Reader) error
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	GetSignedURL(ctx context.Context, key string) (string, error)
	Delete(ctx context.Context, key string) error
}

type PluginRepository interface {
	CreatePlugin(ctx context.Context, plugin Plugin) (Plugin, error)
	FindPluginSummary(ctx context.Context, filters PluginFindBy) (*Plugin, error)
	FindPluginDetails(ctx context.Context, filters PluginFindBy) (*Plugin, error)
	HasMatchingPlugin(ctx context.Context, filters PluginFindBy) (bool, error)

	ListByOwner(ctx context.Context, ownerID string) ([]Plugin, error)
	UpdateStatus(ctx context.Context, id PluginId, status PluginStatus) error
	Delete(ctx context.Context, id PluginId) error
	Search(ctx context.Context, query string) ([]Plugin, error)
	CreateVersion(ctx context.Context, version PluginVersion) (PluginVersion, error)
	GetVersion(ctx context.Context, pluginID PluginId, version string) (*PluginVersion, error)
	SearchWithFilters(ctx context.Context, filter PluginFilter) ([]Plugin, error)
	UpdateDownloads(ctx context.Context, pluginID PluginId, version string, downloads uint32) error
	UpdateLatestVersions(ctx context.Context, pluginID PluginId, latestVersions string) error

	// Stats
	GetAggregatedStats(ctx context.Context, ownerID string) (totalPlugins, totalDownloads, totalVersions int, err error)
	GetLatestAuditLogs(ctx context.Context, userID string, limit int) ([]AuditLog, error)

	// Task management
	CreateTask(ctx context.Context, task PluginTask) error
	UpdateTaskStatus(ctx context.Context, taskID string, status PluginTaskStatus, errMsg *string) error
	GetTask(ctx context.Context, taskID string) (*PluginTask, error)
}

type ObjectRepository interface {
	// Insert or create object in object_storage
	UpsertObjects(ctx context.Context, objects []BlobObject) error
}

type BlobObject struct {
	ObjectHash string // SHA256 hash
	Type       string // 'tarball', 'manifest', 'readme', 'license', etc.
	SizeBytes  int64
	MimeType   string // 'application/json', 'text/markdown', 'application/gzip'
	Blob       []byte // bynary content
	CreatedAt  time.Time
}

func NewBlobObject(ID string, rtype string, blobType string, blob []byte) *BlobObject {
	hasher := sha256.New()
	hasher.Write(blob)

	return &BlobObject{
		ObjectHash: ID,
		Type:       rtype,
		SizeBytes:  int64(len(blob)),
		MimeType:   blobType,
		Blob:       blob,
		CreatedAt:  time.Now().UTC(),
	}
}
