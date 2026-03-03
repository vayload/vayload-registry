package persistence

import (
	"database/sql"

	"github.com/goccy/go-json"
	"github.com/vayload/plug-registry/internal/domain"
	"github.com/vayload/plug-registry/internal/shared"
)

type PluginModel struct {
	ID                  string              `db:"id"`
	OwnerID             string              `db:"owner_id"`
	Name                string              `db:"name"`
	DisplayName         string              `db:"display_name"`
	Namespace           string              `db:"namespace"`
	Description         sql.NullString      `db:"description"`
	HomepageURL         sql.NullString      `db:"homepage_url"`
	RepoURL             sql.NullString      `db:"repo_url"`
	DocumentationURL    sql.NullString      `db:"documentation_url"`
	Visibility          string              `db:"visibility"`
	Tags                sql.NullString      `db:"tags"`
	Status              string              `db:"status"`
	PricingType         string              `db:"pricing_type"`
	TotalDownloads      int64               `db:"total_downloads"`
	LatestStableVersion sql.NullString      `db:"latest_stable_version"`
	LatestBetaVersion   sql.NullString      `db:"latest_beta_version"`
	CreatedAt           shared.UnixTime     `db:"created_at"`
	UpdatedAt           shared.UnixTime     `db:"updated_at"`
	DeletedAt           shared.NullUnixTime `db:"deleted_at"`
}

func NewPluginModel(plugin *domain.Plugin) *PluginModel {
	tagsJSON, _ := json.Marshal(plugin.Tags)

	return &PluginModel{
		ID:                  plugin.ID.String(),
		OwnerID:             plugin.Owner.ID,
		Name:                plugin.Name.String(),
		DisplayName:         plugin.DisplayName,
		Namespace:           plugin.Namespace,
		Description:         stringToNullString(plugin.Description),
		HomepageURL:         stringToNullString(plugin.HomepageURL),
		RepoURL:             stringToNullString(plugin.RepoURL),
		DocumentationURL:    stringToNullString(plugin.DocumentationURL),
		Visibility:          plugin.Visibility.String(),
		Tags:                sql.NullString{String: string(tagsJSON), Valid: true},
		Status:              plugin.Status.String(),
		PricingType:         plugin.PricingType,
		TotalDownloads:      int64(plugin.TotalDownloads),
		LatestStableVersion: stringToNullString(plugin.LatestStableVersion),
		LatestBetaVersion:   stringToNullString(plugin.LatestBetaVersion),
		CreatedAt:           shared.UnixTime(plugin.CreatedAt),
		UpdatedAt:           shared.UnixTime(plugin.UpdatedAt),
	}
}

func (m *PluginModel) MapToDomain() *domain.Plugin {
	var tags []string
	if m.Tags.Valid {
		_ = json.Unmarshal([]byte(m.Tags.String), &tags)
	}

	return &domain.Plugin{
		ID: domain.PluginId(m.ID),
		Owner: domain.PluginOwner{
			ID: m.OwnerID,
		},
		Name:                domain.PluginName(m.Name),
		DisplayName:         m.DisplayName,
		Description:         nullStringPtr(m.Description),
		HomepageURL:         nullStringPtr(m.HomepageURL),
		RepoURL:             nullStringPtr(m.RepoURL),
		DocumentationURL:    nullStringPtr(m.DocumentationURL),
		Visibility:          domain.PluginVisibility(m.Visibility),
		Tags:                tags,
		Status:              domain.PluginStatus(m.Status),
		PricingType:         m.PricingType,
		TotalDownloads:      uint32(m.TotalDownloads),
		LatestStableVersion: nullStringPtr(m.LatestStableVersion),
		LatestBetaVersion:   nullStringPtr(m.LatestBetaVersion),
		CreatedAt:           m.CreatedAt.Time(),
		UpdatedAt:           m.UpdatedAt.Time(),
	}
}

type PluginVersionModel struct {
	ID             string              `db:"id"`
	PluginID       string              `db:"plugin_id"`
	Version        string              `db:"version"`
	PublishedAt    shared.UnixTime     `db:"published_at"`
	Yanked         int                 `db:"yanked"`
	YankReason     sql.NullString      `db:"yank_reason"`
	Status         string              `db:"status"`
	ManifestObject string              `db:"manifest_object"`
	ReadmeObject   sql.NullString      `db:"readme_object"`
	LicenseObject  sql.NullString      `db:"license_object"`
	LicenseType    sql.NullString      `db:"license_type"`
	Integrity      shared.SinatureByte `db:"integrity"`
	Filename       string              `db:"filename"`
	SizeBytes      int64               `db:"size_bytes"`
	TotalFiles     int                 `db:"total_files"`
	DownloadsCount int                 `db:"downloads_count"`
	Changelog      sql.NullString      `db:"changelog"`
	CreatedAt      shared.UnixTime     `db:"created_at"`
}

func NewPluginVersionModel(version *domain.PluginVersion) *PluginVersionModel {
	return &PluginVersionModel{
		ID:             version.ID,
		PluginID:       version.PluginID.String(),
		Version:        version.Version,
		PublishedAt:    shared.UnixTime(version.PublishedAt),
		Yanked:         boolToInt(version.Yanked),
		YankReason:     stringToNullString(version.YankReason),
		Status:         version.Status.String(),
		ManifestObject: version.ManifestObject,
		ReadmeObject:   stringToNullString(version.ReadmeObject),
		LicenseObject:  stringToNullString(version.LicenseObject),
		LicenseType:    stringToNullString(version.LicenseType),
		Integrity:      version.Integrity,
		Filename:       version.Filename,
		SizeBytes:      int64(version.SizeBytes),
		TotalFiles:     int(version.TotalFiles),
		DownloadsCount: int(version.DownloadsCount),
		Changelog:      stringToNullString(version.Changelog),
	}
}

func (m *PluginVersionModel) MapToDomain() *domain.PluginVersion {
	return &domain.PluginVersion{
		ID:             m.ID,
		PluginID:       domain.PluginId(m.PluginID),
		Version:        m.Version,
		PublishedAt:    m.PublishedAt.Time(),
		Yanked:         m.Yanked == 1,
		YankReason:     nullStringPtr(m.YankReason),
		Status:         domain.PluginVersionStatus(m.Status),
		ManifestObject: m.ManifestObject,
		ReadmeObject:   nullStringPtr(m.ReadmeObject),
		LicenseObject:  nullStringPtr(m.LicenseObject),
		LicenseType:    nullStringPtr(m.LicenseType),
		Integrity:      m.Integrity,
		Filename:       m.Filename,
		SizeBytes:      uint64(m.SizeBytes),
		TotalFiles:     int32(m.TotalFiles),
		DownloadsCount: uint32(m.DownloadsCount),
		Changelog:      nullStringPtr(m.Changelog),
	}
}

type DetailedPluginModel struct {
	PluginModel
	Version        string          `db:"version"`
	PublishedAt    shared.UnixTime `db:"published_at"`
	Yanked         int             `db:"yanked"`
	YankReason     sql.NullString  `db:"yank_reason"`
	ManifestObject string          `db:"manifest_object"`
	ReadmeObject   sql.NullString  `db:"readme_object"`
	LicenseObject  sql.NullString  `db:"license_object"`
	LicenseType    sql.NullString  `db:"license_type"`
	Integrity      string          `db:"integrity"`
	Filename       string          `db:"filename"`
	SizeBytes      int64           `db:"size_bytes"`
	TotalFiles     int             `db:"total_files"`
	DownloadsCount int             `db:"downloads_count"`
	Changelog      sql.NullString  `db:"changelog"`
	CreatedAt      shared.UnixTime `db:"created_at"`

	// For objects
	ManifestBlob     []byte `db:"manifest_blob"`
	ReadmeBlob       []byte `db:"readme_blob"`
	LicenseBlob      []byte `db:"license_blob"`
	ManifestMimeType string `db:"manifest_mime_type"`
	ReadmeMimeType   string `db:"readme_mime_type"`
	LicenseMimeType  string `db:"license_mime_type"`
}

type PluginTaskModel struct {
	ID        string          `db:"id"`
	PluginID  string          `db:"plugin_id"`
	Version   string          `db:"version"`
	UserID    string          `db:"user_id"`
	Status    string          `db:"status"`
	Metadata  string          `db:"metadata"`
	Error     sql.NullString  `db:"error"`
	CreatedAt shared.UnixTime `db:"created_at"`
	UpdatedAt shared.UnixTime `db:"updated_at"`
}

func NewPluginTaskModel(task *domain.PluginTask) *PluginTaskModel {
	return &PluginTaskModel{
		ID:        task.ID,
		PluginID:  task.PluginID.String(),
		Version:   task.Version,
		UserID:    task.UserID,
		Status:    task.Status.String(),
		Metadata:  task.Metadata,
		Error:     stringToNullString(task.Error),
		CreatedAt: shared.UnixTime(task.CreatedAt),
		UpdatedAt: shared.UnixTime(task.UpdatedAt),
	}
}

func (m *PluginTaskModel) MapToDomain() *domain.PluginTask {
	return &domain.PluginTask{
		ID:        m.ID,
		PluginID:  domain.PluginId(m.PluginID),
		Version:   m.Version,
		UserID:    m.UserID,
		Status:    domain.PluginTaskStatus(m.Status),
		Metadata:  m.Metadata,
		Error:     nullStringPtr(m.Error),
		CreatedAt: m.CreatedAt.Time(),
		UpdatedAt: m.UpdatedAt.Time(),
	}
}

type AuditLogModel struct {
	ID           string          `db:"id"`
	UserID       string          `db:"user_id"`
	Action       string          `db:"action"`
	ResourceType string          `db:"resource_type"`
	ResourceID   string          `db:"resource_id"`
	Metadata     sql.NullString  `db:"metadata,omitempty"`
	IPAddress    sql.NullString  `db:"ip_address,omitempty"`
	UserAgent    sql.NullString  `db:"user_agent,omitempty"`
	CreatedAt    shared.UnixTime `db:"created_at"`
}

func NewAuditLogModel(log *domain.AuditLog) *AuditLogModel {
	return &AuditLogModel{
		ID:           log.ID,
		UserID:       log.UserID,
		Action:       log.Action,
		ResourceType: log.ResourceType,
		ResourceID:   log.ResourceID,
		Metadata:     stringToNullString(log.Metadata),
		IPAddress:    stringToNullString(log.IPAddress),
		UserAgent:    stringToNullString(log.UserAgent),
		CreatedAt:    shared.UnixTime(log.CreatedAt),
	}
}

func (m *AuditLogModel) MapToDomain() *domain.AuditLog {
	return &domain.AuditLog{
		ID:           m.ID,
		UserID:       m.UserID,
		Action:       m.Action,
		ResourceType: m.ResourceType,
		ResourceID:   m.ResourceID,
		Metadata:     nullStringPtr(m.Metadata),
		IPAddress:    nullStringPtr(m.IPAddress),
		UserAgent:    nullStringPtr(m.UserAgent),
		CreatedAt:    m.CreatedAt.Time(),
	}
}

// Helpers
func nullStringPtr(ns sql.NullString) *string {
	if ns.Valid {
		return &ns.String
	}
	return nil
}

func stringPtr(s string) *string {
	return &s
}

func stringToNullString(s *string) sql.NullString {
	if s == nil {
		return sql.NullString{Valid: false}
	}
	return sql.NullString{String: *s, Valid: true}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
