package persistence

import (
	"database/sql"
	"time"

	"github.com/goccy/go-json"
	"github.com/vayload/plug-registry/internal/domain"
)

type PluginModel struct {
	ID                  string         `db:"id"`
	OwnerID             string         `db:"owner_id"`
	Name                string         `db:"name"`
	DisplayName         string         `db:"display_name"`
	Description         sql.NullString `db:"description"`
	HomepageURL         sql.NullString `db:"homepage_url"`
	RepoURL             sql.NullString `db:"repo_url"`
	DocumentationURL    sql.NullString `db:"documentation_url"`
	Readme              sql.NullString `db:"readme"`
	License             sql.NullString `db:"license"`
	LicenseType         sql.NullString `db:"license_type"`
	Visibility          string         `db:"visibility"`
	Tags                sql.NullString `db:"tags"`
	Status              string         `db:"status"`
	PricingType         string         `db:"pricing_type"`
	TotalDownloads      int64          `db:"total_downloads"`
	LatestStableVersion sql.NullString `db:"latest_stable_version"`
	LatestBetaVersion   sql.NullString `db:"latest_beta_version"`
	CreatedAt           time.Time      `db:"created_at"`
	UpdatedAt           time.Time      `db:"updated_at"`
}

func NewPluginModel(plugin *domain.Plugin) *PluginModel {
	tagsJSON, _ := json.Marshal(plugin.Tags)

	return &PluginModel{
		ID:                  plugin.ID.String(),
		OwnerID:             plugin.Owner.ID,
		Name:                plugin.Name.String(),
		DisplayName:         plugin.DisplayName,
		Description:         stringToNullString(plugin.Description),
		HomepageURL:         stringToNullString(plugin.HomepageURL),
		RepoURL:             stringToNullString(plugin.RepoURL),
		DocumentationURL:    stringToNullString(plugin.DocumentationURL),
		Readme:              stringToNullString(plugin.Readme),
		License:             stringToNullString(plugin.License),
		LicenseType:         stringToNullString(plugin.LicenseType),
		Visibility:          plugin.Visibility.String(),
		Tags:                sql.NullString{String: string(tagsJSON), Valid: true},
		Status:              plugin.Status.String(),
		PricingType:         plugin.PricingType,
		TotalDownloads:      int64(plugin.TotalDownloads),
		LatestStableVersion: stringToNullString(plugin.LatestStableVersion),
		LatestBetaVersion:   stringToNullString(plugin.LatestBetaVersion),
		CreatedAt:           plugin.CreatedAt,
		UpdatedAt:           plugin.UpdatedAt,
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
		Readme:              nullStringPtr(m.Readme),
		License:             nullStringPtr(m.License),
		LicenseType:         nullStringPtr(m.LicenseType),
		Visibility:          domain.PluginVisibility(m.Visibility),
		Tags:                tags,
		Status:              domain.PluginStatus(m.Status),
		PricingType:         m.PricingType,
		TotalDownloads:      uint32(m.TotalDownloads),
		LatestStableVersion: nullStringPtr(m.LatestStableVersion),
		LatestBetaVersion:   nullStringPtr(m.LatestBetaVersion),
		CreatedAt:           m.CreatedAt,
		UpdatedAt:           m.UpdatedAt,
	}
}

type PluginVersionModel struct {
	ID             string         `db:"id"`
	PluginID       string         `db:"plugin_id"`
	Version        string         `db:"version"`
	PublishedAt    time.Time      `db:"published_at"`
	Yanked         int            `db:"yanked"`
	YankReason     sql.NullString `db:"yank_reason"`
	Status         string         `db:"status"`
	ManifestJSON   string         `db:"manifest_json"`
	SHA256         string         `db:"sha256"`
	Filename       string         `db:"filename"`
	SizeBytes      int64          `db:"size_bytes"`
	TotalFiles     int            `db:"total_files"`
	DownloadsCount int            `db:"downloads_count"`
	MinAppVersion  sql.NullString `db:"min_app_version"`
	MaxAppVersion  sql.NullString `db:"max_app_version"`
	Changelog      sql.NullString `db:"changelog"`
}

func NewPluginVersionModel(version *domain.PluginVersion) *PluginVersionModel {
	return &PluginVersionModel{
		ID:             version.ID,
		PluginID:       version.PluginID.String(),
		Version:        version.Version,
		PublishedAt:    version.PublishedAt,
		Yanked:         boolToInt(version.Yanked),
		YankReason:     stringToNullString(version.YankReason),
		Status:         version.Status.String(),
		ManifestJSON:   version.ManifestJSON,
		SHA256:         version.SHA256,
		Filename:       version.Filename,
		SizeBytes:      int64(version.SizeBytes),
		TotalFiles:     int(version.TotalFiles),
		DownloadsCount: int(version.DownloadsCount),
		MinAppVersion:  stringToNullString(version.MinAppVersion),
		MaxAppVersion:  stringToNullString(version.MaxAppVersion),
		Changelog:      stringToNullString(version.Changelog),
	}
}

func (m *PluginVersionModel) MapToDomain() *domain.PluginVersion {
	return &domain.PluginVersion{
		ID:             m.ID,
		PluginID:       domain.PluginId(m.PluginID),
		Version:        m.Version,
		PublishedAt:    m.PublishedAt,
		Yanked:         m.Yanked == 1,
		YankReason:     nullStringPtr(m.YankReason),
		Status:         domain.PluginVersionStatus(m.Status),
		ManifestJSON:   m.ManifestJSON,
		SHA256:         m.SHA256,
		Filename:       m.Filename,
		SizeBytes:      uint64(m.SizeBytes),
		TotalFiles:     int32(m.TotalFiles),
		DownloadsCount: uint32(m.DownloadsCount),
		MinAppVersion:  nullStringPtr(m.MinAppVersion),
		MaxAppVersion:  nullStringPtr(m.MaxAppVersion),
		Changelog:      nullStringPtr(m.Changelog),
	}
}

type PluginTaskModel struct {
	ID        string         `db:"id"`
	PluginID  string         `db:"plugin_id"`
	Version   string         `db:"version"`
	UserID    string         `db:"user_id"`
	Status    string         `db:"status"`
	Metadata  string         `db:"metadata"`
	Error     sql.NullString `db:"error"`
	CreatedAt time.Time      `db:"created_at"`
	UpdatedAt time.Time      `db:"updated_at"`
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
		CreatedAt: task.CreatedAt,
		UpdatedAt: task.UpdatedAt,
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
		CreatedAt: m.CreatedAt,
		UpdatedAt: m.UpdatedAt,
	}
}

// Helpers
func nullStringPtr(ns sql.NullString) *string {
	if ns.Valid {
		return &ns.String
	}
	return nil
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
