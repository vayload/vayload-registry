package persistence

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/vayload/plug-registry/internal/domain"
	"github.com/vayload/plug-registry/internal/infrastructure/database"
)

type pluginRepository struct {
	db database.Queryer
}

func NewPluginRepository(db database.Queryer) domain.PluginRepository {
	return &pluginRepository{db: db}
}

func (r *pluginRepository) CreatePlugin(ctx context.Context, plugin domain.Plugin) (domain.Plugin, error) {
	query := `
	INSERT INTO plugins (
	    id,
	    owner_id,
	    name,
	    display_name,
	    namespace,
	    description,
	    homepage_url,
	    repo_url,
	    documentation_url,
	    visibility,
	    tags,
	    status,
	    pricing_type,
	    total_downloads,
	    latest_stable_version,
	    latest_beta_version,
	    created_at,
	    updated_at
	) VALUES (
	    :id,
	    :owner_id,
	    :name,
	    :display_name,
	    :namespace,
	    :description,
	    :homepage_url,
	    :repo_url,
	    :documentation_url,
	    :visibility,
	    :tags,
	    :status,
	    :pricing_type,
	    :total_downloads,
	    :latest_stable_version,
	    :latest_beta_version,
	    :created_at,
	    :updated_at
	)`

	model := NewPluginModel(&plugin)

	_, err := r.db.NamedExecContext(ctx, query, model)
	return plugin, err
}

func (r *pluginRepository) FindPluginSummary(ctx context.Context, filters domain.PluginFindBy) (*domain.Plugin, error) {
	baseQuery := "SELECT * FROM plugins p "
	conditions := []string{}
	args := []any{}

	if filters.ID != nil {
		conditions = append(conditions, "p.id = ?")
		args = append(args, *filters.ID)
	}
	// for this criteria need join with plugin_versions table
	if filters.Version != nil {
		baseQuery += "JOIN plugin_versions pv ON p.id = pv.plugin_id "
		conditions = append(conditions, "pv.version = ?")
		args = append(args, *filters.Version)
	}
	if filters.Name != nil {
		conditions = append(conditions, "p.name = ?")
		args = append(args, *filters.Name)
	}
	if filters.OwnerID != nil {
		conditions = append(conditions, "p.owner_id = ?")
		args = append(args, *filters.OwnerID)
	}
	if filters.Status != nil {
		conditions = append(conditions, "p.status = ?")
		args = append(args, *filters.Status)
	}

	query := baseQuery
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	model := PluginModel{}
	err := r.db.GetContext(ctx, &model, query+"AND p.deleted_at IS NULL LIMIT 1", args...)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotResultSet
		}

		return nil, err
	}

	return model.MapToDomain(), nil
}

func (r *pluginRepository) FindPluginDetails(ctx context.Context, filters domain.PluginFindBy) (*domain.Plugin, error) {
	model := DetailedPluginModel{}
	query := `
    SELECT
        p.*,
        v.version,
        v.published_at,
        v.yanked,
        v.yank_reason,
        v.license_type,
        v.integrity,
        v.filename,
        v.size_bytes,
        v.total_files,
        v.downloads_count,
        v.changelog,
        ro.blob as readme_blob,
        lo.blob as license_blob,
        ro.mime_type as readme_mime_type,
        lo.mime_type as license_mime_type
    FROM plugins p
    JOIN plugin_versions v ON v.plugin_id = p.id AND v.version = (
    	-- Fetch the latest version if the target version is not provided
    	COALESCE(NULLIF(?, ''), p.latest_stable_version, (SELECT version FROM plugin_versions WHERE plugin_id = p.id ORDER BY created_at DESC LIMIT 1))
    )
    LEFT JOIN storage_objects ro ON v.readme_object = ro.object_hash
    LEFT JOIN storage_objects lo ON v.license_object = lo.object_hash
    WHERE p.deleted_at IS NULL
    `

	conditions := []string{}
	targetVersion := ""
	if filters.Version != nil {
		targetVersion = *filters.Version
	}
	args := []any{targetVersion}

	if filters.ID != nil {
		conditions = append(conditions, "p.id = ?")
		args = append(args, *filters.ID)
	}
	if filters.Name != nil {
		conditions = append(conditions, "p.name = ?")
		args = append(args, *filters.Name)
	}
	if filters.OwnerID != nil {
		conditions = append(conditions, "p.owner_id = ?")
		args = append(args, *filters.OwnerID)
	}

	if len(conditions) > 0 {
		query += " AND " + strings.Join(conditions, " AND ")
	}
	query += " LIMIT 1"

	err := r.db.GetContext(ctx, &model, query, args...)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotResultSet
		}

		return nil, err
	}

	plugin := model.PluginModel.MapToDomain()
	plugin.Readme = stringPtr(string(model.ReadmeBlob))
	plugin.License = stringPtr(string(model.LicenseBlob))
	plugin.LicenseType = stringPtr(model.LicenseType.String)

	return plugin, nil
}

func (r *pluginRepository) HasMatchingPlugin(ctx context.Context, filters domain.PluginFindBy) (bool, error) {
	baseQuery := "SELECT EXISTS(SELECT 1 FROM plugins p "
	conditions := []string{}
	args := []any{}

	if filters.ID != nil {
		conditions = append(conditions, "p.id = ?")
		args = append(args, *filters.ID)
	}
	// for this criteria need join with plugin_versions table
	if filters.Version != nil {
		baseQuery += "JOIN plugin_versions pv ON p.id = pv.plugin_id "
		conditions = append(conditions, "pv.version = ?")
		args = append(args, *filters.Version)
	}
	if filters.Name != nil {
		conditions = append(conditions, "p.name = ?")
		args = append(args, *filters.Name)
	}
	if filters.OwnerID != nil {
		conditions = append(conditions, "p.owner_id = ?")
		args = append(args, *filters.OwnerID)
	}
	if filters.Status != nil {
		conditions = append(conditions, "p.status = ?")
		args = append(args, *filters.Status)
	}

	query := baseQuery
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	var exist bool
	err := r.db.GetContext(ctx, &exist, query+"AND p.deleted_at IS NULL LIMIT 1)", args...)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, domain.ErrNotResultSet
		}

		return false, err
	}

	return exist, nil
}

func (r *pluginRepository) ListByOwner(ctx context.Context, ownerID string) ([]domain.Plugin, error) {
	models := []PluginModel{}
	err := r.db.SelectContext(ctx, &models, "SELECT * FROM plugins WHERE owner_id = ? AND deleted_at IS NULL", ownerID)
	if err != nil {
		return nil, err
	}

	plugins := make([]domain.Plugin, len(models))
	for i, m := range models {
		plugins[i] = *m.MapToDomain()
	}

	return plugins, nil
}

func (r *pluginRepository) UpdateStatus(ctx context.Context, id domain.PluginId, status domain.PluginStatus) error {
	_, err := r.db.ExecContext(ctx, "UPDATE plugins SET status = ?, updated_at = ? WHERE id = ?", status.String(), time.Now().UTC(), id.String())
	return err
}

func (r *pluginRepository) Delete(ctx context.Context, id domain.PluginId) error {
	_, err := r.db.ExecContext(ctx, "UPDATE plugins SET deleted_at = ?, updated_at = ? WHERE id = ?", time.Now().UTC(), time.Now().UTC(), id.String())
	return err
}

func (r *pluginRepository) Search(ctx context.Context, query string) ([]domain.Plugin, error) {
	models := []PluginModel{}
	q := "%" + query + "%"
	err := r.db.SelectContext(ctx, &models, "SELECT * FROM plugins WHERE (name LIKE ? OR display_name LIKE ? OR description LIKE ?) AND deleted_at IS NULL", q, q, q)
	if err != nil {
		return nil, err
	}

	plugins := make([]domain.Plugin, len(models))
	for i, m := range models {
		plugins[i] = *m.MapToDomain()
	}
	return plugins, nil
}

func (r *pluginRepository) SearchWithFilters(ctx context.Context, filter domain.PluginFilter) ([]domain.Plugin, error) {
	query := "SELECT * FROM plugins WHERE deleted_at IS NULL"
	args := []any{}

	if filter.Query != nil {
		query += " AND (name LIKE ? OR display_name LIKE ?)"
		q := "%" + *filter.Query + "%"
		args = append(args, q, q)
	}

	query += " LIMIT ? OFFSET ?"
	args = append(args, filter.Limit, filter.Offset)

	models := []PluginModel{}
	err := r.db.SelectContext(ctx, &models, query, args...)
	if err != nil {
		return nil, err
	}

	plugins := make([]domain.Plugin, len(models))
	for i, m := range models {
		plugins[i] = *m.MapToDomain()
	}
	return plugins, nil
}

func (r *pluginRepository) CreateVersion(ctx context.Context, version domain.PluginVersion) (domain.PluginVersion, error) {
	query := `INSERT INTO plugin_versions (id, plugin_id, version, published_at, yanked, yank_reason, status, manifest_object, readme_object, license_object, license_type, integrity, filename, size_bytes, total_files, downloads_count, changelog)
	          VALUES (:id, :plugin_id, :version, :published_at, :yanked, :yank_reason, :status, :manifest_object, :readme_object, :license_object, :license_type, :integrity, :filename, :size_bytes, :total_files, :downloads_count, :changelog)`

	model := NewPluginVersionModel(&version)

	_, err := r.db.NamedExecContext(ctx, query, model)
	return version, err
}

func (r *pluginRepository) GetVersion(ctx context.Context, pluginID domain.PluginId, version string) (*domain.PluginVersion, error) {
	model := PluginVersionModel{}
	err := r.db.GetContext(ctx, &model, "SELECT * FROM plugin_versions WHERE plugin_id = ? AND version = ?", pluginID.String(), version)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotResultSet
		}

		return nil, err
	}

	return model.MapToDomain(), nil
}

func (r *pluginRepository) UpdateDownloads(ctx context.Context, pluginID domain.PluginId, version string, downloads uint32) error {
	if transactor, ok := r.db.(database.Transactor); ok {
		return transactor.Transaction(ctx, func(ctx context.Context, tx database.Queryer) error {
			return r.updateDownloads(ctx, tx, pluginID, version, downloads)
		})
	}

	return r.updateDownloads(ctx, r.db, pluginID, version, downloads)
}

func (r *pluginRepository) updateDownloads(ctx context.Context, q database.Queryer, pluginID domain.PluginId, version string, downloads uint32) error {
	_, err := q.ExecContext(ctx, "UPDATE plugin_versions SET downloads_count = downloads_count + ? WHERE plugin_id = ? AND version = ?", downloads, pluginID.String(), version)
	if err != nil {
		return err
	}

	_, err = q.ExecContext(ctx, "UPDATE plugins SET total_downloads = total_downloads + ? WHERE id = ?", downloads, pluginID.String())
	return err
}

func (r *pluginRepository) UpdateLatestVersions(ctx context.Context, pluginID domain.PluginId, latestVersions string) error {
	_, err := r.db.ExecContext(ctx, "UPDATE plugins SET latest_stable_version = ?, updated_at = ? WHERE id = ?", latestVersions, time.Now().UTC(), pluginID.String())
	return err
}

func (r *pluginRepository) CreateTask(ctx context.Context, task domain.PluginTask) error {
	query := `INSERT INTO plugin_tasks (id, plugin_id, version, user_id, status, metadata, error, created_at, updated_at)
	          VALUES (:id, :plugin_id, :version, :user_id, :status, :metadata, :error, :created_at, :updated_at)`

	model := NewPluginTaskModel(&task)

	_, err := r.db.NamedExecContext(ctx, query, model)
	return err
}

func (r *pluginRepository) UpdateTaskStatus(ctx context.Context, taskID string, status domain.PluginTaskStatus, errMsg *string) error {
	query := "UPDATE plugin_tasks SET status = ?, error = ?, updated_at = ? WHERE id = ?"
	_, err := r.db.ExecContext(ctx, query, status.String(), stringToNullString(errMsg), time.Now().UTC(), taskID)
	return err
}

func (r *pluginRepository) GetTask(ctx context.Context, taskID string) (*domain.PluginTask, error) {
	model := PluginTaskModel{}
	err := r.db.GetContext(ctx, &model, "SELECT * FROM plugin_tasks WHERE id = ?", taskID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotResultSet
		}

		return nil, err
	}

	return model.MapToDomain(), nil
}

func (r *pluginRepository) GetAggregatedStats(ctx context.Context, ownerID string) (totalPlugins, totalDownloads, totalVersions int, err error) {
	query := `
		SELECT 
			COUNT(DISTINCT p.id) as total_plugins,
			COALESCE(SUM(p.total_downloads), 0) as total_downloads,
			COUNT(pv.id) as total_versions
		FROM plugins p
		LEFT JOIN plugin_versions pv ON p.id = pv.plugin_id
		WHERE p.owner_id = ? AND p.deleted_at IS NULL
	`
	err = r.db.QueryRowContext(ctx, query, ownerID).Scan(&totalPlugins, &totalDownloads, &totalVersions)
	return
}

func (r *pluginRepository) GetLatestAuditLogs(ctx context.Context, userID string, limit int) ([]domain.AuditLog, error) {
	query := `
		SELECT * FROM audit_logs 
		WHERE user_id = ? 
		ORDER BY created_at DESC 
		LIMIT ?
	`
	var logs []AuditLogModel
	err := r.db.SelectContext(ctx, &logs, query, userID, limit)
	if err != nil {
		return nil, err
	}

	auditLogs := make([]domain.AuditLog, len(logs))
	for i, log := range logs {
		auditLogs[i] = *log.MapToDomain()
	}

	return auditLogs, nil
}
