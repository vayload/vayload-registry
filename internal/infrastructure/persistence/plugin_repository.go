package persistence

import (
	"context"
	"database/sql"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/vayload/plug-registry/internal/domain"
)

type pluginRepository struct {
	db *sqlx.DB
}

func NewPluginRepository(db *sqlx.DB) domain.PluginRepository {
	return &pluginRepository{db: db}
}

func (r *pluginRepository) Create(ctx context.Context, plugin domain.Plugin) (domain.Plugin, error) {
	query := `INSERT INTO plugins (id, owner_id, name, display_name, description, homepage_url, repo_url, documentation_url, readme, license, license_type, visibility, tags, status, pricing_type, total_downloads, latest_stable_version, latest_beta_version, created_at, updated_at)
	          VALUES (:id, :owner_id, :name, :display_name, :description, :homepage_url, :repo_url, :documentation_url, :readme, :license, :license_type, :visibility, :tags, :status, :pricing_type, :total_downloads, :latest_stable_version, :latest_beta_version, :created_at, :updated_at)`

	model := NewPluginModel(&plugin)

	_, err := r.db.NamedExecContext(ctx, query, model)
	return plugin, err
}

func (r *pluginRepository) GetByID(ctx context.Context, id domain.PluginId) (*domain.Plugin, error) {
	model := PluginModel{}
	err := r.db.GetContext(ctx, &model, "SELECT * FROM plugins WHERE id = ? AND deleted_at IS NULL", id.String())
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return model.MapToDomain(), nil
}

func (r *pluginRepository) GetByName(ctx context.Context, name domain.PluginName) (*domain.Plugin, error) {
	model := PluginModel{}
	err := r.db.GetContext(ctx, &model, "SELECT * FROM plugins WHERE name = ? AND deleted_at IS NULL", name.String())
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return model.MapToDomain(), nil
}

func (r *pluginRepository) GetByNameAndVersion(ctx context.Context, name domain.PluginName, version string) (*domain.Plugin, error) {
	model := PluginModel{}
	err := r.db.GetContext(ctx, &model, `SELECT p.* FROM plugins p 
	                                 JOIN plugin_versions v ON p.id = v.plugin_id 
	                                 WHERE p.name = ? AND v.version = ? AND p.deleted_at IS NULL`, name.String(), version)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return model.MapToDomain(), nil
}

func (r *pluginRepository) HasVersionUploaded(ctx context.Context, name domain.PluginName, version string) (bool, error) {
	var exists bool
	err := r.db.GetContext(ctx, &exists, `SELECT EXISTS(SELECT 1 FROM plugins p 
	                                           JOIN plugin_versions v ON p.id = v.plugin_id 
	                                           WHERE p.name = ? AND v.version = ?)`, name.String(), version)
	return exists, err
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
	query := `INSERT INTO plugin_versions (id, plugin_id, version, published_at, yanked, yank_reason, status, manifest_json, sha256, filename, size_bytes, total_files, downloads_count, min_app_version, max_app_version, changelog)
	          VALUES (:id, :plugin_id, :version, :published_at, :yanked, :yank_reason, :status, :manifest_json, :sha256, :filename, :size_bytes, :total_files, :downloads_count, :min_app_version, :max_app_version, :changelog)`

	model := NewPluginVersionModel(&version)

	_, err := r.db.NamedExecContext(ctx, query, model)
	return version, err
}

func (r *pluginRepository) GetVersion(ctx context.Context, pluginID domain.PluginId, version string) (*domain.PluginVersion, error) {
	model := PluginVersionModel{}
	err := r.db.GetContext(ctx, &model, "SELECT * FROM plugin_versions WHERE plugin_id = ? AND version = ?", pluginID.String(), version)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return model.MapToDomain(), nil
}

func (r *pluginRepository) UpdateDownloads(ctx context.Context, pluginID domain.PluginId, version string, downloads uint32) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, "UPDATE plugin_versions SET downloads_count = downloads_count + ? WHERE plugin_id = ? AND version = ?", downloads, pluginID.String(), version)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, "UPDATE plugins SET total_downloads = total_downloads + ? WHERE id = ?", downloads, pluginID.String())
	if err != nil {
		return err
	}

	return tx.Commit()
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
			return nil, nil
		}
		return nil, err
	}

	return model.MapToDomain(), nil
}
