package persistence

import (
	"context"
	"database/sql"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/vayload/plug-registry/internal/domain"
)

type apiTokenRepository struct {
	db *sqlx.DB
}

func NewApiTokenRepository(db *sqlx.DB) domain.ApiTokenRepository {
	return &apiTokenRepository{db: db}
}

func (r *apiTokenRepository) Create(ctx context.Context, apiToken domain.ApiToken) (domain.ApiToken, error) {
	query := `INSERT INTO api_tokens (id, user_id, key_hash, key_name, key_scope, created_at, expires_at, last_used_at, revoked_at)
	          VALUES (:id, :user_id, :key_hash, :key_name, :key_scope, :created_at, :expires_at, :last_used_at, :revoked_at)`

	model := NewApiTokenModel(&apiToken)

	_, err := r.db.NamedExecContext(ctx, query, model)
	return apiToken, err
}

func (r *apiTokenRepository) GetByID(ctx context.Context, id domain.ApiTokenId) (*domain.ApiToken, error) {
	model := apiTokenModel{}
	err := r.db.GetContext(ctx, &model, "SELECT * FROM api_tokens WHERE id = ?", id.String())
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return model.MapToDomain(), nil
}

func (r *apiTokenRepository) GetByHash(ctx context.Context, hash string) (*domain.ApiToken, error) {
	model := apiTokenModel{}
	err := r.db.GetContext(ctx, &model, "SELECT * FROM api_tokens WHERE key_hash = ?", hash)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return model.MapToDomain(), nil
}

func (r *apiTokenRepository) ListByUser(ctx context.Context, userID string) ([]domain.ApiToken, error) {
	models := []apiTokenModel{}
	err := r.db.SelectContext(ctx, &models, "SELECT * FROM api_tokens WHERE user_id = ?", userID)
	if err != nil {
		return nil, err
	}

	tokens := make([]domain.ApiToken, len(models))
	for i, model := range models {
		tokens[i] = *model.MapToDomain()
	}

	return tokens, nil
}

func (r *apiTokenRepository) Revoke(ctx context.Context, id domain.ApiTokenId) error {
	_, err := r.db.ExecContext(ctx, "UPDATE api_tokens SET revoked_at = ? WHERE id = ?", time.Now().UTC(), id.String())
	return err
}

func (r *apiTokenRepository) Delete(ctx context.Context, id domain.ApiTokenId) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM api_tokens WHERE id = ?", id.String())
	return err
}

func (r *apiTokenRepository) UpdateLastUsed(ctx context.Context, id domain.ApiTokenId) error {
	_, err := r.db.ExecContext(ctx, "UPDATE api_tokens SET last_used_at = ? WHERE id = ?", time.Now().UTC(), id.String())
	return err
}
