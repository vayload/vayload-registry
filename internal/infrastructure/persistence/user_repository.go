package persistence

import (
	"context"
	"database/sql"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/vayload/plug-registry/internal/domain"
)

type userRepository struct {
	db *sqlx.DB
}

func NewUserRepository(db *sqlx.DB) domain.UserRepository {
	return &userRepository{db: db}
}

func (r *userRepository) Create(ctx context.Context, user domain.User) (domain.User, error) {
	query := `INSERT INTO users (id, username, email, password_hash, avatar_url, provider, provider_id, is_active, role, verified_at, created_at, updated_at, last_login_at) 
	          VALUES (:id, :username, :email, :password_hash, :avatar_url, :provider, :provider_id, :is_active, :role, :verified_at, :created_at, :updated_at, :last_login_at)`

	model := NewUserModel(&user)

	_, err := r.db.NamedExecContext(ctx, query, model)
	return user, err
}

func (r *userRepository) GetByID(ctx context.Context, id domain.UserID) (*domain.User, error) {
	model := UserModel{}
	err := r.db.GetContext(ctx, &model, "SELECT * FROM users WHERE id = ?", id.String())
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return model.MapToDomain(), nil
}

func (r *userRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	model := UserModel{}
	err := r.db.GetContext(ctx, &model, "SELECT * FROM users WHERE email = ?", email)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return model.MapToDomain(), nil
}

func (r *userRepository) GetByUsername(ctx context.Context, username string) (*domain.User, error) {
	model := UserModel{}
	err := r.db.GetContext(ctx, &model, "SELECT * FROM users WHERE username = ?", username)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return model.MapToDomain(), nil
}

func (r *userRepository) GetByProvider(ctx context.Context, provider domain.AuthProvider, providerID string) (*domain.User, error) {
	model := UserModel{}
	err := r.db.GetContext(ctx, &model, "SELECT * FROM users WHERE provider = ? AND provider_id = ?", provider.String(), providerID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return model.MapToDomain(), nil
}

func (r *userRepository) UpdatePassword(ctx context.Context, email domain.Email, passwordHash domain.PasswordHash) error {
	_, err := r.db.ExecContext(ctx, "UPDATE users SET password_hash = ?, updated_at = ? WHERE email = ?", passwordHash.String(), time.Now().UTC(), email.String())
	return err
}

func (r *userRepository) UpdateUsername(ctx context.Context, id domain.UserID, username domain.Username) error {
	_, err := r.db.ExecContext(ctx, "UPDATE users SET username = ?, updated_at = ? WHERE id = ?", username.String(), time.Now().UTC(), id.String())
	return err
}

func (r *userRepository) UpdateEmail(ctx context.Context, id domain.UserID, email string) error {
	_, err := r.db.ExecContext(ctx, "UPDATE users SET email = ?, updated_at = ? WHERE id = ?", email, time.Now().UTC(), id.String())
	return err
}

func (r *userRepository) VerifyEmail(ctx context.Context, id domain.UserID) error {
	_, err := r.db.ExecContext(ctx, "UPDATE users SET verified_at = ?, updated_at = ? WHERE id = ?", time.Now().UTC(), time.Now().UTC(), id.String())
	return err
}

func (r *userRepository) UpdateLastLogin(ctx context.Context, id domain.UserID, at time.Time) error {
	_, err := r.db.ExecContext(ctx, "UPDATE users SET last_login_at = ? WHERE id = ?", at, id.String())
	return err
}

func (r *userRepository) UpsertRefreshToken(ctx context.Context, userID domain.UserID, token *domain.RefreshToken) error {
	query := `INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, created_at, revoked_at, revoked_reason)
	          VALUES (:id, :user_id, :token_hash, :expires_at, :created_at, :revoked_at, :revoked_reason)
	          ON CONFLICT(user_id) DO UPDATE SET
	          id = excluded.id,
	          token_hash = excluded.token_hash,
	          expires_at = excluded.expires_at,
	          created_at = excluded.created_at,
	          revoked_at = excluded.revoked_at,
	          revoked_reason = excluded.revoked_reason`

	model := NewRefreshTokenModel(token)

	_, err := r.db.NamedExecContext(ctx, query, model)
	return err
}

func (r *userRepository) RemoveRefreshToken(ctx context.Context, userID domain.UserID, tokenHash string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM refresh_tokens WHERE user_id = ? AND token_hash = ?", userID.String(), tokenHash)
	return err
}

func (r *userRepository) GetRefreshToken(ctx context.Context, id domain.UserID, token string) (*domain.RefreshToken, error) {
	model := RefreshTokenModel{}
	err := r.db.GetContext(ctx, &model, "SELECT * FROM refresh_tokens WHERE user_id = ? AND token_hash = ?", id.String(), token)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return model.MapToDomain(), nil
}

func (r *userRepository) FindRefreshTokenByHash(ctx context.Context, tokenHash string) (*domain.RefreshToken, error) {
	model := RefreshTokenModel{}
	err := r.db.GetContext(ctx, &model, "SELECT * FROM refresh_tokens WHERE token_hash = ?", tokenHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return model.MapToDomain(), nil
}
