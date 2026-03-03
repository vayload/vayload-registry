package persistence

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/vayload/plug-registry/internal/domain"
	"github.com/vayload/plug-registry/internal/infrastructure/database"
)

type userRepository struct {
	db database.Queryer
}

func NewUserRepository(db database.Queryer) domain.UserRepository {
	return &userRepository{db: db}
}

func (r *userRepository) Create(ctx context.Context, user domain.User) (domain.User, error) {
	query := `INSERT INTO users (id, username, email, password_hash, avatar_url, provider, provider_id, is_active, role, verified_at, created_at, updated_at, last_login_at) 
	          VALUES (:id, :username, :email, :password_hash, :avatar_url, :provider, :provider_id, :is_active, :role, :verified_at, :created_at, :updated_at, :last_login_at)`

	model := NewUserModel(&user)

	_, err := r.db.NamedExecContext(ctx, query, model)
	return user, err
}

func (r *userRepository) CreateUnverifiedUser(ctx context.Context, user domain.User, token domain.UnverifiedToken) (domain.User, error) {
	query := `INSERT INTO users (id, username, email, password_hash, avatar_url, provider, provider_id, is_active, role, verification_token, created_at, updated_at, last_login_at) 
	          VALUES (:id, :username, :email, :password_hash, :avatar_url, :provider, :provider_id, :is_active, :role, :verification_token, :created_at, :updated_at, :last_login_at)`

	model := NewUserModel(&user)
	model.SetUnverifiedToken(token.Token)

	_, err := r.db.NamedExecContext(ctx, query, model)
	return user, err
}

func (r *userRepository) FindUserBy(ctx context.Context, filter domain.UserFilterBy) (*domain.User, error) {
	var query strings.Builder
	query.WriteString("SELECT * FROM users WHERE 1=1")

	args := make([]any, 0, 4)

	if filter.ID != nil {
		query.WriteString(" AND id = ?")
		args = append(args, filter.ID.String())
	}
	if filter.Username != nil {
		query.WriteString(" AND username = ?")
		args = append(args, filter.Username.String())
	}
	if filter.Email != nil {
		query.WriteString(" AND email = ?")
		args = append(args, filter.Email.String())
	}
	if filter.Role != nil {
		query.WriteString(" AND role = ?")
		args = append(args, filter.Role.String())
	}

	query.WriteString(" LIMIT 1")

	model := UserModel{}
	err := r.db.GetContext(ctx, &model, query.String(), args...)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotResultSet
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

func (r *userRepository) FindByVerificationToken(ctx context.Context, userID domain.UserID, token string) (*domain.User, error) {
	model := UserModel{}
	err := r.db.GetContext(ctx, &model, "SELECT * FROM users WHERE id = ? AND verification_token = ?", userID.String(), token)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotResultSet
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

func (r *userRepository) MarkEmailVerified(ctx context.Context, id domain.UserID) error {
	_, err := r.db.ExecContext(ctx, "UPDATE users SET verified_at = ?, verification_token = NULL, updated_at = ? WHERE id = ?", time.Now().UTC(), time.Now().UTC(), id.String())
	return err
}

func (r *userRepository) UpdateLastLogin(ctx context.Context, id domain.UserID, at time.Time) error {
	_, err := r.db.ExecContext(ctx, "UPDATE users SET last_login_at = ? WHERE id = ?", at, id.String())
	return err
}

func (r *userRepository) CreateRefreshToken(ctx context.Context, token *domain.RefreshToken) error {
	query := `
	INSERT INTO refresh_tokens (
		id,
		token_hash,
		user_id,
		family_id,
		parent_id,
		used_at,
		revoked_at,
		revoked_reason,
		expires_at,
		created_at,
		user_agent,
		ip_address
	) VALUES (
		:id,
		:token_hash,
		:user_id,
		:family_id,
		:parent_id,
		:used_at,
		:revoked_at,
		:revoked_reason,
		:expires_at,
		:created_at,
		:user_agent,
		:ip_address
	)`

	model := NewRefreshTokenModel(token)

	_, err := r.db.NamedExecContext(ctx, query, model)
	return err
}

func (r *userRepository) MarkRefreshTokenUsed(ctx context.Context, tokenID string) error {
	_, err := r.db.ExecContext(
		ctx,
		`UPDATE refresh_tokens
		 SET used_at = CURRENT_TIMESTAMP
		 WHERE id = ?`,
		tokenID,
	)

	return err
}

func (r *userRepository) RevokeRefreshTokenFamily(ctx context.Context, familyID string, reason string) error {
	_, err := r.db.ExecContext(
		ctx,
		`UPDATE refresh_tokens
		 SET revoked_at = CURRENT_TIMESTAMP,
		     revoked_reason = ?
		 WHERE family_id = ?
		   AND revoked_at IS NULL`,
		reason,
		familyID,
	)

	return err
}

func (r *userRepository) FindRefreshTokenByHash(ctx context.Context, tokenHash string) (*domain.RefreshToken, error) {
	model := RefreshTokenModel{}

	err := r.db.GetContext(
		ctx,
		&model,
		`SELECT * FROM refresh_tokens WHERE token_hash = ?`,
		tokenHash,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return model.MapToDomain(), nil
}
