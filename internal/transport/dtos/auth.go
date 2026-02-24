package dtos

import (
	"errors"

	"github.com/vayload/plug-registry/internal/domain"
)

type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (v *RegisterRequest) ToValueObjects() (*domain.Email, *domain.PasswordHash, *domain.Username, error) {
	email, err := domain.NewEmail(v.Email)
	if err != nil {
		return nil, nil, nil, err
	}

	password, err := domain.NewPasswordHash(v.Password)
	if err != nil {
		return nil, nil, nil, err
	}

	username, err := domain.NewUsername(v.Username)
	if err != nil {
		return nil, nil, nil, err
	}

	return &email, &password, &username, nil
}

type RegisterUserResponse struct {
	ID          string  `json:"id"`
	Email       string  `json:"email"`
	Username    string  `json:"username"`
	AvatarURL   *string `json:"avatar_url"`
	Provider    string  `json:"provider"`
	AccessToken string  `json:"access_token"`
}

type UpdatePasswordRequest struct {
	Email       string `json:"email"`
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// Premature validations, should be done by validator
func (v *UpdatePasswordRequest) Validate() error {
	if v.Email == "" || !domain.IsValidEmail(v.Email) {
		return errors.New("email is required or invalid")
	}
	if v.OldPassword == "" || len(v.OldPassword) < domain.MinPasswordLength {
		return errors.New("old password is required or too short")
	}
	if v.NewPassword == "" || len(v.NewPassword) < domain.MinPasswordLength {
		return errors.New("new password is required or too short")
	}

	return nil
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Premature validations, should be done by validator
func (v *LoginRequest) Validate() error {
	if v.Email == "" || !domain.IsValidEmail(v.Email) {
		return errors.New("email is required or invalid")
	}
	if v.Password == "" || len(v.Password) < (domain.MinPasswordLength/2) {
		return errors.New("password is required or too short")
	}

	return nil
}

type OAuthParams struct {
	State         string  `json:"state"`
	RedirectURI   *string `json:"redirect_uri"`
	OriginURI     string  `json:"origin_uri"`
	CodeChallenge string  `json:"code_challenge"`
	ClientType    string  `json:"client_type"`
}

type OAuthResponse struct {
	AuthorizationURI string `json:"authorization_uri"`
}

type OAuthExchangeParams struct {
	Code  string `json:"code"`
	State string `json:"state"`
}

type OAuthDataResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    uint64 `json:"expires_in"`
}

type RefreshTokenRequest struct {
	RefreshToken *string `json:"refresh_token"`
}
