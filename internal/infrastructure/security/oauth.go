package security

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/vayload/plug-registry/config"
	"github.com/vayload/plug-registry/internal/domain"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

type githubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	AvatarURL string `json:"avatar_url"`
}

type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

type googleUser struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
}

type oauthStrategyFacadeImpl struct {
	githubWeb *oauth2.Config
	githubCli *oauth2.Config
	googleWeb *oauth2.Config
	googleCli *oauth2.Config
}

func NewOAuthStrategy(cfg *config.Config) domain.OAuthStrategy {
	return &oauthStrategyFacadeImpl{
		githubWeb: &oauth2.Config{
			ClientID:     cfg.OAuth.GithubWeb.ClientID,
			ClientSecret: cfg.OAuth.GithubWeb.ClientSecret,
			RedirectURL:  cfg.OAuth.GithubWeb.RedirectURL,
			Endpoint:     github.Endpoint,
			Scopes:       []string{"user:email", "read:user"},
		},
		githubCli: &oauth2.Config{
			ClientID:     cfg.OAuth.GithubCli.ClientID,
			ClientSecret: cfg.OAuth.GithubCli.ClientSecret,
			RedirectURL:  cfg.OAuth.GithubCli.RedirectURL,
			Endpoint:     github.Endpoint,
			Scopes:       []string{"user:email", "read:user"},
		},
		googleWeb: &oauth2.Config{
			ClientID:     cfg.OAuth.GoogleWeb.ClientID,
			ClientSecret: cfg.OAuth.GoogleWeb.ClientSecret,
			RedirectURL:  cfg.OAuth.GoogleWeb.RedirectURL,
			Endpoint:     google.Endpoint,
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
			},
		},
		googleCli: &oauth2.Config{
			ClientID:     cfg.OAuth.GoogleCli.ClientID,
			ClientSecret: cfg.OAuth.GoogleCli.ClientSecret,
			RedirectURL:  cfg.OAuth.GoogleCli.RedirectURL,
			Endpoint:     google.Endpoint,
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
			},
		},
	}
}

func (s *oauthStrategyFacadeImpl) GetAuthenticationURI(provider domain.OAuthProvider, state domain.OAuthState) (string, error) {
	c := s.getClient(provider, state.ClientType)
	if c == nil {
		return "", domain.NewConflictError("Invalid provider or client type")
	}

	return c.AuthCodeURL(state.ToBase64()), nil
}

func (s *oauthStrategyFacadeImpl) ExchangeCode(provider domain.OAuthProvider, clientType domain.ClientType, code string) (domain.OAuthUser, error) {
	c := s.getClient(provider, clientType)
	if c == nil {
		return domain.OAuthUser{}, domain.NewConflictError("Invalid provider or client type")
	}

	ctx := context.Background()
	token, err := c.Exchange(ctx, code)
	if err != nil {
		return domain.OAuthUser{}, domain.NewUnauthorizedError(fmt.Sprintf("%s exchange failed: %v", provider, err))
	}

	client := c.Client(ctx, token)

	switch provider {
	case domain.OAuthProviderGitHub:
		return s.fetchGitHubUser(client)
	case domain.OAuthProviderGoogle:
		return s.fetchGoogleUser(client)
	default:
		return domain.OAuthUser{}, domain.NewConflictError("Unsupported provider")
	}
}

func (s *oauthStrategyFacadeImpl) getClient(provider domain.OAuthProvider, clientType domain.ClientType) *oauth2.Config {
	switch provider {
	case domain.OAuthProviderGitHub:
		if clientType == domain.ClientTypeCli {
			return s.githubCli
		}
		return s.githubWeb
	case domain.OAuthProviderGoogle:
		if clientType == domain.ClientTypeCli {
			return s.googleCli
		}
		return s.googleWeb
	default:
		return nil
	}
}

func (s *oauthStrategyFacadeImpl) fetchGitHubUser(client *http.Client) (domain.OAuthUser, error) {
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		return domain.OAuthUser{}, domain.NewInternalError(fmt.Sprintf("Failed to fetch GitHub user: %v", err))
	}
	defer resp.Body.Close()

	var u githubUser
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return domain.OAuthUser{}, domain.NewInternalError(fmt.Sprintf("Failed to parse GitHub user: %v", err))
	}

	email := u.Email
	if email == "" {
		// Fetch emails if not available in profile
		emailsResp, err := client.Get("https://api.github.com/user/emails")
		if err == nil {
			defer emailsResp.Body.Close()
			var emails []githubEmail
			if err := json.NewDecoder(emailsResp.Body).Decode(&emails); err == nil {
				for _, e := range emails {
					if e.Primary && e.Verified {
						email = e.Email
						break
					}
				}
			}
		}
	}

	if email == "" {
		return domain.OAuthUser{}, domain.NewUnauthorizedError("GitHub account has no primary verified email")
	}

	name := u.Name
	if name == "" {
		name = u.Login
	}

	return domain.OAuthUser{
		SID:           fmt.Sprintf("%d", u.ID),
		Email:         email,
		EmailVerified: true,
		Name:          name,
		FirstName:     name,
		LastName:      "",
		AvatarURL:     u.AvatarURL,
	}, nil
}

func (s *oauthStrategyFacadeImpl) fetchGoogleUser(client *http.Client) (domain.OAuthUser, error) {
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		return domain.OAuthUser{}, domain.NewInternalError(fmt.Sprintf("Failed to fetch Google user: %v", err))
	}
	defer resp.Body.Close()

	var u googleUser
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return domain.OAuthUser{}, domain.NewInternalError(fmt.Sprintf("Failed to parse Google user: %v", err))
	}

	name := u.Name
	if name == "" {
		name = u.Email
	}

	return domain.OAuthUser{
		SID:           u.Sub,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Name:          name,
		FirstName:     u.GivenName,
		LastName:      u.FamilyName,
		AvatarURL:     u.Picture,
	}, nil
}
