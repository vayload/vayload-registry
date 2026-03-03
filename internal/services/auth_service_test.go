package services

import (
	"context"
	"testing"
	"time"

	"github.com/vayload/plug-registry/internal/domain"
	"github.com/vayload/plug-registry/internal/infrastructure/security"
	"github.com/vayload/plug-registry/pkg/queue"
)

// MockUserRepository
type MockUserRepository struct {
	domain.UserRepository
	OnGetByEmail         func(email string) (*domain.User, error)
	OnGetByUsername      func(username string) (*domain.User, error)
	OnCreate             func(user domain.User) (domain.User, error)
	OnUpdateLastLogin    func(id domain.UserID, at time.Time) error
	OnCreateRefreshToken func(token *domain.RefreshToken) error
}

var _ domain.UserRepository = (*MockUserRepository)(nil)

func (m *MockUserRepository) FindUserBy(ctx context.Context, filter domain.UserFilterBy) (*domain.User, error) {
	if m.OnGetByEmail != nil && filter.Email != nil {
		return m.OnGetByEmail(filter.Email.String())
	}
	if m.OnGetByUsername != nil && filter.Username != nil {
		return m.OnGetByUsername(filter.Username.String())
	}
	return nil, nil
}

func (m *MockUserRepository) CreateUnverifiedUser(ctx context.Context, user domain.User, unverifiedToken domain.UnverifiedToken) (domain.User, error) {
	if m.OnCreate != nil {
		return m.OnCreate(user)
	}
	return user, nil
}

func (m *MockUserRepository) UpdateLastLogin(ctx context.Context, id domain.UserID, at time.Time) error {
	if m.OnUpdateLastLogin != nil {
		return m.OnUpdateLastLogin(id, at)
	}
	return nil
}

func (m *MockUserRepository) CreateRefreshToken(ctx context.Context, token *domain.RefreshToken) error {
	if m.OnCreateRefreshToken != nil {
		return m.OnCreateRefreshToken(token)
	}
	return nil
}

// MockHashingStrategy
type MockHashingStrategy struct {
	domain.HashingStrategy
}

func (m *MockHashingStrategy) Hash(password string) (string, error) {
	return "hashed_" + password, nil
}

func (m *MockHashingStrategy) Verify(password, hash string) bool {
	return hash == "hashed_"+password
}

// MockTokenManager
type MockTokenManager struct {
	domain.TokenManager
}

func (m *MockTokenManager) Sign(payload domain.TokenPayload) (domain.AuthToken, error) {
	return domain.AuthToken{
		AccessToken:  "access_token",
		RefreshToken: "refresh_token",
	}, nil
}

// MockApiTokenRepository
type MockApiTokenRepository struct {
	domain.ApiTokenRepository
}

// MockProducer
type MockProducer struct {
	Published []queue.Job
}

func (m *MockProducer) Publish(ctx context.Context, job queue.Job) error {
	m.Published = append(m.Published, job)
	return nil
}

func TestAuthService_Register(t *testing.T) {
	// Prepare
	username, _ := domain.NewUsername("testuser")
	email, _ := domain.NewEmail("test@example.com")
	password, _ := domain.NewPasswordHash("password123")

	users := []domain.User{
		{
			Email:    domain.Email(email),
			Username: domain.Username(username),
		},
	}

	// Mock dependencies
	mockRepo := &MockUserRepository{
		OnGetByEmail: func(email string) (*domain.User, error) {
			for _, user := range users {
				if user.Email.String() == email {
					return &user, nil
				}
			}
			return nil, nil
		},
		OnCreate: func(user domain.User) (domain.User, error) {
			users = append(users, user)
			return user, nil
		},
	}
	mockHashing := &MockHashingStrategy{}
	mockJWT := &MockTokenManager{}
	mockProducer := &MockProducer{}

	service := NewAuthService(
		mockRepo,
		&MockApiTokenRepository{}, // tokenRepo
		mockHashing,
		nil, // oauth
		mockJWT,
		security.NewVerificationTokenManager("test-secret"), // verifier
		mockProducer,
	)

	// The same user should not be able to register again
	err := service.Register(context.Background(), username, email, password, TransportMeta{})

	if err == nil {
		t.Fatalf("Expected error, got nil")
	}

	// Create with another username and email
	username2, _ := domain.NewUsername("testuser2")
	email2, _ := domain.NewEmail("test2@example.com")
	err = service.Register(context.Background(), username2, email2, password, TransportMeta{})

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

func TestAuthService_Login(t *testing.T) {
	mockRepo := &MockUserRepository{}
	mockHashing := &MockHashingStrategy{}
	mockJWT := &MockTokenManager{}

	hashedPassword := "hashed_password123"
	userID := domain.NewUserID()
	email, _ := domain.NewEmail("test@example.com")
	username, _ := domain.NewUsername("testuser")

	existingUser := domain.NewUser(userID, username, email, domain.AuthProviderPassword, userID.String())
	ph := domain.PasswordHash(hashedPassword)
	existingUser.SetPassword(ph)

	mockRepo.OnGetByEmail = func(email string) (*domain.User, error) {
		return existingUser, nil
	}

	service := NewAuthService(
		mockRepo,
		&MockApiTokenRepository{}, // tokenRepo
		mockHashing,
		nil, // oauth
		mockJWT,
		security.NewVerificationTokenManager("test-secret"), // verifier
		nil, // producer
	)

	user, token, err := service.LoginWithPassword(context.Background(), "test@example.com", "password123", TransportMeta{})

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if user.ID != userID {
		t.Errorf("Expected user ID %s, got %s", userID, user.ID)
	}

	if token.AccessToken != "access_token" {
		t.Error("Expected access token")
	}
}
