package processors

import (
	"context"
	"strings"
	"testing"

	"github.com/vayload/plug-registry/pkg/queue"
)

type MockEmailClient struct {
	To      string
	Subject string
	Body    string
	Err     error
}

func (m *MockEmailClient) SendEmail(ctx context.Context, to, subject, body string, attachments []any) error {
	m.To = to
	m.Subject = subject
	m.Body = body
	return m.Err
}

func TestEmailProcessor_HandleEmailVerificationJob(t *testing.T) {
	mockEmail := &MockEmailClient{}
	cfg := EmailProcessorConfig{
		BaseURL: "https://test.vayload.dev",
		AppName: "Test Registry",
	}
	processor := NewEmailProcessor(mockEmail, cfg)

	job := queue.Job{
		Payload: map[string]any{
			"email":    "user@example.com",
			"token":    "verify-token-123",
			"username": "testuser",
		},
	}

	err := processor.HandleEmailVerificationJob(context.Background(), job)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if mockEmail.To != "user@example.com" {
		t.Errorf("Expected recipient user@example.com, got %s", mockEmail.To)
	}

	if !strings.Contains(mockEmail.Subject, "Verify your email") {
		t.Errorf("Subject does not contain expected text: %s", mockEmail.Subject)
	}

	if !strings.Contains(mockEmail.Body, "verify-token-123") {
		t.Error("Body does not contain verification token")
	}
}

func TestEmailProcessor_HandleWelcomeJob(t *testing.T) {
	mockEmail := &MockEmailClient{}
	cfg := EmailProcessorConfig{
		BaseURL: "https://test.vayload.dev",
		AppName: "Test Registry",
	}
	processor := NewEmailProcessor(mockEmail, cfg)

	job := queue.Job{
		Payload: map[string]any{
			"email":    "user@example.com",
			"username": "testuser",
		},
	}

	err := processor.HandleWelcomeJob(context.Background(), job)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if mockEmail.To != "user@example.com" {
		t.Errorf("Expected recipient user@example.com, got %s", mockEmail.To)
	}

	if !strings.Contains(mockEmail.Subject, "Welcome to Test Registry") {
		t.Errorf("Subject does not contain expected text: %s", mockEmail.Subject)
	}

	if !strings.Contains(mockEmail.Body, "Welcome to Test Registry") {
		t.Error("Body does not contain welcome message")
	}
}

func TestEmailProcessor_HandlePasswordRecoveryJob(t *testing.T) {
	mockEmail := &MockEmailClient{}
	cfg := EmailProcessorConfig{
		BaseURL: "https://test.vayload.dev",
		AppName: "Test Registry",
	}
	processor := NewEmailProcessor(mockEmail, cfg)

	job := queue.Job{
		Payload: map[string]any{
			"email": "user@example.com",
			"token": "reset-token-456",
		},
	}

	err := processor.HandlePasswordRecoveryJob(context.Background(), job)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if !strings.Contains(mockEmail.Body, "reset-token-456") {
		t.Error("Body does not contain reset token")
	}
}

func TestEmailProcessor_HandleEmailChangeJob(t *testing.T) {
	mockEmail := &MockEmailClient{}
	cfg := EmailProcessorConfig{
		BaseURL: "https://test.vayload.dev",
		AppName: "Test Registry",
	}
	processor := NewEmailProcessor(mockEmail, cfg)

	job := queue.Job{
		Payload: map[string]any{
			"new_email": "new@example.com",
			"old_email": "old@example.com",
			"token":     "change-token-789",
		},
	}

	err := processor.HandleEmailChangeJob(context.Background(), job)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if mockEmail.To != "new@example.com" {
		t.Errorf("Expected recipient new@example.com, got %s", mockEmail.To)
	}

	if !strings.Contains(mockEmail.Body, "old@example.com") {
		t.Error("Body does not contain old email")
	}

	if !strings.Contains(mockEmail.Body, "change-token-789") {
		t.Error("Body does not contain change token")
	}
}
