package email

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/vayload/plug-registry/pkg/logger"
)

type Client interface {
	SendEmail(ctx context.Context, to, subject, body string, attachments []any) error
}

type resendClient struct {
	apiKey    string
	fromEmail string
}

func NewResendClient(apiKey, fromEmail string) Client {
	return &resendClient{
		apiKey:    apiKey,
		fromEmail: fromEmail,
	}
}

const resendURL = "https://api.resend.com/emails"

func (c *resendClient) SendEmail(ctx context.Context, to, subject, body string, attachments []any) error {
	payload := map[string]any{
		"from":        fmt.Sprintf("%s <%s>", "Vayload Registry", c.fromEmail),
		"to":          []string{to},
		"subject":     subject,
		"html":        body,
		"attachments": attachments,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal email payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", resendURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to create email request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send email via Resend: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var errResp map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&errResp)
		logger.E(fmt.Errorf("resend error: %v", errResp), logger.Fields{"status": resp.StatusCode})
		return fmt.Errorf("resend API returned status %d", resp.StatusCode)
	}

	logger.I("Email sent successfully", logger.Fields{"to": to, "subject": subject})
	return nil
}
