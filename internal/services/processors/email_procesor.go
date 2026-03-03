package processors

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"sync"

	"github.com/vayload/plug-registry/pkg/email"
	"github.com/vayload/plug-registry/pkg/queue"
)

type EmailProcessorConfig struct {
	BaseURL string
	AppName string
}

type EmailProcessor struct {
	email email.Client
	cfg   EmailProcessorConfig
}

func NewEmailProcessor(email email.Client, cfg EmailProcessorConfig) *EmailProcessor {
	return &EmailProcessor{email: email, cfg: cfg}
}

var (
	baseOnce sync.Once
	baseTmpl *template.Template
)

func (p *EmailProcessor) getBaseTemplate() (*template.Template, error) {
	var err error
	baseOnce.Do(func() {
		baseTmpl, err = template.New("base").Parse(baseTemplate)
	})
	return baseTmpl, err
}

func (p *EmailProcessor) renderEmail(contentTemplate string, data any) (string, error) {
	base, err := p.getBaseTemplate()
	if err != nil {
		return "", err
	}

	tmpl, err := base.Clone()
	if err != nil {
		return "", err
	}

	_, err = tmpl.New("content").Parse(contentTemplate)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "base", data); err != nil {
		return "", err
	}

	return buf.String(), nil
}

///////////////////////////////////////////////////////////
///////////////////// HANDLERS ////////////////////////////
///////////////////////////////////////////////////////////

func (p *EmailProcessor) HandleEmailVerificationJob(ctx context.Context, job queue.Job) error {
	emailAddr := job.Payload["email"].(string)
	token := job.Payload["token"].(string)

	url := fmt.Sprintf("%s/verify-email?token=%s", p.cfg.BaseURL, token)

	body, err := p.renderEmail(`
	{{define "content"}}
	<h1 style="color:#FFFFFF;">Hey {{.Username}}, Verify your email</h1>
	<p style="color:#CCCCCC;">
		Click the button below to verify your email address.
	</p>
	<p>
		<a href="{{.URL}}" style="background:#FF6B00;color:#000;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:bold;">
			Verify Email
		</a>
	</p>
	<p style="color:#777;font-size:13px;">
		This link will expire in 15 minutes.
	</p>
	{{end}}
	`, map[string]string{
		"URL":      url,
		"Username": job.Payload["username"].(string),
	})
	if err != nil {
		return err
	}

	attachments := []any{
		map[string]any{
			"path":       "https://vayload.dev/favicon.svg",
			"filename":   "logo.svg",
			"content_id": "vayload-logo",
		},
	}

	return p.email.SendEmail(ctx, emailAddr, "Verify your email - "+p.cfg.AppName, body, attachments)
}

///////////////////////////////////////////////////////////

func (p *EmailProcessor) HandleWelcomeJob(ctx context.Context, job queue.Job) error {
	fmt.Printf("Consuming welcome job")
	emailAddr := job.Payload["email"].(string)
	username := job.Payload["username"].(string)

	body, err := p.renderEmail(`
	{{define "content"}}
	<h1 style="color:#FFFFFF;">Welcome to {{.AppName}}</h1>
	<p style="color:#CCCCCC;">
		Your account has been successfully created in {{.AppName}}.
	</p>
	<p style="color:#CCCCCC;">
		You can now start publishing and managing your plugins.
	</p>
	<p>
		<a href="{{.DashboardURL}}" style="background:#FF6B00;color:#000;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:bold;">
			Go to Dashboard
		</a>
	</p>
	{{end}}
	`, map[string]string{
		"Username":     username,
		"AppName":      p.cfg.AppName,
		"DashboardURL": p.cfg.BaseURL + "/dev",
	})
	if err != nil {
		return err
	}

	attachments := []any{
		map[string]any{
			"path":       "https://vayload.dev/favicon.svg",
			"filename":   "logo.svg",
			"content_id": "vayload-logo",
		},
	}

	return p.email.SendEmail(ctx, emailAddr, "Welcome to "+p.cfg.AppName, body, attachments)
}

///////////////////////////////////////////////////////////

func (p *EmailProcessor) HandlePasswordRecoveryJob(ctx context.Context, job queue.Job) error {
	emailAddr := job.Payload["email"].(string)
	token := job.Payload["token"].(string)

	resetURL := fmt.Sprintf("%s/reset-password?token=%s", p.cfg.BaseURL, token)

	body, err := p.renderEmail(`
	{{define "content"}}
	<h1 style="color:#FFFFFF;">Password recovery</h1>
	<p style="color:#CCCCCC;">
		We received a request to reset your password.
	</p>
	<p>
		<a href="{{.ResetURL}}" style="background:#FF6B00;color:#000;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:bold;">
			Reset Password
		</a>
	</p>
	<p style="color:#777;font-size:13px;">
		If you did not request this change, you can ignore this email.
		The link expires in 1 hour.
	</p>
	{{end}}
	`, map[string]string{
		"ResetURL": resetURL,
	})
	if err != nil {
		return err
	}

	attachments := []any{
		map[string]any{
			"path":       "https://vayload.dev/favicon.svg",
			"filename":   "logo.svg",
			"content_id": "vayload-logo",
		},
	}

	return p.email.SendEmail(ctx, emailAddr, "Password recovery - "+p.cfg.AppName, body, attachments)
}

///////////////////////////////////////////////////////////

func (p *EmailProcessor) HandleEmailChangeJob(ctx context.Context, job queue.Job) error {
	newEmail := job.Payload["new_email"].(string)
	oldEmail := job.Payload["old_email"].(string)
	token := job.Payload["token"].(string)

	confirmURL := fmt.Sprintf("%s/confirm-email-change?token=%s", p.cfg.BaseURL, token)

	body, err := p.renderEmail(`
	{{define "content"}}
	<h1 style="color:#FFFFFF;">Confirm email change</h1>
	<p style="color:#CCCCCC;">
		You are requesting to change your email from <strong>{{.OldEmail}}</strong>
		to <strong>{{.NewEmail}}</strong>.
	</p>
	<p>
		<a href="{{.ConfirmURL}}" style="background:#FF6B00;color:#000;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:bold;">
			Confirm Email Change
		</a>
	</p>
	<p style="color:#777;font-size:13px;">
		If you did not request this change, you can ignore this email.
	</p>
	{{end}}
	`, map[string]string{
		"OldEmail":   oldEmail,
		"NewEmail":   newEmail,
		"ConfirmURL": confirmURL,
	})
	if err != nil {
		return err
	}

	attachments := []any{
		map[string]any{
			"path":       "https://vayload.dev/favicon.svg",
			"filename":   "logo.svg",
			"content_id": "vayload-logo",
		},
	}

	return p.email.SendEmail(ctx, newEmail, "Confirm email change - "+p.cfg.AppName, body, attachments)
}

///////////////////////////////////////////////////////////
//////////////////// HANDLER MAP //////////////////////////
///////////////////////////////////////////////////////////

func (p *EmailProcessor) Handlers() map[queue.JobType]queue.Handler {
	return map[queue.JobType]queue.Handler{
		queue.JobTypeEmailVerification:   p.HandleEmailVerificationJob,
		queue.JobTypeEmailWelcome:        p.HandleWelcomeJob,
		queue.JobTypeEmailPasswordChange: p.HandlePasswordRecoveryJob,
		queue.JobTypeEmailChange:         p.HandleEmailChangeJob,
	}
}

const baseTemplate = `
{{define "base"}}
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Vayload Registry</title>
</head>
<body style="margin:0;padding:0;background-color:#0d1016;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#e8e8e8;">

  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#0d1016;padding:60px 0;">
    <tr>
      <td align="center">

        <table width="600" cellpadding="0" cellspacing="0" style="background-color:#151922;border-radius:12px;padding:48px 42px;box-shadow:0 0 0 1px #1c212c;">
          
          <tr>
            <td align="center" style="padding-bottom:36px;">
              
              <div style="margin-bottom:18px;">
                <svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg" fill="none" stroke="none" width="50" height="50"><g id="SVGRepo_bgCarrier" stroke-width="0"></g><g id="SVGRepo_tracerCarrier" stroke-linecap="round" stroke-linejoin="round"></g><g id="SVGRepo_iconCarrier"><path fill="#FF6347" fill-rule="evenodd" d="M9.02.678a2.25 2.25 0 00-2.04 0L1.682 3.374A1.25 1.25 0 001 4.488v6.717c0 .658.37 1.26.956 1.56l5.023 2.557a2.25 2.25 0 002.042 0l5.023-2.557a1.75 1.75 0 00.956-1.56V4.488c0-.47-.264-.9-.683-1.114L9.021.678zM7.66 2.015a.75.75 0 01.68 0l4.436 2.258-1.468.734-4.805-2.403 1.157-.59zM4.84 3.45l-1.617.823L8 6.661l1.631-.815-4.79-2.396zM2.5 5.588v5.617c0 .094.053.18.137.223l4.613 2.348V7.964L2.5 5.588zm10.863 5.84L8.75 13.776V7.964l4.75-2.375v5.617a.25.25 0 01-.137.223z" clip-rule="evenodd"></path></g></svg>
              </div>

              <h1 style="margin:0;color:#ffffff;font-size:24px;font-weight:600;letter-spacing:0.4px;">
                Vayload Registry
              </h1>

              <p style="margin:10px 0 0 0;color:#8c93a8;font-size:14px;">
                The official plugin registry for Vayload Ecosystem
              </p>
            </td>
          </tr>

          <tr>
            <td style="border-top:1px solid #202634;padding-top:36px;">
				{{template "content" .}}
			</td>
          </tr>

          <tr>
            <td style="padding-bottom:32px;">
              <h2 style="color:#ffffff;margin:0 0 18px 0;font-size:19px;font-weight:600;">
                Extend your CMS with Lua plugins
              </h2>

              <p style="margin:0 0 16px 0;color:#c9cdd6;line-height:1.65;font-size:15px;">
                Vayload Registry powers the plugin ecosystem behind 
                <span style="color:#FF6347;">vayload.dev</span>.
                Discover, install and publish Lua-powered extensions securely.
              </p>

              <p style="margin:0;color:#c9cdd6;line-height:1.65;font-size:15px;">
                Explore the ecosystem at 
                <a href="https://plugins.vayload.dev" style="color:#FF6347;text-decoration:none;">
                  plugins.vayload.dev
                </a>
              </p>
            </td>
          </tr>

          <tr>
            <td align="center" style="padding-bottom:40px;">
              <a href="https://plugins.vayload.dev"
                 style="background-color:#FF6347;
                        color:#111111;
                        padding:12px 26px;
                        text-decoration:none;
                        font-weight:600;
                        border-radius:6px;
                        display:inline-block;
                        font-size:13px;
                        letter-spacing:0.4px;">
                Browse Plugins
              </a>
            </td>
          </tr>

          <tr>
            <td style="padding-bottom:24px;">
              <p style="margin:0 0 6px 0;color:#8c93a8;font-size:13px;">
                Build your own plugin for Vayload
              </p>

              <a href="https://plugins.vayload.dev/docs"
                 style="color:#b5bccf;text-decoration:none;font-size:13px;">
                Read the documentation →
              </a>
            </td>
          </tr>

          <tr>
            <td style="border-top:1px solid #202634;padding-top:28px;text-align:center;">

              <div style="margin-bottom:14px; width: 100%; text-align: center;">
                <img src="cid:vayload-logo" width="36" height="36"/>
              </div>

              <p style="margin:0;color:#8c93a8;font-size:12px;">
                © 2026 Vayload Registry. All rights reserved.
              </p>

              <p style="margin:8px 0 0 0;color:#6e768a;font-size:12px;line-height:1.6;">
                Automated message from plugins.vayload.dev.<br>
                Please do not reply to this email.
              </p>

              <p style="margin:14px 0 0 0;font-size:12px;">
                <a href="https://vayload.dev" style="color:#FF6347;text-decoration:none;">
                  vayload.dev
                </a>
              </p>

            </td>
          </tr>

        </table>

      </td>
    </tr>
  </table>

</body>
</html>
{{end}}
`
