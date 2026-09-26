package email

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"time"
)

// Service is a simple SMTP email sender. All SMTP config is read from env vars at send time
// so the struct itself is stateless and safe to share.
type Service struct{}

// New returns a new email Service.
func New() *Service {
	return &Service{}
}

// stripCRLF removes carriage-return/newline characters so a value can't smuggle
// extra lines into a raw SMTP header block.
func stripCRLF(v string) string {
	v = strings.ReplaceAll(v, "\r", "")
	v = strings.ReplaceAll(v, "\n", "")
	return v
}

// Send sends an HTML email. It prefers routing through vsay-auth (so SMTP creds live in
// ONE place): if AUTH_EMAIL_URL is set, it POSTs to vsay-auth's /internal/send-email
// with the shared gateway token. Otherwise it falls back to sending SMTP directly
// (and skips silently if SMTP_USERNAME is unset).
func (s *Service) Send(to, subject, htmlBody string) error {
	// Subject/to/from are interpolated directly into raw header lines below, and
	// subject in particular can carry user-controlled data (e.g. a machine name
	// the user picked). Strip CR/LF so nobody can smuggle extra headers (e.g. a
	// "Bcc:" line) via SMTP header injection.
	to = stripCRLF(to)
	subject = stripCRLF(subject)
	// Preferred path: forward to vsay-auth's SMTP.
	if authURL := os.Getenv("AUTH_EMAIL_URL"); authURL != "" {
		return s.sendViaAuth(authURL, []string{to}, subject, htmlBody)
	}

	host := os.Getenv("SMTP_HOST")
	if host == "" {
		host = "smtp.gmail.com"
	}
	port := os.Getenv("SMTP_PORT")
	if port == "" {
		port = "587"
	}
	username := os.Getenv("SMTP_USERNAME")
	if username == "" {
		log.Printf("email: SMTP_USERNAME not set, skipping email to %s (subject: %s)", to, subject)
		return nil
	}
	password := os.Getenv("SMTP_PASSWORD")
	from := os.Getenv("SMTP_FROM")
	if from == "" {
		from = "noreply@vsay.com"
	}

	auth := smtp.PlainAuth("", username, password, host)

	headers := strings.Join([]string{
		"From: " + from,
		"To: " + to,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/html; charset=\"UTF-8\"",
	}, "\r\n")

	body := headers + "\r\n\r\n" + htmlBody

	addr := host + ":" + port
	if err := smtp.SendMail(addr, auth, from, []string{to}, []byte(body)); err != nil { // #nosec G707 -- to/subject are CRLF-stripped above (stripCRLF); gosec's taint tracker doesn't see through the helper
		return fmt.Errorf("email: send failed: %w", err)
	}
	return nil
}

// sendViaAuth POSTs the email to vsay-auth's internal endpoint, which owns the SMTP
// config. Authenticated with the shared gateway secret.
// url is always AUTH_EMAIL_URL, a deployment-time env var — never derived from a
// request — so this is not an attacker-reachable SSRF sink despite the taint warning.
func (s *Service) sendViaAuth(url string, to []string, subject, htmlBody string) error {
	payload, _ := json.Marshal(map[string]interface{}{
		"to":      to,
		"subject": subject,
		"html":    htmlBody,
	})
	req, err := http.NewRequest("POST", url, bytes.NewReader(payload)) // #nosec G704 -- url is AUTH_EMAIL_URL env var, not request-derived
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Gateway-Token", os.Getenv("GATEWAY_SECRET"))

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req) // #nosec G704 -- same req built from AUTH_EMAIL_URL above, not request-derived
	if err != nil {
		return fmt.Errorf("email: forward to vsay-auth failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("email: vsay-auth returned %d", resp.StatusCode)
	}
	return nil
}

// SendIntrusionAlert warns that someone logged into the machine directly (SSH/RDP),
// bypassing the vsay portal. Sent to every recipient in `to`.
func (s *Service) SendIntrusionAlert(to []string, machineName, protocol, osUser, sourceIP string, loginAt time.Time) error {
	if len(to) == 0 {
		return nil
	}
	subject := fmt.Sprintf("⚠️ Direct %s login detected on %s", strings.ToUpper(protocol), machineName)
	body := fmt.Sprintf(`
		<div style="font-family:system-ui,Segoe UI,Arial,sans-serif;max-width:560px;margin:0 auto">
		  <div style="background:#b91c1c;color:#fff;padding:16px 20px;border-radius:10px 10px 0 0">
		    <h2 style="margin:0;font-size:18px">⚠️ Direct access detected</h2>
		  </div>
		  <div style="border:1px solid #eee;border-top:none;padding:20px;border-radius:0 0 10px 10px;color:#111">
		    <p>Someone connected to <strong>%s</strong> directly over <strong>%s</strong> — outside the vsay portal.</p>
		    <table style="width:100%%;border-collapse:collapse;font-size:14px;margin:12px 0">
		      <tr><td style="padding:6px 0;color:#666">Machine</td><td style="padding:6px 0"><strong>%s</strong></td></tr>
		      <tr><td style="padding:6px 0;color:#666">Protocol</td><td style="padding:6px 0">%s</td></tr>
		      <tr><td style="padding:6px 0;color:#666">Account</td><td style="padding:6px 0">%s</td></tr>
		      <tr><td style="padding:6px 0;color:#666">From IP</td><td style="padding:6px 0">%s</td></tr>
		      <tr><td style="padding:6px 0;color:#666">Time</td><td style="padding:6px 0">%s</td></tr>
		    </table>
		    <p style="color:#666;font-size:13px">If this was you or your team, no action is needed. Otherwise, review the machine's access history in the vsay portal immediately.</p>
		  </div>
		</div>`,
		machineName, strings.ToUpper(protocol), machineName, strings.ToUpper(protocol),
		osUser, sourceIP, loginAt.UTC().Format("2006-01-02 15:04:05 MST"))

	var firstErr error
	for _, addr := range to {
		if addr == "" {
			continue
		}
		if err := s.Send(addr, subject, body); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// SendAccessRequestNotification notifies the machine owner about a new access request.
func (s *Service) SendAccessRequestNotification(ownerEmail, ownerName, requesterName, machineName string, durationHours int, note string) error {
	subject := fmt.Sprintf("New Machine Access Request - %s", machineName)

	noteSection := ""
	if note != "" {
		noteSection = fmt.Sprintf(`<p><strong>Note from requester:</strong><br>%s</p>`, note)
	}

	body := fmt.Sprintf(`<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; color: #333;">
  <h2>New Machine Access Request</h2>
  <p>Hello %s,</p>
  <p><strong>%s</strong> has requested access to your machine <strong>%s</strong>.</p>
  <p><strong>Requested duration:</strong> %d hour(s)</p>
  %s
  <p>Please log in to the VSay portal to approve or reject this request.</p>
  <hr>
  <p style="color:#888;font-size:12px;">This is an automated notification from VSay.</p>
</body>
</html>`, ownerName, requesterName, machineName, durationHours, noteSection)

	return s.Send(ownerEmail, subject, body)
}

// SendAccessRequestDecision notifies the requester of an approval or rejection.
func (s *Service) SendAccessRequestDecision(requesterEmail, requesterName, machineName, status, comment string, expiresAt *time.Time) error {
	statusLabel := "Approved"
	if status == "rejected" {
		statusLabel = "Rejected"
	} else if status == "revoked" {
		statusLabel = "Revoked"
	}

	subject := fmt.Sprintf("Machine Access Request %s - %s", statusLabel, machineName)

	var extraSection string
	if status == "approved" && expiresAt != nil {
		extraSection = fmt.Sprintf(`<p><strong>Access expires at:</strong> %s</p>`, expiresAt.UTC().Format("2006-01-02 15:04:05 UTC"))
	}
	if status == "rejected" && comment != "" {
		extraSection = fmt.Sprintf(`<p><strong>Reason:</strong><br>%s</p>`, comment)
	}

	body := fmt.Sprintf(`<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; color: #333;">
  <h2>Machine Access Request %s</h2>
  <p>Hello %s,</p>
  <p>Your access request for machine <strong>%s</strong> has been <strong>%s</strong>.</p>
  %s
  <p>Please log in to the VSay portal for more details.</p>
  <hr>
  <p style="color:#888;font-size:12px;">This is an automated notification from VSay.</p>
</body>
</html>`, statusLabel, requesterName, machineName, strings.ToLower(statusLabel), extraSection)

	return s.Send(requesterEmail, subject, body)
}
