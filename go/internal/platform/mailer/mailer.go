// Package mailer sends plain-text email over SMTP, or logs it when SMTP_HOST is empty.
package mailer

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

type Mailer struct {
	host, user, pass, from string
	port                   int
	production             bool
}

func New(host string, port int, user, pass, from string, production bool) *Mailer {
	return &Mailer{host: host, port: port, user: user, pass: pass, from: from, production: production}
}

const timeout = 10 * time.Second // SPEC 2: connect and send

// Send delivers one message. `to` must already be a validated address (no CR/LF).
// Port 465 is implicit TLS; any other port upgrades with STARTTLS (server name verified),
// which is mandatory in production and opportunistic in development.
func (m *Mailer) Send(ctx context.Context, log *slog.Logger, to, subject, body string) error {
	if m.host == "" {
		// Dev-only path (production refuses to start without SMTP_HOST): the body, which
		// holds the one-time link, is logged instead of sent.
		log.Info("email (SMTP_HOST empty, not sent)", "to", to, "subject", subject, "body", body)
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	addr := net.JoinHostPort(m.host, strconv.Itoa(m.port))
	tlsCfg := &tls.Config{ServerName: m.host, MinVersion: tls.VersionTLS12}
	var conn net.Conn
	var err error
	if m.port == 465 {
		conn, err = (&tls.Dialer{NetDialer: &net.Dialer{}, Config: tlsCfg}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)

	c, err := smtp.NewClient(conn, m.host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp handshake: %w", err)
	}
	defer c.Close()
	if m.port != 465 {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(tlsCfg); err != nil {
				return fmt.Errorf("smtp starttls: %w", err)
			}
		} else if m.production {
			return errors.New("smtp: server does not offer STARTTLS; refusing to send in plaintext in production")
		}
	}
	if m.user != "" {
		// PlainAuth refuses to send credentials over an unencrypted non-localhost connection.
		if err := c.Auth(smtp.PlainAuth("", m.user, m.pass, m.host)); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := c.Mail(m.from); err != nil {
		return fmt.Errorf("smtp MAIL FROM: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("smtp RCPT TO: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	if _, err := w.Write(m.message(to, subject, body)); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp end of data: %w", err)
	}
	return c.Quit()
}

func (m *Mailer) message(to, subject, body string) []byte {
	id := make([]byte, 12)
	_, _ = rand.Read(id)
	domain := m.from[strings.LastIndex(m.from, "@")+1:]
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", m.from)
	fmt.Fprintf(&b, "To: %s\r\n", to)
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Message-ID: <%s@%s>\r\n", hex.EncodeToString(id), domain)
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n")
	b.WriteString(strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n"))
	return []byte(b.String())
}
