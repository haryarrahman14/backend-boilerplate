// Package config parses and validates every env var once at startup (SPEC section 2).
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Secret is a config value that never prints itself: fmt (%v, %+v, %#v), slog and JSON
// all see "[redacted]". Call Reveal to use it.
type Secret string

func (s Secret) Reveal() string             { return string(s) }
func (Secret) String() string               { return "[redacted]" }
func (Secret) GoString() string             { return `"[redacted]"` }
func (Secret) LogValue() slog.Value         { return slog.StringValue("[redacted]") }
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"[redacted]"`), nil }

type Config struct {
	Port        int
	AppEnv      string
	AppURL      string
	DatabaseURL Secret

	JWTSecret                Secret
	AccessTokenTTL           time.Duration
	RefreshTokenTTL          time.Duration
	AuthRequireVerifiedEmail bool
	RateLimitAuthPerMinute   int
	TrustedProxyHops         int
	TrustedProxyCIDRs        []netip.Prefix
	EmailTokenCooldown       time.Duration
	CORSOrigins              []string

	SMTPHost string
	SMTPPort int
	SMTPUser string
	SMTPPass Secret
	MailFrom string

	S3Endpoint        string
	S3Region          string
	S3AccessKeyID     string
	S3SecretAccessKey Secret
	S3Bucket          string

	UploadMaxBytes     int64
	UploadAllowedTypes []string
}

func (c *Config) Production() bool { return c.AppEnv == "production" }

// Load reads the process environment. It reports every problem at once.
func Load() (*Config, error) { return load(os.Getenv) }

// LoadDatabaseURL is all the migrate command needs.
func LoadDatabaseURL() (string, error) {
	if v := strings.TrimSpace(os.Getenv("DATABASE_URL")); v != "" {
		return v, nil
	}
	return "", errors.New("config: DATABASE_URL is required")
}

func load(getenv func(string) string) (*Config, error) {
	p := parser{getenv: getenv}
	c := &Config{
		Port:        p.intRange("PORT", 8080, 1, 65535),
		AppEnv:      p.oneOf("APP_ENV", "development", "development", "production"),
		AppURL:      strings.TrimRight(p.url("APP_URL", "http://localhost:3000", false), "/"),
		DatabaseURL: Secret(p.required("DATABASE_URL")),

		AccessTokenTTL:           time.Duration(p.intRange("ACCESS_TOKEN_TTL_SECONDS", 900, 1, 1<<31)) * time.Second,
		RefreshTokenTTL:          time.Duration(p.intRange("REFRESH_TOKEN_TTL_SECONDS", 2592000, 1, 1<<31)) * time.Second,
		AuthRequireVerifiedEmail: p.bool("AUTH_REQUIRE_VERIFIED_EMAIL", false),
		RateLimitAuthPerMinute:   p.intRange("RATE_LIMIT_AUTH_PER_MINUTE", 10, 1, 1<<31),
		TrustedProxyHops:         p.intRange("TRUSTED_PROXY_HOPS", 0, 0, 32),
		TrustedProxyCIDRs:        p.prefixes("TRUSTED_PROXY_CIDRS"),
		EmailTokenCooldown:       time.Duration(p.intRange("EMAIL_TOKEN_COOLDOWN_SECONDS", 60, 0, 1<<31)) * time.Second,
		CORSOrigins:              p.list("CORS_ORIGINS", "http://localhost:3000"),

		SMTPHost: p.str("SMTP_HOST", ""),
		SMTPPort: p.intRange("SMTP_PORT", 1025, 1, 65535),
		SMTPUser: p.str("SMTP_USER", ""),
		SMTPPass: Secret(p.raw("SMTP_PASS")),
		MailFrom: p.str("MAIL_FROM", "no-reply@example.com"),

		S3Endpoint:        p.url("S3_ENDPOINT", "", true),
		S3Region:          p.str("S3_REGION", "auto"),
		S3AccessKeyID:     p.required("S3_ACCESS_KEY_ID"),
		S3SecretAccessKey: Secret(p.required("S3_SECRET_ACCESS_KEY")),
		S3Bucket:          p.required("S3_BUCKET"),

		UploadMaxBytes:     int64(p.intRange("UPLOAD_MAX_BYTES", 10485760, 1, 1<<62)),
		UploadAllowedTypes: p.list("UPLOAD_ALLOWED_TYPES", "image/jpeg,image/png,image/webp,application/pdf"),
	}

	// Not trimmed: the secret is used byte for byte.
	secret := getenv("JWT_SECRET")
	switch {
	case secret == "":
		p.fail("JWT_SECRET is required")
	case utf8.RuneCountInString(secret) < 32:
		p.fail("JWT_SECRET must be at least 32 characters")
	case c.Production() && strings.Contains(secret, "change-me"):
		p.fail("JWT_SECRET still contains the .env.example placeholder 'change-me'; set a random value in production")
	}
	c.JWTSecret = Secret(secret)

	for _, o := range c.CORSOrigins {
		if o == "*" {
			p.fail("CORS_ORIGINS must list explicit origins, '*' is not allowed with credentials")
		}
	}
	if c.TrustedProxyHops > 0 && len(c.TrustedProxyCIDRs) == 0 {
		p.fail("TRUSTED_PROXY_CIDRS is required when TRUSTED_PROXY_HOPS > 0 (otherwise anyone who can reach the port could forge X-Forwarded-For)")
	}
	if c.Production() {
		if !hasSSLMode(c.DatabaseURL.Reveal()) {
			p.fail("DATABASE_URL must set sslmode explicitly in production (verify-full recommended)")
		}
		if !strings.HasPrefix(c.AppURL, "https://") {
			p.fail("APP_URL must be https:// in production (email links carry one-time tokens)")
		}
		if !strings.HasPrefix(c.S3Endpoint, "https://") {
			p.fail("S3_ENDPOINT must be https:// in production")
		}
	}
	if c.Production() && c.SMTPHost == "" {
		p.fail("SMTP_HOST is required when APP_ENV=production (emails carry one-time tokens and must never be logged there)")
	}
	if c.SMTPUser != "" && c.SMTPHost == "" {
		p.fail("SMTP_USER is set but SMTP_HOST is empty")
	}
	if c.S3Region == "" {
		p.fail("S3_REGION must not be empty")
	}

	if len(p.errs) > 0 {
		return nil, fmt.Errorf("invalid configuration:\n  - %s", strings.Join(p.errs, "\n  - "))
	}
	return c, nil
}

type parser struct {
	getenv func(string) string
	errs   []string
}

func (p *parser) fail(format string, a ...any) { p.errs = append(p.errs, fmt.Sprintf(format, a...)) }

func (p *parser) raw(key string) string { return p.getenv(key) }

func (p *parser) str(key, def string) string {
	if v := strings.TrimSpace(p.getenv(key)); v != "" {
		return v
	}
	return def
}

func (p *parser) required(key string) string {
	v := strings.TrimSpace(p.getenv(key))
	if v == "" {
		p.fail("%s is required", key)
	}
	return v
}

func (p *parser) intRange(key string, def, min, max int) int {
	v := strings.TrimSpace(p.getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min || n > max {
		p.fail("%s must be an integer between %d and %d, got %q", key, min, max, v)
		return def
	}
	return n
}

func (p *parser) bool(key string, def bool) bool {
	v := strings.TrimSpace(p.getenv(key))
	if v == "" {
		return def
	}
	switch v {
	case "true":
		return true
	case "false":
		return false
	}
	p.fail("%s must be exactly true or false, got %q", key, v)
	return def
}

func (p *parser) oneOf(key, def string, allowed ...string) string {
	v := p.str(key, def)
	for _, a := range allowed {
		if v == a {
			return v
		}
	}
	p.fail("%s must be one of %s, got %q", key, strings.Join(allowed, ", "), v)
	return def
}

func (p *parser) url(key, def string, required bool) string {
	v := p.str(key, def)
	if v == "" {
		if required {
			p.fail("%s is required", key)
		}
		return v
	}
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		p.fail("%s must be an absolute http(s) URL, got %q", key, v)
	}
	return v
}

var dsnSSLMode = regexp.MustCompile(`(^|\s)sslmode\s*=\s*\S`)

// hasSSLMode accepts both URL (postgres://...?sslmode=x) and keyword (host=... sslmode=x) DSNs.
// pgx itself honours disable, allow, prefer, require, verify-ca and verify-full.
func hasSSLMode(dsn string) bool {
	if u, err := url.Parse(dsn); err == nil && (u.Scheme == "postgres" || u.Scheme == "postgresql") {
		return u.Query().Get("sslmode") != ""
	}
	return dsnSSLMode.MatchString(dsn)
}

func (p *parser) prefixes(key string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range strings.Split(p.getenv(key), ",") {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		pfx, err := netip.ParsePrefix(s)
		if err != nil {
			p.fail("%s: %q is not a CIDR (e.g. 10.0.0.0/8 or ::1/128)", key, s)
			continue
		}
		out = append(out, pfx.Masked())
	}
	return out
}

func (p *parser) list(key, def string) []string {
	var out []string
	for _, s := range strings.Split(p.str(key, def), ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		p.fail("%s must not be empty", key)
	}
	return out
}
