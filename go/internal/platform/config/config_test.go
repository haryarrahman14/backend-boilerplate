package config

import (
	"fmt"
	"strings"
	"testing"
)

func base() map[string]string {
	return map[string]string{
		"DATABASE_URL":         "postgres://u:p@db:5432/app?sslmode=verify-full",
		"JWT_SECRET":           "a-random-secret-that-is-long-enough-0123",
		"S3_ENDPOINT":          "https://acct.r2.cloudflarestorage.com",
		"S3_ACCESS_KEY_ID":     "k",
		"S3_SECRET_ACCESS_KEY": "s",
		"S3_BUCKET":            "b",
	}
}

func run(env map[string]string) (*Config, error) {
	return load(func(k string) string { return env[k] })
}

func TestProductionRules(t *testing.T) {
	prod := base()
	prod["APP_ENV"], prod["APP_URL"], prod["SMTP_HOST"] = "production", "https://app.example.com", "smtp.example.com"
	if _, err := run(prod); err != nil {
		t.Fatalf("valid production config rejected: %v", err)
	}
	cases := map[string]func(map[string]string){
		"sslmode":           func(e map[string]string) { e["DATABASE_URL"] = "postgres://u:p@db:5432/app" },
		"sslmode (keyword)": func(e map[string]string) { e["DATABASE_URL"] = "host=db dbname=app" },
		"APP_URL":           func(e map[string]string) { e["APP_URL"] = "http://app.example.com" },
		"S3_ENDPOINT":       func(e map[string]string) { e["S3_ENDPOINT"] = "http://minio:9000" },
		"SMTP_HOST":         func(e map[string]string) { e["SMTP_HOST"] = "" },
		"change-me":         func(e map[string]string) { e["JWT_SECRET"] = "change-me-to-a-random-string-of-32-plus" },
	}
	for name, mutate := range cases {
		env := map[string]string{}
		for k, v := range prod {
			env[k] = v
		}
		mutate(env)
		if _, err := run(env); err == nil {
			t.Errorf("production must refuse bad %s", name)
		}
	}
	// keyword DSN with sslmode is fine; sslmode=disable is an explicit operator choice
	for _, dsn := range []string{"host=db dbname=app sslmode=require", "postgres://db/app?sslmode=disable"} {
		prod["DATABASE_URL"] = dsn
		if _, err := run(prod); err != nil {
			t.Errorf("explicit sslmode %q rejected: %v", dsn, err)
		}
	}
	// development keeps the relaxed defaults
	dev := base()
	dev["DATABASE_URL"], dev["S3_ENDPOINT"] = "postgres://localhost/app", "http://localhost:9000"
	if _, err := run(dev); err != nil {
		t.Fatalf("development config rejected: %v", err)
	}
}

func TestStartupRules(t *testing.T) {
	cases := map[string]map[string]string{
		"short JWT_SECRET":   {"JWT_SECRET": strings.Repeat("x", 31)},
		"boolean True":       {"AUTH_REQUIRE_VERIFIED_EMAIL": "True"},
		"boolean 1":          {"AUTH_REQUIRE_VERIFIED_EMAIL": "1"},
		"hops without CIDRs": {"TRUSTED_PROXY_HOPS": "1"},
		"bad CIDR":           {"TRUSTED_PROXY_HOPS": "1", "TRUSTED_PROXY_CIDRS": "10.0.0.1"},
		"wildcard CORS":      {"CORS_ORIGINS": "*"},
	}
	for name, over := range cases {
		env := base()
		for k, v := range over {
			env[k] = v
		}
		if _, err := run(env); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
	env := base()
	env["TRUSTED_PROXY_HOPS"], env["TRUSTED_PROXY_CIDRS"] = "1", "127.0.0.1/32, ::1/128"
	c, err := run(env)
	if err != nil || len(c.TrustedProxyCIDRs) != 2 {
		t.Fatalf("hops with CIDRs: %v", err)
	}
	// JWT_SECRET is used byte for byte, surrounding spaces included
	env = base()
	env["JWT_SECRET"] = "  " + strings.Repeat("s", 32) + "  "
	if c, _ := run(env); c == nil || c.JWTSecret.Reveal() != env["JWT_SECRET"] {
		t.Fatal("JWT_SECRET must not be trimmed")
	}
}

func TestSecretsDoNotPrint(t *testing.T) {
	c, err := run(base())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"%v", "%+v", "%#v", "%s"} {
		out := fmt.Sprintf(f, c)
		for _, secret := range []string{"a-random-secret", "u:p@db"} {
			if strings.Contains(out, secret) {
				t.Errorf("%s leaks %q: %s", f, secret, out)
			}
		}
	}
}
