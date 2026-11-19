package auth

import (
	"strings"
	"testing"
)

func TestValidEmail(t *testing.T) {
	good := []string{
		"a@example.com", "first.last+tag@sub.example.co", "o'brien@example.com",
		"x_y-z@a-b.example", "!#$%&'*+/=?^_`{|}~-@example.com",
	}
	bad := []string{
		"", "not-an-email", "a@b", "a@@example.com", "@example.com", "a@",
		"victim<attacker@evil.example>", "Name <a@example.com>", `"a b"@example.com`,
		"a b@example.com", "a@exa_mple.com", "josé@example.com", "a@example..com",
		"a@example.com.", "A@example.com", "a@example.com\r\nBcc: x@y.z", "a\x00@example.com",
		"a@[127.0.0.1]", strings.Repeat("a", 243) + "@example.com",
	}
	for _, e := range good {
		if !ValidEmail(e) {
			t.Errorf("rejected valid %q", e)
		}
	}
	for _, e := range bad {
		if ValidEmail(e) {
			t.Errorf("accepted invalid %q", e)
		}
	}
	if NormalizeEmail("  A@Example.COM ") != "a@example.com" {
		t.Error("normalise must trim and lowercase")
	}
}
