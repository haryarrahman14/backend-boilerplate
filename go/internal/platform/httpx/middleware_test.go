package httpx

import (
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestClientIP(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("::1/128"), netip.MustParsePrefix("192.0.2.0/24")}
	cases := []struct {
		name, remote string
		xff          []string
		hops         int
		want         string
	}{
		{"hops 0 ignores XFF", "10.0.0.1:5000", []string{"1.1.1.1"}, 0, "10.0.0.1"},
		{"one hop takes right-most", "10.0.0.1:5000", []string{"6.6.6.6, 203.0.113.9"}, 1, "203.0.113.9"},
		{"two hops", "10.0.0.1:5000", []string{"6.6.6.6, 203.0.113.9, 10.0.0.2"}, 2, "203.0.113.9"},
		{"multiple headers are one list", "10.0.0.1:5000", []string{"6.6.6.6", "203.0.113.9"}, 1, "203.0.113.9"},
		{"invalid entry falls back to peer", "10.0.0.1:5000", []string{"not-an-ip"}, 1, "10.0.0.1"},
		{"missing entry falls back to peer", "10.0.0.1:5000", []string{"203.0.113.9"}, 2, "10.0.0.1"},
		{"no header falls back to peer", "[::1]:5000", nil, 1, "::1"},
		{"IPv4-mapped peer shown as IPv4", "[::ffff:192.0.2.7]:5000", nil, 0, "192.0.2.7"},
		{"IPv4-mapped forwarded shown as IPv4", "10.0.0.1:5000", []string{"::ffff:192.0.2.8"}, 1, "192.0.2.8"},
		{"IPv6 normalised", "10.0.0.1:5000", []string{"2001:DB8:0:0::1"}, 1, "2001:db8::1"},
		{"untrusted peer: XFF ignored", "198.51.100.4:5000", []string{"203.0.113.9"}, 1, "198.51.100.4"},
		{"IPv4-mapped trusted peer still trusted", "[::ffff:10.0.0.1]:5000", []string{"203.0.113.9"}, 1, "203.0.113.9"},
		{"non-ASCII header split per entry", "10.0.0.1:5000", []string{"\u00e9vil, 203.0.113.9"}, 1, "203.0.113.9"},
		{"non-IP peer is empty (NULL)", "@unix", nil, 0, ""},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remote
		for _, v := range c.xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		if got := clientIP(r, c.hops, trusted); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestHasLoneSurrogate(t *testing.T) {
	for in, want := range map[string]bool{
		`{"a":"\ud800"}`:   true,
		`{"a":"x\udc00y"}`: true,
		`{"a":"\ud800A"}`:  true,
		`{"a":"😀"}`:        false,
		`{"a":"\\ud800"}`:  false, // escaped backslash, literal text
		`{"\ud800":1}`:     true,
		`{"a":"plain é"}`:  false,
	} {
		if got := hasLoneSurrogate([]byte(in)); got != want {
			t.Errorf("%s: got %v, want %v", in, got, want)
		}
	}
}
