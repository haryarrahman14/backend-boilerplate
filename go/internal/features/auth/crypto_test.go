package auth

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestPasswordHashVerify(t *testing.T) {
	ctx := context.Background()
	h, err := HashPassword(ctx, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("not a PHC argon2id string with the SPEC params: %s", h)
	}
	if ok, _ := VerifyPassword(ctx, h, "correct horse battery"); !ok {
		t.Fatal("right password rejected")
	}
	if ok, _ := VerifyPassword(ctx, h, "correct horse batterY"); ok {
		t.Fatal("wrong password accepted")
	}
	h2, _ := HashPassword(ctx, "correct horse battery")
	if h == h2 {
		t.Fatal("salt must be random")
	}
	for _, bad := range []string{"", "plain", "$argon2i$v=19$m=19456,t=2,p=1$AAAA$AAAA", strings.Replace(h, "m=19456", "m=99999999", 1)} {
		if ok, _ := VerifyPassword(ctx, bad, "correct horse battery"); ok {
			t.Fatalf("malformed hash %q accepted", bad)
		}
	}
}

func TestSecretAndHash(t *testing.T) {
	s, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(raw) != 32 || len(s) != 43 {
		t.Fatalf("secret %q is not 32 bytes base64url without padding", s)
	}
	s2, _ := NewSecret()
	if s == s2 {
		t.Fatal("secrets must be random")
	}
	// sha256("abc")
	if got := HashSecret("abc"); got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("HashSecret = %s", got)
	}
	if !HashesEqual(HashSecret(s), HashSecret(s)) || HashesEqual(HashSecret(s), HashSecret(s2)) {
		t.Fatal("HashesEqual wrong")
	}
}

func TestRefreshTokenParse(t *testing.T) {
	sid := uuid.New()
	secret, _ := NewSecret()
	tok := FormatRefreshToken(sid, secret)
	gotID, gotSecret, err := ParseRefreshToken(tok)
	if err != nil || gotID != sid || gotSecret != secret {
		t.Fatalf("round trip failed: %v %v %v", gotID, gotSecret, err)
	}
	for _, bad := range []string{
		"", "nope", "a.b", sid.String(), sid.String() + ".",
		"not-a-uuid." + secret,
		sid.String() + "." + secret + ".x",
		sid.String() + "." + secret[:42],             // 31.x bytes
		sid.String() + "." + secret + "=",            // padding
		sid.String() + "." + strings.Repeat("A", 44), // 33 bytes
		strings.ReplaceAll(sid.String(), "-", "") + "." + secret,
		strings.ToUpper(sid.String()) + "." + secret, // not canonical
	} {
		if _, _, err := ParseRefreshToken(bad); err == nil {
			t.Fatalf("accepted malformed refresh token %q", bad)
		}
	}
}

func TestAccessToken(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	uid, sid := uuid.New(), uuid.New()
	now := time.Now()
	tok, err := IssueAccessToken(key, uid, sid, now, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	gotU, gotS, err := ParseAccessToken(key, tok, now)
	if err != nil || gotU != uid || gotS != sid {
		t.Fatalf("parse: %v %v %v", gotU, gotS, err)
	}

	if _, _, err := ParseAccessToken(key, tok, now.Add(16*time.Minute)); err == nil {
		t.Fatal("expired token accepted")
	}
	if _, _, err := ParseAccessToken([]byte(strings.Repeat("x", 32)), tok, now); err == nil {
		t.Fatal("token signed with another key accepted")
	}

	// alg=none with the same claims
	parts := strings.Split(tok, ".")
	none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + parts[1] + "."
	if _, _, err := ParseAccessToken(key, none, now); err == nil {
		t.Fatal("alg=none accepted")
	}

	// HS512 with the right key is still rejected: the algorithm is pinned
	hs512, _ := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": uid.String(), "sid": sid.String(), "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
	}).SignedString(key)
	if _, _, err := ParseAccessToken(key, hs512, now); err == nil {
		t.Fatal("HS512 accepted")
	}

	// exp is required
	noExp, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": uid.String(), "sid": sid.String(), "iat": now.Unix(),
	}).SignedString(key)
	if _, _, err := ParseAccessToken(key, noExp, now); err == nil {
		t.Fatal("token without exp accepted")
	}

	// sid must be a UUID
	badSid, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": uid.String(), "sid": "x", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
	}).SignedString(key)
	if _, _, err := ParseAccessToken(key, badSid, now); err == nil {
		t.Fatal("non-uuid sid accepted")
	}
}

func TestArgonGateWaiterCap(t *testing.T) {
	g := newGate(1)
	if err := g.acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	// 4 waiters fit (4 x 1 slot); they block until released or cancelled.
	ctx, cancel := context.WithCancel(context.Background())
	results := make(chan error, 4)
	for range 4 {
		go func() { results <- g.acquire(ctx) }()
	}
	for g.waiting.Load() != 4 {
		time.Sleep(time.Millisecond)
	}
	if err := g.acquire(context.Background()); err != ErrBusy {
		t.Fatalf("5th waiter must get ErrBusy (429), got %v", err)
	}
	cancel() // waiting stops when the request is cancelled
	for range 4 {
		if err := <-results; err != ErrBusy {
			t.Fatalf("cancelled waiter got %v", err)
		}
	}
	if g.waiting.Load() != 0 || len(g.slots) != 1 {
		t.Fatal("cancelled waiters must not take or free a slot")
	}
	g.release()
	dl, cancel2 := context.WithTimeout(context.Background(), time.Hour)
	defer cancel2()
	if err := g.acquire(dl); err != nil {
		t.Fatalf("free slot must be taken: %v", err)
	}
	if ErrBusy.Status != 429 || ErrBusy.Code != "rate_limited" || ErrBusy.RetryAfter != 1 {
		t.Fatal("ErrBusy must render as 429 rate_limited, Retry-After: 1")
	}
}

func TestReuseDetected(t *testing.T) {
	prev := HashSecret("old")
	other := HashSecret("guess")
	if !reuseDetected(prev, &prev, true) {
		t.Fatal("the genuinely previous token on a live session is reuse")
	}
	if reuseDetected(other, &prev, true) {
		t.Fatal("a never-issued secret must not revoke")
	}
	if reuseDetected(prev, nil, true) {
		t.Fatal("no rotation yet: nothing to detect")
	}
	if reuseDetected(prev, &prev, false) {
		t.Fatal("revoked/expired sessions are left alone")
	}
}

func TestLoginGate(t *testing.T) {
	now := time.Now()
	active := User{EmailVerifiedAt: &now}
	unverified := User{}
	disabled := User{EmailVerifiedAt: &now, DisabledAt: &now}
	disabledUnverified := User{DisabledAt: &now}
	cases := []struct {
		name    string
		u       User
		require bool
		want    error
	}{
		{"active", active, true, nil},
		{"unverified, not required", unverified, false, nil},
		{"unverified, required", unverified, true, errEmailNotVerified},
		{"disabled", disabled, false, errAccountDisabled},
		{"disabled wins over unverified", disabledUnverified, true, errAccountDisabled},
	}
	for _, c := range cases {
		if got := loginGate(c.u, c.require); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
	if errAccountDisabled.Status != 403 || errAccountDisabled.Code != "account_disabled" {
		t.Fatal("account_disabled must be a 403")
	}
}
