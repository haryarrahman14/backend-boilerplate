package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"

	"boilerplate/internal/platform/httpx"
)

// ---------- passwords: argon2id, PHC string ----------

const (
	argonMemory  = 19456 // KiB
	argonTime    = 2
	argonThreads = 1
	argonSaltLen = 16
	argonKeyLen  = 32
)

// ErrBusy is returned when no argon2 slot frees up in time; it renders as 429 + Retry-After: 1.
var ErrBusy = &httpx.Error{Status: http.StatusTooManyRequests, Code: "rate_limited", Message: "Server busy, try again shortly.", RetryAfter: 1}

// gate bounds concurrent argon2 runs (each takes 19 MiB and a core) and the queue in front of them.
type gate struct {
	slots   chan struct{}
	waiting atomic.Int64
	maxWait int64
}

func newGate(slots int) *gate {
	return &gate{slots: make(chan struct{}, slots), maxWait: int64(4 * slots)}
}

// acquire takes a slot, waiting only while ctx is live and at most maxWait callers are waiting.
func (g *gate) acquire(ctx context.Context) error {
	select {
	case g.slots <- struct{}{}:
		return nil
	default:
	}
	if g.waiting.Add(1) > g.maxWait {
		g.waiting.Add(-1)
		return ErrBusy
	}
	defer g.waiting.Add(-1)
	select {
	case g.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ErrBusy
	}
}

func (g *gate) release() { <-g.slots }

var argon = newGate(runtime.NumCPU())

// idKey holds its slot for the whole hash: cancellation only ever stops the wait, never a running hash.
func idKey(ctx context.Context, password, salt []byte, t, m uint32, p uint8, keyLen uint32) ([]byte, error) {
	if err := argon.acquire(ctx); err != nil {
		return nil, err
	}
	defer argon.release()
	return argon2.IDKey(password, salt, t, m, p, keyLen), nil
}

func HashPassword(ctx context.Context, password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := idKey(ctx, []byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	if err != nil {
		return "", err
	}
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// VerifyPassword checks password against a PHC string, using the parameters stored in it.
// A malformed hash simply fails verification; err is only ErrBusy.
func VerifyPassword(ctx context.Context, encoded, password string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return false, nil
	}
	var version int
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, nil
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false, nil
	}
	// Bound the cost so a corrupted row cannot make one verify take minutes or gigabytes.
	if m < 8 || m > 1<<20 || t < 1 || t > 16 || p < 1 || p > 16 {
		return false, nil
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return false, nil
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil || len(want) < 16 || len(want) > 128 {
		return false, nil
	}
	got, err := idKey(ctx, []byte(password), salt, t, m, p, uint32(len(want)))
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// ---------- opaque tokens: refresh secrets and one-time tokens ----------

// NewSecret returns 32 CSPRNG bytes, base64url without padding (43 chars).
func NewSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashSecret is the sha256 hex stored in the DB in place of the secret.
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// HashesEqual compares two hex hashes in constant time.
func HashesEqual(a, b string) bool { return hmac.Equal([]byte(a), []byte(b)) }

var errMalformedToken = errors.New("malformed token")

func FormatRefreshToken(sessionID uuid.UUID, secret string) string {
	return sessionID.String() + "." + secret
}

var secretPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// ParseRefreshToken accepts exactly "<canonical 36-char lowercase uuid>.<43 base64url chars>" (SPEC 4).
func ParseRefreshToken(token string) (uuid.UUID, string, error) {
	sid, secret, ok := strings.Cut(token, ".")
	if !ok || !secretPattern.MatchString(secret) {
		return uuid.Nil, "", errMalformedToken
	}
	id, err := uuid.Parse(sid)
	if err != nil || id.String() != sid {
		return uuid.Nil, "", errMalformedToken
	}
	return id, secret, nil
}

// ---------- access tokens: JWT HS256 ----------

type accessClaims struct {
	SessionID string `json:"sid"`
	jwt.RegisteredClaims
}

func IssueAccessToken(secret []byte, userID, sessionID uuid.UUID, now time.Time, ttl time.Duration) (string, error) {
	now = now.Truncate(time.Second)
	claims := accessClaims{
		SessionID: sessionID.String(),
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
}

// ParseAccessToken pins HS256 (so `none` and every other alg are rejected), requires exp,
// and requires sub and sid to be UUIDs. iat is informational and not validated (SPEC 4).
func ParseAccessToken(secret []byte, token string, now time.Time) (userID, sessionID uuid.UUID, err error) {
	var claims accessClaims
	_, err = jwt.ParseWithClaims(token, &claims,
		func(t *jwt.Token) (any, error) {
			if t.Method != jwt.SigningMethodHS256 {
				return nil, errors.New("unexpected signing method")
			}
			return secret, nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(func() time.Time { return now }),
	)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	if userID, err = uuid.Parse(claims.Subject); err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	if sessionID, err = uuid.Parse(claims.SessionID); err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	return userID, sessionID, nil
}
