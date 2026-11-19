package auth

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"boilerplate/internal/platform/db"
)

// User is the users row minus the password hash. Shared with the users feature.
type User struct {
	ID              uuid.UUID
	Email           string
	Name            string
	Role            string
	EmailVerifiedAt *time.Time
	DisabledAt      *time.Time
	CreatedAt       time.Time
}

// UserColumns matches ScanUser; userColumnsU is the same list for the alias `u` in joins.
const (
	UserColumns  = "id, email, name, role, email_verified_at, disabled_at, created_at"
	userColumnsU = "u.id, u.email, u.name, u.role, u.email_verified_at, u.disabled_at, u.created_at"
)

func ScanUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Email, &u.Name, &u.Role, &u.EmailVerifiedAt, &u.DisabledAt, &u.CreatedAt)
	return u, err
}

type UserDTO struct {
	ID            uuid.UUID `json:"id"`
	Email         string    `json:"email"`
	Name          string    `json:"name"`
	Role          string    `json:"role"`
	EmailVerified bool      `json:"email_verified"`
	Disabled      bool      `json:"disabled"`
	CreatedAt     time.Time `json:"created_at"`
}

func (u User) DTO() UserDTO {
	return UserDTO{ID: u.ID, Email: u.Email, Name: u.Name, Role: u.Role, EmailVerified: u.EmailVerifiedAt != nil, Disabled: u.DisabledAt != nil, CreatedAt: u.CreatedAt.UTC()}
}

const (
	tokenEmailVerification = "email_verification"
	tokenPasswordReset     = "password_reset"
)

func isNoRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

func secs(d time.Duration) float64 { return d.Seconds() }

// ---------- users ----------

func insertUser(ctx context.Context, q db.DBTX, email, hash, name string) (User, error) {
	return ScanUser(q.QueryRow(ctx,
		`INSERT INTO auth.users (email, password_hash, name) VALUES ($1, $2, $3) RETURNING `+UserColumns,
		email, hash, name))
}

func userWithHashByEmail(ctx context.Context, q db.DBTX, email string) (User, string, error) {
	var u User
	var hash string
	err := q.QueryRow(ctx, `SELECT `+UserColumns+`, password_hash FROM auth.users WHERE email = $1`, email).
		Scan(&u.ID, &u.Email, &u.Name, &u.Role, &u.EmailVerifiedAt, &u.DisabledAt, &u.CreatedAt, &hash)
	return u, hash, err
}

func passwordHash(ctx context.Context, q db.DBTX, userID uuid.UUID) (string, error) {
	var hash string
	err := q.QueryRow(ctx, `SELECT password_hash FROM auth.users WHERE id = $1`, userID).Scan(&hash)
	return hash, err
}

// swapPasswordHash is the SPEC 4 compare-and-swap: it only succeeds if the hash is still the one
// the caller verified and the caller's session is still live. A reset that landed in between
// (new hash, sessions revoked) makes it a no-op.
func swapPasswordHash(ctx context.Context, q db.DBTX, userID, sid uuid.UUID, oldHash, newHash string) (bool, error) {
	tag, err := q.Exec(ctx,
		`UPDATE auth.users SET password_hash = $3, updated_at = now()
		 WHERE id = $1 AND password_hash = $2
		   AND EXISTS (SELECT 1 FROM auth.sessions WHERE id = $4 AND revoked_at IS NULL AND expires_at > now())`,
		userID, oldHash, newHash, sid)
	return tag.RowsAffected() == 1, err
}

// ---------- sessions ----------

// insertSession only inserts while the user's hash is still the one login verified (SPEC 4);
// pgx.ErrNoRows means the password changed while argon2 ran. FOR SHARE makes it wait for an
// in-flight reset/change of that row and re-check the hash after it commits; without it a plain
// read sees the old hash and inserts a session after the reset has already revoked them all.
func insertSession(ctx context.Context, q db.DBTX, userID uuid.UUID, verifiedHash, tokenHash string, userAgent, ip *string, ttl time.Duration) (uuid.UUID, error) {
	var id uuid.UUID
	err := q.QueryRow(ctx,
		`INSERT INTO auth.sessions (user_id, refresh_token_hash, user_agent, ip, expires_at)
		 SELECT id, $2, $3, $4, now() + make_interval(secs => $5) FROM auth.users WHERE id = $1 AND password_hash = $6 AND disabled_at IS NULL
		 FOR SHARE
		 RETURNING id`,
		userID, tokenHash, userAgent, ip, secs(ttl), verifiedHash).Scan(&id)
	return id, err
}

// rotateSession is the single atomic rotation statement from SPEC 4, re-reading the user in the same round trip.
func rotateSession(ctx context.Context, q db.DBTX, sid uuid.UUID, oldHash, newHash string, ttl time.Duration) (User, error) {
	return ScanUser(q.QueryRow(ctx,
		`WITH s AS (
		   UPDATE auth.sessions SET refresh_token_hash = $3, previous_refresh_token_hash = $2,
		     last_used_at = now(), expires_at = now() + make_interval(secs => $4)
		   WHERE id = $1 AND refresh_token_hash = $2 AND revoked_at IS NULL AND expires_at > now()
		     AND EXISTS (SELECT 1 FROM auth.users WHERE id = sessions.user_id AND disabled_at IS NULL)
		   RETURNING user_id
		 )
		 SELECT `+userColumnsU+` FROM auth.users u JOIN s ON u.id = s.user_id`,
		sid, oldHash, newHash, secs(ttl)))
}

// sessionPreviousHash returns the hash the session's current token replaced and whether it is live.
func sessionPreviousHash(ctx context.Context, q db.DBTX, sid uuid.UUID) (*string, bool, error) {
	var prev *string
	var live bool
	err := q.QueryRow(ctx,
		`SELECT previous_refresh_token_hash, (revoked_at IS NULL AND expires_at > now()) FROM auth.sessions WHERE id = $1`, sid).
		Scan(&prev, &live)
	return prev, live, err
}

// revokeOnReuse is SPEC 4's reuse revocation, conditional on the presented hash being the previous one.
func revokeOnReuse(ctx context.Context, q db.DBTX, sid uuid.UUID, presented string) (bool, error) {
	tag, err := q.Exec(ctx,
		`UPDATE auth.sessions SET revoked_at = now()
		 WHERE id = $1 AND previous_refresh_token_hash = $2 AND revoked_at IS NULL AND expires_at > now()`, sid, presented)
	return tag.RowsAffected() == 1, err
}

func revokeSession(ctx context.Context, q db.DBTX, sid, userID uuid.UUID) (bool, error) {
	tag, err := q.Exec(ctx,
		`UPDATE auth.sessions SET revoked_at = now() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL AND expires_at > now()`,
		sid, userID)
	return tag.RowsAffected() == 1, err
}

// revokeUserSessions revokes every live session of the user except `keep` (uuid.Nil keeps none).
func revokeUserSessions(ctx context.Context, q db.DBTX, userID, keep uuid.UUID) error {
	_, err := q.Exec(ctx,
		`UPDATE auth.sessions SET revoked_at = now() WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL`,
		userID, keep)
	return err
}

// sessionUser is the guard's one query: live session + its (not disabled) user.
func sessionUser(ctx context.Context, q db.DBTX, sid, userID uuid.UUID) (User, error) {
	return ScanUser(q.QueryRow(ctx,
		`SELECT `+userColumnsU+`
		 FROM auth.sessions s JOIN auth.users u ON u.id = s.user_id
		 WHERE s.id = $1 AND s.user_id = $2 AND s.revoked_at IS NULL AND s.expires_at > now()
		   AND u.disabled_at IS NULL`,
		sid, userID))
}

type sessionRow struct {
	ID         uuid.UUID
	UserAgent  *string
	IP         *string
	CreatedAt  time.Time
	LastUsedAt time.Time
}

func listActiveSessions(ctx context.Context, q db.DBTX, userID uuid.UUID) ([]sessionRow, error) {
	rows, err := q.Query(ctx,
		`SELECT id, user_agent, ip, created_at, last_used_at FROM auth.sessions
		 WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()
		 ORDER BY created_at DESC, id DESC`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (sessionRow, error) {
		var s sessionRow
		err := r.Scan(&s.ID, &s.UserAgent, &s.IP, &s.CreatedAt, &s.LastUsedAt)
		return s, err
	})
}

// ---------- one-time tokens ----------

// userForToken is a plain read (no row lock): issuance must only lock via lockTokenIssue.
// Disabled accounts are invisible here, so they never get verification or reset mail.
func userForToken(ctx context.Context, q db.DBTX, email string) (uuid.UUID, bool, error) {
	var id uuid.UUID
	var verifiedAt *time.Time
	err := q.QueryRow(ctx, `SELECT id, email_verified_at FROM auth.users WHERE email = $1 AND disabled_at IS NULL`, email).
		Scan(&id, &verifiedAt)
	return id, verifiedAt != nil, err
}

// lockTokenIssue serialises issuance per (user, type) until the transaction ends (SPEC 4).
func lockTokenIssue(ctx context.Context, q db.DBTX, userID uuid.UUID, typ string) error {
	_, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, userID.String()+":"+typ)
	return err
}

// tokenIssuedWithin reports whether the user's newest token of the type is younger than d.
func tokenIssuedWithin(ctx context.Context, q db.DBTX, userID uuid.UUID, typ string, d time.Duration) (bool, error) {
	var recent bool
	err := q.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM auth.user_tokens WHERE user_id = $1 AND type = $2 AND created_at > now() - make_interval(secs => $3))`,
		userID, typ, secs(d)).Scan(&recent)
	return recent, err
}

// invalidateTokens marks the user's unused tokens of a type as used.
func invalidateTokens(ctx context.Context, q db.DBTX, userID uuid.UUID, typ string) error {
	_, err := q.Exec(ctx,
		`UPDATE auth.user_tokens SET used_at = now() WHERE user_id = $1 AND type = $2 AND used_at IS NULL`, userID, typ)
	return err
}

func insertToken(ctx context.Context, q db.DBTX, userID uuid.UUID, typ, hash string, ttl time.Duration) error {
	_, err := q.Exec(ctx,
		`INSERT INTO auth.user_tokens (user_id, type, token_hash, expires_at) VALUES ($1, $2, $3, now() + make_interval(secs => $4))`,
		userID, typ, hash, secs(ttl))
	return err
}

// consumeToken is the atomic single-use consumption from SPEC 4.
func consumeToken(ctx context.Context, q db.DBTX, hash, typ string) (uuid.UUID, error) {
	var userID uuid.UUID
	err := q.QueryRow(ctx,
		`UPDATE auth.user_tokens SET used_at = now()
		 WHERE token_hash = $1 AND type = $2 AND used_at IS NULL AND expires_at > now()
		 RETURNING user_id`, hash, typ).Scan(&userID)
	return userID, err
}

func markEmailVerified(ctx context.Context, q db.DBTX, userID uuid.UUID) error {
	_, err := q.Exec(ctx,
		`UPDATE auth.users SET email_verified_at = now(), updated_at = now() WHERE id = $1 AND email_verified_at IS NULL`, userID)
	return err
}

func resetPassword(ctx context.Context, q db.DBTX, userID uuid.UUID, hash string) error {
	_, err := q.Exec(ctx,
		`UPDATE auth.users SET password_hash = $2, email_verified_at = coalesce(email_verified_at, now()), updated_at = now()
		 WHERE id = $1`, userID, hash)
	return err
}
