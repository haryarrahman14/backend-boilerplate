package auth

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"boilerplate/internal/platform/config"
	"boilerplate/internal/platform/db"
	"boilerplate/internal/platform/httpx"
	"boilerplate/internal/platform/mailer"
)

const (
	verificationTTL = 24 * time.Hour
	resetTTL        = time.Hour
)

var (
	errInvalidCredentials = httpx.NewError(http.StatusUnauthorized, "invalid_credentials", "Invalid email or password.")
	errWrongPassword      = httpx.NewError(http.StatusUnauthorized, "invalid_credentials", "Current password is incorrect.")
	errInvalidToken       = httpx.NewError(http.StatusBadRequest, "invalid_token", "The link is invalid or has expired.")
	errEmailTaken         = httpx.NewError(http.StatusConflict, "email_taken", "An account with this email already exists.")
	errEmailNotVerified   = httpx.NewError(http.StatusForbidden, "email_not_verified", "Verify your email address before logging in.")
)

// Background email jobs run on a small fixed worker pool fed by a bounded queue, so a
// forgot-password flood can hold at most bgWorkers DB connections and bgMaxJobs jobs of memory
// (queued + in flight, SPEC 4). Ceiling: overflow is dropped (logged); in-process only, lost on a crash.
const (
	bgWorkers = 2
	bgMaxJobs = 1000
)

type job struct {
	name string
	log  *slog.Logger
	fn   func(ctx context.Context) error
}

type Service struct {
	cfg       *config.Config
	jwtKey    []byte
	pool      *pgxpool.Pool
	mail      *mailer.Mailer
	dummyHash string

	jobs    chan job
	workers sync.WaitGroup
	closeMu sync.Mutex
	closed  bool
}

func NewService(cfg *config.Config, pool *pgxpool.Pool, mail *mailer.Mailer) (*Service, error) {
	// Verified against when the login email is unknown, so both paths cost one argon2 run.
	dummy, err := HashPassword(context.Background(), "dummy password, never matches")
	if err != nil {
		return nil, err
	}
	s := &Service{cfg: cfg, jwtKey: []byte(cfg.JWTSecret.Reveal()), pool: pool, mail: mail, dummyHash: dummy, jobs: make(chan job, bgMaxJobs-bgWorkers)}
	for range bgWorkers {
		s.workers.Add(1)
		go s.work()
	}
	return s, nil
}

func (s *Service) work() {
	defer s.workers.Done()
	for j := range s.jobs {
		s.run(j)
	}
}

func (s *Service) run(j job) {
	defer func() {
		if rec := recover(); rec != nil {
			j.log.Error("background job panicked", "job", j.name, "panic", rec)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := j.fn(ctx); err != nil {
		j.log.Error("background job failed", "job", j.name, "error", err.Error())
	}
}

// Wait stops taking jobs and blocks until queued emails are sent or ctx ends. Called on shutdown,
// after the HTTP server stopped, before the DB pool closes.
func (s *Service) Wait(ctx context.Context) {
	s.closeMu.Lock()
	if !s.closed {
		s.closed = true
		close(s.jobs)
	}
	s.closeMu.Unlock()
	done := make(chan struct{})
	go func() { s.workers.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// background queues fn to run after the response, detached from the request context.
// Failures are logged and never reach the client.
func (s *Service) background(log *slog.Logger, name string, fn func(ctx context.Context) error) {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if s.closed {
		log.Error("background job dropped: shutting down", "job", name)
		return
	}
	select {
	case s.jobs <- job{name: name, log: log, fn: fn}:
	default:
		log.Error("background job dropped: queue full", "job", name)
	}
}

type Tokens struct {
	AccessToken  string  `json:"access_token"`
	RefreshToken string  `json:"refresh_token"`
	TokenType    string  `json:"token_type"`
	ExpiresIn    int     `json:"expires_in"`
	User         UserDTO `json:"user"`
}

func (s *Service) tokens(u User, sid uuid.UUID, secret string) (Tokens, error) {
	access, err := IssueAccessToken(s.jwtKey, u.ID, sid, time.Now(), s.cfg.AccessTokenTTL)
	if err != nil {
		return Tokens{}, err
	}
	return Tokens{
		AccessToken: access, RefreshToken: FormatRefreshToken(sid, secret), TokenType: "Bearer",
		ExpiresIn: int(s.cfg.AccessTokenTTL / time.Second), User: u.DTO(),
	}, nil
}

// ---------- register / login / refresh ----------

func (s *Service) Register(ctx context.Context, email, password, name string) (User, error) {
	hash, err := HashPassword(ctx, password)
	if err != nil {
		return User{}, err
	}
	u, err := insertUser(ctx, s.pool, email, hash, name)
	if db.IsUniqueViolation(err, "users_email_key") {
		return User{}, errEmailTaken
	}
	if err != nil {
		return User{}, err
	}
	s.sendTokenEmail(httpx.Logger(ctx), email, tokenEmailVerification)
	return u, nil
}

// verifyDummy burns one argon2 run on the fixed dummy hash, so every login miss costs the same.
// It never hashes a password longer than 128 code points (SPEC 4).
func (s *Service) verifyDummy(ctx context.Context, password string) error {
	if tooLong(password) {
		password = "x"
	}
	_, err := VerifyPassword(ctx, s.dummyHash, password)
	return err
}

func tooLong(password string) bool { return utf8.RuneCountInString(password) > 128 }

func (s *Service) Login(ctx context.Context, email, password, userAgent, ip string) (Tokens, error) {
	// A malformed email (including NUL bytes Postgres cannot take) or an over-long password is a
	// plain miss: it never reaches the DB or argon2.
	if !ValidEmail(email) || tooLong(password) {
		if err := s.verifyDummy(ctx, password); err != nil {
			return Tokens{}, err
		}
		return Tokens{}, errInvalidCredentials
	}
	u, hash, err := userWithHashByEmail(ctx, s.pool, email)
	if isNoRows(err) {
		if err := s.verifyDummy(ctx, password); err != nil {
			return Tokens{}, err
		}
		return Tokens{}, errInvalidCredentials
	}
	if err != nil {
		return Tokens{}, err
	}
	ok, err := VerifyPassword(ctx, hash, password)
	if err != nil {
		return Tokens{}, err
	}
	if !ok {
		return Tokens{}, errInvalidCredentials
	}
	// Checked only after the password, so it cannot be used to probe for accounts.
	if s.cfg.AuthRequireVerifiedEmail && u.EmailVerifiedAt == nil {
		return Tokens{}, errEmailNotVerified
	}

	secret, err := NewSecret()
	if err != nil {
		return Tokens{}, err
	}
	// Bound to the verified hash: if a reset/change landed while argon2 ran, no session is created.
	sid, err := insertSession(ctx, s.pool, u.ID, hash, HashSecret(secret), nullable(truncate(userAgent, 255)), nullable(ip), s.cfg.RefreshTokenTTL)
	if isNoRows(err) {
		return Tokens{}, errInvalidCredentials
	}
	if err != nil {
		return Tokens{}, err
	}
	httpx.SetUserID(ctx, u.ID.String())
	return s.tokens(u, sid, secret)
}

func (s *Service) Refresh(ctx context.Context, refreshToken string) (Tokens, error) {
	sid, secret, err := ParseRefreshToken(refreshToken)
	if err != nil {
		return Tokens{}, httpx.Unauthorized()
	}
	oldHash := HashSecret(secret)
	newSecret, err := NewSecret()
	if err != nil {
		return Tokens{}, err
	}
	u, err := rotateSession(ctx, s.pool, sid, oldHash, HashSecret(newSecret), s.cfg.RefreshTokenTTL)
	if err == nil {
		httpx.SetUserID(ctx, u.ID.String())
		return s.tokens(u, sid, newSecret)
	}
	if !isNoRows(err) {
		return Tokens{}, err
	}

	// Nothing rotated. Only the token this session's current one replaced proves a replay of a
	// genuinely issued secret; a guess (the session id is public) must revoke nothing.
	previous, live, err := sessionPreviousHash(ctx, s.pool, sid)
	if err != nil && !isNoRows(err) {
		return Tokens{}, err
	}
	if err == nil && reuseDetected(oldHash, previous, live) {
		revoked, err := revokeOnReuse(ctx, s.pool, sid, oldHash) // re-checks atomically
		if err != nil {
			return Tokens{}, err
		}
		if revoked {
			httpx.Logger(ctx).Warn("refresh token reuse detected, session revoked", "session_id", sid.String())
		}
	}
	return Tokens{}, httpx.Unauthorized()
}

// reuseDetected decides reuse: the presented hash equals the previous hash of a live session.
func reuseDetected(presented string, previous *string, live bool) bool {
	return live && previous != nil && HashesEqual(presented, *previous)
}

// ---------- guard ----------

type Principal struct {
	User      User
	SessionID uuid.UUID
}

// Authenticate verifies the JWT and loads the live session + user in one query.
func (s *Service) Authenticate(ctx context.Context, header string) (Principal, error) {
	scheme, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return Principal{}, httpx.Unauthorized()
	}
	userID, sid, err := ParseAccessToken(s.jwtKey, strings.TrimSpace(token), time.Now())
	if err != nil {
		return Principal{}, httpx.Unauthorized()
	}
	u, err := sessionUser(ctx, s.pool, sid, userID)
	if isNoRows(err) {
		return Principal{}, httpx.Unauthorized()
	}
	if err != nil {
		return Principal{}, err
	}
	return Principal{User: u, SessionID: sid}, nil
}

// ---------- sessions ----------

func (s *Service) Logout(ctx context.Context, p Principal) error {
	_, err := revokeSession(ctx, s.pool, p.SessionID, p.User.ID)
	return err
}

func (s *Service) LogoutAll(ctx context.Context, p Principal) error {
	return revokeUserSessions(ctx, s.pool, p.User.ID, uuid.Nil)
}

func (s *Service) Sessions(ctx context.Context, p Principal) ([]sessionRow, error) {
	return listActiveSessions(ctx, s.pool, p.User.ID)
}

func (s *Service) RevokeSession(ctx context.Context, p Principal, sid uuid.UUID) error {
	ok, err := revokeSession(ctx, s.pool, sid, p.User.ID)
	if err != nil {
		return err
	}
	if !ok {
		return httpx.NotFound()
	}
	return nil
}

// ---------- email verification / password reset ----------

func (s *Service) VerifyEmail(ctx context.Context, token string) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		userID, err := consumeToken(ctx, tx, HashSecret(token), tokenEmailVerification)
		if isNoRows(err) {
			return errInvalidToken
		}
		if err != nil {
			return err
		}
		// SPEC 4 order: user_tokens -> users. One verified link kills the others.
		if err := invalidateTokens(ctx, tx, userID, tokenEmailVerification); err != nil {
			return err
		}
		return markEmailVerified(ctx, tx, userID)
	})
}

// ResendVerification and ForgotPassword do all their work (lookup included) in the
// background, so the response is identical in body and timing whether or not the account exists.
func (s *Service) ResendVerification(ctx context.Context, email string) {
	s.sendTokenEmail(httpx.Logger(ctx), email, tokenEmailVerification)
}

func (s *Service) ForgotPassword(ctx context.Context, email string) {
	s.sendTokenEmail(httpx.Logger(ctx), email, tokenPasswordReset)
}

func (s *Service) ResetPassword(ctx context.Context, token, password string) error {
	hash, err := HashPassword(ctx, password) // before the transaction: argon2 is slow
	if err != nil {
		return err
	}
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		userID, err := consumeToken(ctx, tx, HashSecret(token), tokenPasswordReset)
		if isNoRows(err) {
			return errInvalidToken
		}
		if err != nil {
			return err
		}
		// SPEC 4 order: user_tokens -> users -> sessions.
		if err := invalidateTokens(ctx, tx, userID, tokenPasswordReset); err != nil {
			return err
		}
		if err := resetPassword(ctx, tx, userID, hash); err != nil {
			return err
		}
		return revokeUserSessions(ctx, tx, userID, uuid.Nil)
	})
}

func (s *Service) ChangePassword(ctx context.Context, p Principal, current, next string) error {
	if tooLong(current) {
		if err := s.verifyDummy(ctx, current); err != nil {
			return err
		}
		return errWrongPassword
	}
	oldHash, err := passwordHash(ctx, s.pool, p.User.ID)
	if err != nil {
		return err
	}
	ok, err := VerifyPassword(ctx, oldHash, current)
	if err != nil {
		return err
	}
	if !ok {
		return errWrongPassword
	}
	newHash, err := HashPassword(ctx, next)
	if err != nil {
		return err
	}
	// SPEC 4 order: users -> sessions. password_reset tokens are left alone on purpose: the
	// mailbox owner must always be able to recover with a reset link.
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		ok, err := swapPasswordHash(ctx, tx, p.User.ID, p.SessionID, oldHash, newHash)
		if err != nil {
			return err
		}
		if !ok { // password or session changed underneath us (e.g. a reset won the race)
			return errWrongPassword
		}
		return revokeUserSessions(ctx, tx, p.User.ID, p.SessionID)
	})
}

// sendTokenEmail issues a one-time token and mails the link, all in the background. Older
// tokens stay valid (consuming one invalidates the rest). Verification goes to unverified users only.
// The transaction commits before the SMTP send, so no DB connection is held while mailing.
func (s *Service) sendTokenEmail(log *slog.Logger, email, typ string) {
	s.background(log, "email:"+typ, func(ctx context.Context) error {
		token, err := NewSecret()
		if err != nil {
			return err
		}
		userID, verified, err := userForToken(ctx, s.pool, email)
		if isNoRows(err) || (err == nil && typ == tokenEmailVerification && verified) {
			return nil
		}
		if err != nil {
			return err
		}
		ttl := resetTTL
		if typ == tokenEmailVerification {
			ttl = verificationTTL
		}
		send := false
		err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
			// Touches user_tokens only, serialised per (user, type): never deadlocks with reset/change.
			if err := lockTokenIssue(ctx, tx, userID, typ); err != nil {
				return err
			}
			if cd := s.cfg.EmailTokenCooldown; cd > 0 {
				recent, err := tokenIssuedWithin(ctx, tx, userID, typ, cd)
				if err != nil || recent {
					return err // within the cooldown: issue nothing, send nothing
				}
			}
			send = true
			return insertToken(ctx, tx, userID, typ, HashSecret(token), ttl)
		})
		if err != nil || !send {
			return err
		}

		return s.mail.Send(ctx, log, email, mailSubject(typ), mailBody(typ, s.cfg.AppURL, token))
	})
}

// mailSubject and mailBody are fixed text plus the link only: never a user-controlled value,
// since anyone can register any address (SPEC 4).
func mailSubject(typ string) string {
	if typ == tokenPasswordReset {
		return "Reset your password"
	}
	return "Verify your email address"
}

func mailBody(typ, appURL, token string) string {
	if typ == tokenPasswordReset {
		return "Reset your password by opening this link (valid for 1 hour):\n\n" +
			appURL + "/reset-password?token=" + token +
			"\n\nIf you did not ask for a password reset, ignore this email. Your password stays unchanged.\n"
	}
	return "Confirm your email address by opening this link (valid for 24 hours):\n\n" +
		appURL + "/verify-email?token=" + token +
		"\n\nIf you did not create this account, ignore this email and do not use the link.\n"
}

// ---------- helpers ----------

func truncate(s string, n int) string {
	s = strings.ToValidUTF8(s, "")
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
