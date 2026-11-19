package auth

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"boilerplate/internal/platform/httpx"
)

// Routes mounts /auth/*. `limit` is the auth rate limiter, applied to the whole group.
func (s *Service) Routes(r chi.Router, limit func(http.Handler) http.Handler) {
	r.Route("/auth", func(r chi.Router) {
		r.Use(limit)
		r.Post("/register", httpx.Handle(s.handleRegister))
		r.Post("/login", httpx.Handle(s.handleLogin))
		r.Post("/refresh", httpx.Handle(s.handleRefresh))
		r.Post("/verify-email", httpx.Handle(s.handleVerifyEmail))
		r.Post("/resend-verification", httpx.Handle(s.handleResendVerification))
		r.Post("/forgot-password", httpx.Handle(s.handleForgotPassword))
		r.Post("/reset-password", httpx.Handle(s.handleResetPassword))
		r.Group(func(r chi.Router) {
			r.Use(s.Require)
			r.Post("/logout", httpx.Handle(s.handleLogout))
			r.Post("/logout-all", httpx.Handle(s.handleLogoutAll))
			r.Post("/change-password", httpx.Handle(s.handleChangePassword))
			r.Get("/sessions", httpx.Handle(s.handleSessions))
			r.Delete("/sessions/{id}", httpx.Handle(s.handleRevokeSession))
		})
	})
}

// ---------- guard ----------

type principalKey struct{}

// Require rejects requests without a valid access token and live session.
func (s *Service) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := s.Authenticate(r.Context(), r.Header.Get("Authorization"))
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		httpx.SetUserID(r.Context(), p.User.ID.String())
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
	})
}

// RequireRole must run after Require. The role comes from the DB row loaded by the guard.
func RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if CurrentPrincipal(r.Context()).User.Role != role {
				httpx.WriteError(w, r, httpx.Forbidden())
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func CurrentPrincipal(ctx context.Context) Principal {
	p, _ := ctx.Value(principalKey{}).(Principal)
	return p
}

// ---------- validation (shared with users) ----------

func NormalizeEmail(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func validateEmail(v *httpx.Validation, email string) {
	switch {
	case email == "":
		v.Add("email", "is required")
	case utf8.RuneCountInString(email) > 254:
		v.Add("email", "must be at most 254 characters")
	case !emailPattern.MatchString(email):
		v.Add("email", "must be a valid email address")
	}
}

// emailPattern is SPEC 4's exact, ASCII-only address syntax. Nothing looser ever reaches the
// mailer, so "victim<attacker@evil.com>" can never be re-read as a display name + other address.
var emailPattern = regexp.MustCompile("^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9-]+(\\.[a-z0-9-]+)+$")

// ValidEmail reports whether an already-normalised email matches the SPEC syntax and length.
func ValidEmail(email string) bool {
	v := &httpx.Validation{}
	validateEmail(v, email)
	return v.Err() == nil
}

func validatePassword(v *httpx.Validation, field, pw string) {
	if n := utf8.RuneCountInString(pw); n < 15 || n > 128 {
		v.Add(field, "must be between 15 and 128 characters")
	}
}

// ValidateName checks an already-trimmed display name.
func ValidateName(v *httpx.Validation, name string) {
	if n := utf8.RuneCountInString(name); n < 1 || n > 100 {
		v.Add("name", "must be between 1 and 100 characters")
	} else if httpx.HasControlChars(name) {
		v.Add("name", "must not contain control characters")
	}
}

func required(v *httpx.Validation, field, value string) {
	if value == "" {
		v.Add(field, "is required")
	}
}

// ---------- handlers ----------

var (
	resendBody = map[string]string{"message": "If an unverified account exists for this email, a verification link has been sent."}
	forgotBody = map[string]string{"message": "If an account exists for this email, a password reset link has been sent."}
)

func (s *Service) handleRegister(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Name     string `json:"name"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		return err
	}
	in.Email, in.Name = NormalizeEmail(in.Email), strings.TrimSpace(in.Name)
	v := &httpx.Validation{}
	validateEmail(v, in.Email)
	validatePassword(v, "password", in.Password)
	ValidateName(v, in.Name)
	if err := v.Err(); err != nil {
		return err
	}
	u, err := s.Register(r.Context(), in.Email, in.Password, in.Name)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"user": u.DTO()})
	return nil
}

func (s *Service) handleLogin(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		return err
	}
	in.Email = NormalizeEmail(in.Email)
	v := &httpx.Validation{}
	required(v, "email", in.Email)
	required(v, "password", in.Password)
	if err := v.Err(); err != nil {
		return err
	}
	t, err := s.Login(r.Context(), in.Email, in.Password, r.UserAgent(), httpx.ClientIP(r.Context()))
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, t)
	return nil
}

func (s *Service) handleRefresh(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		return err
	}
	v := &httpx.Validation{}
	required(v, "refresh_token", in.RefreshToken)
	if err := v.Err(); err != nil {
		return err
	}
	t, err := s.Refresh(r.Context(), in.RefreshToken)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, t)
	return nil
}

func (s *Service) handleLogout(w http.ResponseWriter, r *http.Request) error {
	if err := s.Logout(r.Context(), CurrentPrincipal(r.Context())); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) handleLogoutAll(w http.ResponseWriter, r *http.Request) error {
	if err := s.LogoutAll(r.Context(), CurrentPrincipal(r.Context())); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) handleVerifyEmail(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Token string `json:"token"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		return err
	}
	v := &httpx.Validation{}
	required(v, "token", in.Token)
	if err := v.Err(); err != nil {
		return err
	}
	if err := s.VerifyEmail(r.Context(), in.Token); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) decodeEmail(r *http.Request) (string, error) {
	var in struct {
		Email string `json:"email"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		return "", err
	}
	email := NormalizeEmail(in.Email)
	v := &httpx.Validation{}
	validateEmail(v, email)
	return email, v.Err()
}

func (s *Service) handleResendVerification(w http.ResponseWriter, r *http.Request) error {
	email, err := s.decodeEmail(r)
	if err != nil {
		return err
	}
	s.ResendVerification(r.Context(), email)
	httpx.WriteJSON(w, http.StatusAccepted, resendBody)
	return nil
}

func (s *Service) handleForgotPassword(w http.ResponseWriter, r *http.Request) error {
	email, err := s.decodeEmail(r)
	if err != nil {
		return err
	}
	s.ForgotPassword(r.Context(), email)
	httpx.WriteJSON(w, http.StatusAccepted, forgotBody)
	return nil
}

func (s *Service) handleResetPassword(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		return err
	}
	// Validate before touching the token, so a weak password does not burn it.
	v := &httpx.Validation{}
	required(v, "token", in.Token)
	validatePassword(v, "password", in.Password)
	if err := v.Err(); err != nil {
		return err
	}
	if err := s.ResetPassword(r.Context(), in.Token, in.Password); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) handleChangePassword(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		return err
	}
	v := &httpx.Validation{}
	required(v, "current_password", in.CurrentPassword)
	validatePassword(v, "new_password", in.NewPassword)
	if err := v.Err(); err != nil {
		return err
	}
	if err := s.ChangePassword(r.Context(), CurrentPrincipal(r.Context()), in.CurrentPassword, in.NewPassword); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

type sessionDTO struct {
	ID         uuid.UUID `json:"id"`
	UserAgent  *string   `json:"user_agent"`
	IP         *string   `json:"ip"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsedAt time.Time `json:"last_used_at"`
	Current    bool      `json:"current"`
}

func (s *Service) handleSessions(w http.ResponseWriter, r *http.Request) error {
	p := CurrentPrincipal(r.Context())
	rows, err := s.Sessions(r.Context(), p)
	if err != nil {
		return err
	}
	out := make([]sessionDTO, 0, len(rows))
	for _, row := range rows {
		out = append(out, sessionDTO{
			ID: row.ID, UserAgent: row.UserAgent, IP: row.IP,
			CreatedAt: row.CreatedAt.UTC(), LastUsedAt: row.LastUsedAt.UTC(), Current: row.ID == p.SessionID,
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"data": out})
	return nil
}

func (s *Service) handleRevokeSession(w http.ResponseWriter, r *http.Request) error {
	id, err := httpx.ParseID(chi.URLParam(r, "id"))
	if err != nil {
		return err
	}
	if err := s.RevokeSession(r.Context(), CurrentPrincipal(r.Context()), id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
