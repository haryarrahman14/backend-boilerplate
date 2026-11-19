// Package users serves the profile, account deletion and admin user management.
package users

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"boilerplate/internal/features/auth"
	"boilerplate/internal/platform/httpx"
	"boilerplate/internal/platform/storage"
)

type Handler struct {
	pool  *pgxpool.Pool
	store *storage.Storage
	auth  *auth.Service
}

func New(pool *pgxpool.Pool, store *storage.Storage, authSvc *auth.Service) *Handler {
	return &Handler{pool: pool, store: store, auth: authSvc}
}

func (h *Handler) Routes(r chi.Router) {
	r.Group(func(r chi.Router) {
		r.Use(h.auth.Require)
		r.Get("/users/me", httpx.Handle(h.me))
		r.Patch("/users/me", httpx.Handle(h.updateMe))
		r.Delete("/users/me", httpx.Handle(h.deleteMe))
		// Role check runs as middleware, before any id parsing or body validation (SPEC 5).
		r.Route("/admin/users", func(r chi.Router) {
			r.Use(auth.RequireRole("admin"))
			r.Get("/", httpx.Handle(h.list))
			r.Patch("/{id}", httpx.Handle(h.adminUpdate))
			r.Delete("/{id}", httpx.Handle(h.adminDelete))
		})
	})
}

func (h *Handler) me(w http.ResponseWriter, r *http.Request) error {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"user": auth.CurrentPrincipal(r.Context()).User.DTO()})
	return nil
}

// updateMe only touches `name`; role, email and anything else in the body are ignored.
// An absent (or null) name leaves the profile unchanged.
func (h *Handler) updateMe(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Name *string `json:"name"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		return err
	}
	u := auth.CurrentPrincipal(r.Context()).User
	if in.Name != nil {
		name := strings.TrimSpace(*in.Name)
		v := &httpx.Validation{}
		auth.ValidateName(v, name)
		if err := v.Err(); err != nil {
			return err
		}
		var err error
		u, err = auth.ScanUser(h.pool.QueryRow(r.Context(),
			`UPDATE auth.users SET name = $2, updated_at = now() WHERE id = $1 RETURNING `+auth.UserColumns, u.ID, name))
		if err == pgx.ErrNoRows {
			return httpx.Unauthorized() // user deleted mid-request
		}
		if err != nil {
			return err
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"user": u.DTO()})
	return nil
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) error {
	page, err := httpx.ParsePage(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	var total int64
	if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM auth.users`).Scan(&total); err != nil {
		return err
	}
	rows, err := h.pool.Query(ctx,
		`SELECT `+auth.UserColumns+` FROM auth.users ORDER BY created_at DESC, id DESC LIMIT $1 OFFSET $2`,
		page.PerPage, page.Offset())
	if err != nil {
		return err
	}
	users, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (auth.UserDTO, error) {
		u, err := auth.ScanUser(row)
		return u.DTO(), err
	})
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.Paginated(users, page, total))
	return nil
}
