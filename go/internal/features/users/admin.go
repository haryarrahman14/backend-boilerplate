package users

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"boilerplate/internal/features/auth"
	"boilerplate/internal/platform/db"
	"boilerplate/internal/platform/httpx"
)

// ---------- DELETE /users/me ----------

func (h *Handler) deleteMe(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Password string `json:"password"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		return err
	}
	if in.Password == "" {
		return httpx.ValidationError("password", "is required")
	}
	ctx := r.Context()
	me := auth.CurrentPrincipal(ctx).User.ID
	if err := h.auth.CheckPassword(ctx, me, in.Password); err != nil {
		return err
	}
	if err := h.deleteUser(ctx, me); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ---------- PATCH /admin/users/{id} ----------

// selfModificationRefused: an admin may not demote or disable their own account (which could
// lock the system out). Setting a value that changes nothing (role "admin", disabled false) is allowed.
func selfModificationRefused(actor, target uuid.UUID, role *string, disabled *bool) bool {
	if actor != target {
		return false
	}
	return (role != nil && *role != "admin") || (disabled != nil && *disabled)
}

func (h *Handler) adminUpdate(w http.ResponseWriter, r *http.Request) error {
	id, err := httpx.ParseID(chi.URLParam(r, "id"))
	if err != nil {
		return err
	}
	var in struct {
		Role     *string `json:"role"`
		Disabled *bool   `json:"disabled"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		return err
	}
	if in.Role != nil && *in.Role != "user" && *in.Role != "admin" {
		return httpx.ValidationError("role", "must be user or admin")
	}
	ctx := r.Context()
	if selfModificationRefused(auth.CurrentPrincipal(ctx).User.ID, id, in.Role, in.Disabled) {
		return httpx.NewError(http.StatusForbidden, "forbidden", "Admins cannot change their own role or disable themselves.")
	}

	var u auth.User
	if in.Role == nil && in.Disabled == nil {
		u, err = auth.ScanUser(h.pool.QueryRow(ctx, `SELECT `+auth.UserColumns+` FROM auth.users WHERE id = $1`, id))
	} else {
		// Disabling and the session revocation commit together (lock order users -> sessions).
		err = db.InTx(ctx, h.pool, func(tx pgx.Tx) error {
			var err error
			u, err = auth.ScanUser(tx.QueryRow(ctx,
				`UPDATE auth.users SET
				   role = coalesce($2, role),
				   disabled_at = CASE WHEN $3::boolean IS NULL THEN disabled_at
				                      WHEN $3 THEN coalesce(disabled_at, now()) ELSE NULL END,
				   updated_at = now()
				 WHERE id = $1 RETURNING `+auth.UserColumns, id, in.Role, in.Disabled))
			if err != nil || in.Disabled == nil || !*in.Disabled {
				return err
			}
			_, err = tx.Exec(ctx, `UPDATE auth.sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`, id)
			return err
		})
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return httpx.NotFound()
	}
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"user": u.DTO()})
	return nil
}

// ---------- DELETE /admin/users/{id} ----------

func (h *Handler) adminDelete(w http.ResponseWriter, r *http.Request) error {
	id, err := httpx.ParseID(chi.URLParam(r, "id"))
	if err != nil {
		return err
	}
	ctx := r.Context()
	if id == auth.CurrentPrincipal(ctx).User.ID {
		return httpx.NewError(http.StatusForbidden, "forbidden", "Use DELETE /users/me to delete your own account.")
	}
	if err := h.deleteUser(ctx, id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ---------- deleting a user (SPEC 5) ----------

const deletePage = 500

// deleteUser: (1) revoke every session and commit, so access stops even if a later step fails;
// (2) delete every bucket object of the user's files, paging by id; a bucket error stops here
// with 500 and leaves the user row, so the call can be repeated; (3) delete the users row,
// cascading to sessions, tokens and file rows. 404 if the user does not exist.
// Ceiling: an upload URL issued before the deletion can still create an orphan object for up
// to 15 minutes; a bucket lifecycle rule on users/ cleans it up.
func (h *Handler) deleteUser(ctx context.Context, id uuid.UUID) error {
	if _, err := h.pool.Exec(ctx, `UPDATE auth.sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`, id); err != nil {
		return err
	}
	after := uuid.Nil
	for {
		rows, err := h.pool.Query(ctx,
			`SELECT id, key FROM storage.files WHERE user_id = $1 AND id > $2 ORDER BY id LIMIT $3`, id, after, deletePage)
		if err != nil {
			return err
		}
		type obj struct {
			id  uuid.UUID
			key string
		}
		page, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (obj, error) {
			var o obj
			return o, row.Scan(&o.id, &o.key)
		})
		if err != nil {
			return err
		}
		// The page is fully read and its connection released before any bucket call.
		for _, o := range page {
			if err := h.store.Delete(ctx, o.key); err != nil {
				return err
			}
		}
		if len(page) < deletePage {
			break
		}
		after = page[len(page)-1].id
	}
	tag, err := h.pool.Exec(ctx, `DELETE FROM auth.users WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return httpx.NotFound()
	}
	return nil
}
