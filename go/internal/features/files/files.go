// Package files implements direct-to-bucket uploads: presign, complete, list, get, delete.
package files

import (
	"context"
	"errors"
	"net/http"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"boilerplate/internal/features/auth"
	"boilerplate/internal/platform/config"
	"boilerplate/internal/platform/httpx"
	"boilerplate/internal/platform/storage"
)

const presignTTL = 900 * time.Second

type Handler struct {
	pool    *pgxpool.Pool
	store   *storage.Storage
	maxSize int64
	allowed []string
}

func New(cfg *config.Config, pool *pgxpool.Pool, store *storage.Storage) *Handler {
	return &Handler{pool: pool, store: store, maxSize: cfg.UploadMaxBytes, allowed: cfg.UploadAllowedTypes}
}

func (h *Handler) Routes(r chi.Router, require func(http.Handler) http.Handler) {
	r.Route("/files", func(r chi.Router) {
		r.Use(require)
		r.Post("/presign", httpx.Handle(h.presign))
		r.Get("/", httpx.Handle(h.list))
		r.Get("/{id}", httpx.Handle(h.get))
		r.Post("/{id}/complete", httpx.Handle(h.complete))
		r.Delete("/{id}", httpx.Handle(h.delete))
	})
}

// ---------- model + queries ----------

type file struct {
	ID          uuid.UUID  `json:"id"`
	Key         string     `json:"-"`
	Filename    string     `json:"filename"`
	ContentType string     `json:"content_type"`
	Size        int64      `json:"size"`
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	UploadedAt  *time.Time `json:"uploaded_at"`
}

const fileColumns = "id, key, filename, content_type, size, status, created_at, uploaded_at"

func scanFile(row pgx.Row) (file, error) {
	var f file
	err := row.Scan(&f.ID, &f.Key, &f.Filename, &f.ContentType, &f.Size, &f.Status, &f.CreatedAt, &f.UploadedAt)
	f.CreatedAt = f.CreatedAt.UTC()
	if f.UploadedAt != nil {
		t := f.UploadedAt.UTC()
		f.UploadedAt = &t
	}
	return f, err
}

// owned loads a file of the current user; someone else's file is indistinguishable from a missing one.
func (h *Handler) owned(r *http.Request) (file, error) {
	id, err := httpx.ParseID(chi.URLParam(r, "id"))
	if err != nil {
		return file{}, err
	}
	f, err := scanFile(h.pool.QueryRow(r.Context(),
		`SELECT `+fileColumns+` FROM storage.files WHERE id = $1 AND user_id = $2`, id, userID(r.Context())))
	if errors.Is(err, pgx.ErrNoRows) {
		return file{}, httpx.NotFound()
	}
	return f, err
}

func userID(ctx context.Context) uuid.UUID { return auth.CurrentPrincipal(ctx).User.ID }

// ---------- handlers ----------

var extPattern = regexp.MustCompile(`^\.[a-z0-9]{1,10}$`)

// objectKey never contains the client filename, only a vetted lowercased extension.
func objectKey(owner, id uuid.UUID, filename string) string {
	key := "users/" + owner.String() + "/" + id.String()
	if ext := strings.ToLower(path.Ext(filename)); extPattern.MatchString(ext) {
		key += ext
	}
	return key
}

func (h *Handler) presign(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Filename    string `json:"filename"`
		ContentType string `json:"content_type"`
		Size        int64  `json:"size"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		return err
	}
	v := &httpx.Validation{}
	if n := utf8.RuneCountInString(in.Filename); n < 1 || n > 255 {
		v.Add("filename", "must be between 1 and 255 characters")
	} else if httpx.HasControlChars(in.Filename) {
		v.Add("filename", "must not contain control characters")
	}
	if !slices.Contains(h.allowed, in.ContentType) {
		v.Add("content_type", "must be one of "+strings.Join(h.allowed, ", "))
	}
	if in.Size < 1 || in.Size > h.maxSize {
		v.Add("size", "must be between 1 and "+strconv.FormatInt(h.maxSize, 10)+" bytes")
	}
	if err := v.Err(); err != nil {
		return err
	}

	ctx := r.Context()
	owner, id := userID(ctx), uuid.New()
	key := objectKey(owner, id, in.Filename)
	url, err := h.store.PresignPut(ctx, key, in.ContentType, in.Size, presignTTL)
	if err != nil {
		return err
	}
	f, err := scanFile(h.pool.QueryRow(ctx,
		`INSERT INTO storage.files (id, user_id, key, filename, content_type, size) VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING `+fileColumns, id, owner, key, in.Filename, in.ContentType, in.Size))
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"file": f,
		"upload": map[string]any{
			"url": url, "method": "PUT", "headers": map[string]string{"Content-Type": in.ContentType},
			"expires_in": int(presignTTL / time.Second),
		},
	})
	return nil
}

func (h *Handler) complete(w http.ResponseWriter, r *http.Request) error {
	f, err := h.owned(r)
	if err != nil {
		return err
	}
	if f.Status == "uploaded" { // idempotent
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"file": f})
		return nil
	}
	ctx := r.Context()
	size, err := h.store.Size(ctx, f.Key)
	if errors.Is(err, storage.ErrNotFound) {
		return httpx.NewError(http.StatusConflict, "upload_incomplete", "The file has not been uploaded yet.")
	}
	if err != nil {
		return err
	}
	if size > h.maxSize {
		if err := h.store.Delete(ctx, f.Key); err != nil {
			return err
		}
		if _, err := h.pool.Exec(ctx, `DELETE FROM storage.files WHERE id = $1`, f.ID); err != nil {
			return err
		}
		return httpx.ValidationError("size", "uploaded object exceeds "+strconv.FormatInt(h.maxSize, 10)+" bytes")
	}
	updated, err := scanFile(h.pool.QueryRow(ctx,
		`UPDATE storage.files SET status = 'uploaded', size = $2, uploaded_at = now()
		 WHERE id = $1 AND status = 'pending' RETURNING `+fileColumns, f.ID, size))
	if errors.Is(err, pgx.ErrNoRows) { // a concurrent complete won the race (or deleted it): re-read
		updated, err = h.owned(r)
	}
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"file": updated})
	return nil
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) error {
	page, err := httpx.ParsePage(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	owner := userID(ctx)
	var total int64
	if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM storage.files WHERE user_id = $1`, owner).Scan(&total); err != nil {
		return err
	}
	rows, err := h.pool.Query(ctx,
		`SELECT `+fileColumns+` FROM storage.files WHERE user_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3`,
		owner, page.PerPage, page.Offset())
	if err != nil {
		return err
	}
	list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (file, error) { return scanFile(row) })
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.Paginated(list, page, total))
	return nil
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) error {
	f, err := h.owned(r)
	if err != nil {
		return err
	}
	var download *string
	if f.Status == "uploaded" {
		url, err := h.store.PresignGet(r.Context(), f.Key, presignTTL)
		if err != nil {
			return err
		}
		download = &url
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"file": f, "download_url": download})
	return nil
}

// delete removes the object first, then the row, so a failure never leaves an orphaned object.
func (h *Handler) delete(w http.ResponseWriter, r *http.Request) error {
	f, err := h.owned(r)
	if err != nil {
		return err
	}
	if err := h.store.Delete(r.Context(), f.Key); err != nil {
		return err
	}
	tag, err := h.pool.Exec(r.Context(), `DELETE FROM storage.files WHERE id = $1`, f.ID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 { // a concurrent delete (or oversize complete) got there first
		return httpx.NotFound()
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
