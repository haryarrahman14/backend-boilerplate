// Package httpx holds the cross-cutting HTTP pieces: the error envelope, JSON helpers and middleware.
package httpx

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// Error is an API error rendered as the SPEC error envelope.
type Error struct {
	Status     int
	Code       string
	Message    string
	Details    []FieldError
	RetryAfter int // seconds; sets the Retry-After header when > 0
}

type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func NewError(status int, code, message string) *Error {
	return &Error{Status: status, Code: code, Message: message}
}

func NotFound() *Error { return NewError(http.StatusNotFound, "not_found", "Resource not found.") }
func Unauthorized() *Error {
	return NewError(http.StatusUnauthorized, "unauthorized", "Authentication required.")
}
func Forbidden() *Error {
	return NewError(http.StatusForbidden, "forbidden", "You are not allowed to do this.")
}
func BadRequest(msg string) *Error {
	return NewError(http.StatusBadRequest, "bad_request", msg)
}

// Validation collects field errors; nil-safe Err() returns nil when there are none.
type Validation struct{ details []FieldError }

func (v *Validation) Add(field, message string) {
	v.details = append(v.details, FieldError{field, message})
}

func (v *Validation) Err() error {
	if len(v.details) == 0 {
		return nil
	}
	return &Error{Status: http.StatusUnprocessableEntity, Code: "validation_error", Message: "Request validation failed.", Details: v.details}
}

func ValidationError(field, message string) error {
	v := &Validation{}
	v.Add(field, message)
	return v.Err()
}

// HandlerFunc is an http handler that returns an error instead of writing it.
type HandlerFunc func(w http.ResponseWriter, r *http.Request) error

func Handle(h HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := h(w, r); err != nil {
			WriteError(w, r, err)
		}
	}
}

// WriteError renders err; anything that is not an *Error is logged and becomes a generic 500.
func WriteError(w http.ResponseWriter, r *http.Request, err error) {
	var apiErr *Error
	if !errors.As(err, &apiErr) {
		Logger(r.Context()).Error("internal error", "error", safeError(err))
		apiErr = NewError(http.StatusInternalServerError, "internal_error", "Something went wrong.")
	}
	if apiErr.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(apiErr.RetryAfter))
	}
	body := map[string]any{"code": apiErr.Code, "message": apiErr.Message}
	if apiErr.Code == "validation_error" {
		body["details"] = apiErr.Details
	}
	WriteJSON(w, apiErr.Status, map[string]any{"error": body})
}

func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// DecodeJSON reads one JSON object into dst. Unknown fields are ignored (SPEC 1).
// Over 1 MB → 413; no JSON content type or not valid JSON → 400;
// valid JSON that is not an object, or a known field with the wrong JSON type → 422.
func DecodeJSON(r *http.Request, dst any) error {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		return BadRequest("Content-Type must be application/json.")
	}
	body, err := io.ReadAll(r.Body) // capped at 1 MB by SecurityHeaders
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		return NewError(http.StatusRequestEntityTooLarge, "payload_too_large", "Request body is larger than 1 MB.")
	}
	if err != nil {
		return BadRequest("Could not read the request body.")
	}
	body = bytes.TrimSpace(body)
	if !json.Valid(body) {
		return BadRequest("Request body is not valid JSON.")
	}
	// encoding/json would silently turn these into U+FFFD and we would store it.
	if !utf8.Valid(body) || hasLoneSurrogate(body) {
		return BadRequest("Request body is not well-formed Unicode.")
	}
	if body[0] != '{' {
		return ValidationError("body", "must be a JSON object")
	}
	var typeErr *json.UnmarshalTypeError
	switch err := json.Unmarshal(body, dst); {
	case errors.As(err, &typeErr):
		field := typeErr.Field
		if field == "" {
			field = "body"
		}
		return ValidationError(field, "has the wrong type, expected "+jsonKind(typeErr.Type.Kind().String()))
	case err != nil:
		return BadRequest("Request body is not valid JSON.")
	}
	return nil
}

func jsonKind(goKind string) string {
	switch {
	case strings.HasPrefix(goKind, "int"), strings.HasPrefix(goKind, "uint"), strings.HasPrefix(goKind, "float"):
		return "number"
	case goKind == "bool":
		return "boolean"
	case goKind == "string":
		return "string"
	}
	return "object"
}

// Page is a validated ?page=&per_page= pair.
type Page struct{ Page, PerPage int }

func (p Page) Offset() int { return (p.Page - 1) * p.PerPage }

func ParsePage(r *http.Request) (Page, error) {
	v := &Validation{}
	q := r.URL.Query()
	parse := func(key string, def, max int, msg string) int {
		if !q.Has(key) {
			return def
		}
		n, err := strconv.Atoi(q.Get(key))
		if err != nil || n < 1 || n > max {
			v.Add(key, msg)
		}
		return n
	}
	// page is capped at MaxInt32 only so the OFFSET arithmetic cannot overflow.
	p := Page{
		Page:    parse("page", 1, math.MaxInt32, "must be an integer >= 1"),
		PerPage: parse("per_page", 20, 100, "must be an integer between 1 and 100"),
	}
	return p, v.Err()
}

func Paginated[T any](data []T, p Page, total int64) map[string]any {
	if data == nil {
		data = []T{}
	}
	return map[string]any{"data": data, "meta": map[string]any{"page": p.Page, "per_page": p.PerPage, "total": total}}
}

// ParseID parses a canonical UUID path parameter; anything else is a 404 (SPEC 5).
func ParseID(s string) (uuid.UUID, error) {
	id, err := uuid.Parse(s)
	if len(s) != 36 || err != nil {
		return uuid.Nil, NotFound()
	}
	return id, nil
}

// HasControlChars reports U+0000–U+001F or U+007F, which name and filename reject (SPEC 1).
func HasControlChars(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0
}

// safeError renders an error for the log. Postgres errors are reduced to SQLSTATE, message and
// constraint: their Detail/Where fields can echo row values (password hashes, emails).
func safeError(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return "postgres " + pgErr.Code + ": " + pgErr.Message + " (constraint " + pgErr.ConstraintName + ")"
	}
	return err.Error()
}

// hasLoneSurrogate scans valid JSON for a \uD800–\uDFFF escape that is not part of a
// high+low surrogate pair.
func hasLoneSurrogate(b []byte) bool {
	hex4 := func(i int) (rune, bool) {
		if i+4 > len(b) {
			return 0, false
		}
		var r rune
		for _, c := range b[i : i+4] {
			switch {
			case c >= '0' && c <= '9':
				r = r<<4 | rune(c-'0')
			case c >= 'a' && c <= 'f':
				r = r<<4 | rune(c-'a'+10)
			case c >= 'A' && c <= 'F':
				r = r<<4 | rune(c-'A'+10)
			default:
				return 0, false
			}
		}
		return r, true
	}
	inString := false
	for i := 0; i < len(b); i++ {
		switch {
		case b[i] == '"':
			inString = !inString
		case inString && b[i] == '\\':
			i++
			if i >= len(b) || b[i] != 'u' {
				continue
			}
			r, ok := hex4(i + 1)
			if !ok {
				continue
			}
			i += 4
			switch {
			case r >= 0xDC00 && r <= 0xDFFF:
				return true
			case r >= 0xD800 && r <= 0xDBFF:
				if i+2 >= len(b) || b[i+1] != '\\' || b[i+2] != 'u' {
					return true
				}
				lo, ok := hex4(i + 3)
				if !ok || lo < 0xDC00 || lo > 0xDFFF {
					return true
				}
				i += 6
			}
		}
	}
	return false
}
