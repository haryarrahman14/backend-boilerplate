package httpx

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

type ctxKey struct{}

// reqInfo is the per-request state shared by the middleware chain and the handlers.
type reqInfo struct {
	id       string
	clientIP string
	userID   string
	logger   *slog.Logger
}

func info(ctx context.Context) *reqInfo {
	ri, _ := ctx.Value(ctxKey{}).(*reqInfo)
	return ri
}

// Logger returns the request-scoped logger (carries request_id), or the default logger.
func Logger(ctx context.Context) *slog.Logger {
	if ri := info(ctx); ri != nil {
		return ri.logger
	}
	return slog.Default()
}

func RequestID(ctx context.Context) string {
	if ri := info(ctx); ri != nil {
		return ri.id
	}
	return ""
}

func ClientIP(ctx context.Context) string {
	if ri := info(ctx); ri != nil {
		return ri.clientIP
	}
	return ""
}

// SetUserID makes the authenticated user id show up on the request log line.
func SetUserID(ctx context.Context, id string) {
	if ri := info(ctx); ri != nil {
		ri.userID = id
	}
}

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// RequestContext assigns the request id, resolves the client IP, recovers panics
// and writes one structured log line per request. It must be the outermost middleware.
func RequestContext(base *slog.Logger, proxyHops int, trustedProxies []netip.Prefix) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			id := r.Header.Get("X-Request-Id")
			if !requestIDPattern.MatchString(id) {
				id = uuid.NewString()
			}
			ri := &reqInfo{id: id, clientIP: clientIP(r, proxyHops, trustedProxies), logger: base.With("request_id", id)}
			w.Header().Set("X-Request-Id", id)
			sw := &statusWriter{ResponseWriter: w}
			r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, ri))

			defer func() {
				if rec := recover(); rec != nil {
					if rec == http.ErrAbortHandler {
						panic(rec)
					}
					ri.logger.Error("panic", "panic", rec, "stack", string(debug.Stack()))
					if sw.status == 0 {
						WriteError(sw, r, NewError(http.StatusInternalServerError, "internal_error", "Something went wrong."))
					}
				}
				attrs := []any{
					"method", r.Method, "path", r.URL.Path, "status", sw.status,
					"duration_ms", time.Since(start).Milliseconds(), "ip", ri.clientIP,
				}
				if ri.userID != "" {
					attrs = append(attrs, "user_id", ri.userID)
				}
				ri.logger.Info("request", attrs...)
			}()
			next.ServeHTTP(sw, r)
		})
	}
}

// clientIP resolves the client address (SPEC 2, TRUSTED_PROXY_HOPS). With hops = N > 0 it is the
// N-th X-Forwarded-For entry from the right: our N proxies each appended one entry, everything
// to the left of that was written by the client. A missing or non-IP entry falls back to the
// socket peer. The result is always a parsed IP, IPv4-mapped IPv6 shown as IPv4, no zone.
func clientIP(r *http.Request, hops int, trusted []netip.Prefix) string {
	peer := peerIP(r.RemoteAddr)
	if hops > 0 && fromTrustedProxy(peer, trusted) {
		var entries []string
		for _, h := range r.Header.Values("X-Forwarded-For") {
			entries = append(entries, strings.Split(h, ",")...)
		}
		if i := len(entries) - hops; i >= 0 {
			if addr, err := netip.ParseAddr(strings.TrimSpace(entries[i])); err == nil {
				return addr.WithZone("").Unmap().String()
			}
		}
	}
	return peer
}

// fromTrustedProxy: X-Forwarded-For is only honoured when the socket peer is one of our proxies.
func fromTrustedProxy(peer string, trusted []netip.Prefix) bool {
	addr, err := netip.ParseAddr(peer)
	if err != nil {
		return false
	}
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// peerIP is the socket peer as a normalised IP, or "" (stored as NULL) if it is not one.
func peerIP(remoteAddr string) string {
	if ap, err := netip.ParseAddrPort(remoteAddr); err == nil {
		return ap.Addr().WithZone("").Unmap().String()
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if addr, perr := netip.ParseAddr(host); err == nil && perr == nil {
		return addr.WithZone("").Unmap().String()
	}
	return ""
}

// SecurityHeaders sets the hardening headers from SPEC 4, plus a 1 MB body cap and a request deadline.
func SecurityHeaders(production bool, timeout time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "no-referrer")
			if production {
				h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// CORS allows only the configured origins, with credentials. Preflights are answered here.
func CORS(origins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			preflight := r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != ""
			h := w.Header()
			h.Add("Vary", "Origin")
			allowed := origin != "" && slices.Contains(origins, origin)
			if allowed {
				h.Set("Access-Control-Allow-Origin", origin)
				h.Set("Access-Control-Allow-Credentials", "true")
				h.Set("Access-Control-Expose-Headers", "X-Request-Id, Retry-After")
			}
			if preflight {
				if allowed {
					h.Add("Vary", "Access-Control-Request-Method")
					h.Add("Vary", "Access-Control-Request-Headers")
					h.Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
					h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Request-Id")
					h.Set("Access-Control-Max-Age", "600")
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
