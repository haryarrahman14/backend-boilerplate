// Package ratelimit is an in-memory fixed-window limiter keyed by client IP.
//
// Ceiling: SINGLE-INSTANCE ONLY. Counters live in this process; with more than one
// replica each gets its own budget. Swap for Redis (INCR + EXPIRE) when scaled out.
package ratelimit

import (
	"math"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"boilerplate/internal/platform/httpx"
)

// MaxKeys caps memory. A new key arriving while the map is full is allowed and not tracked
// (SPEC 4): refusing it would let someone with 100 000 addresses lock everyone else out.
const MaxKeys = 100_000

type window struct {
	start time.Time
	count int
}

type Limiter struct {
	limit     int
	period    time.Duration
	maxKeys   int
	mu        sync.Mutex
	windows   map[string]*window
	lastSweep time.Time
}

func New(limit int, period time.Duration) *Limiter {
	return &Limiter{limit: limit, period: period, maxKeys: MaxKeys, windows: make(map[string]*window)}
}

// Key groups IPv6 clients by their /64 (one subscriber usually owns a whole /64);
// IPv4 and anything unparsable are used as is.
func Key(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.String()
	}
	p, _ := addr.WithZone("").Prefix(64)
	return p.String()
}

// Allow counts one hit for key at now. When rejected it returns how long until a retry can succeed.
func (l *Limiter) Allow(key string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	w, ok := l.windows[key]
	if !ok || now.Sub(w.start) >= l.period {
		if !ok && len(l.windows) >= l.maxKeys {
			l.sweep(now)
			if len(l.windows) >= l.maxKeys {
				return true, 0 // full: allowed, untracked
			}
		}
		w = &window{start: now}
		l.windows[key] = w
		l.sweep(now)
	}
	if w.count >= l.limit {
		return false, w.start.Add(l.period).Sub(now)
	}
	w.count++
	return true, 0
}

// sweep drops expired windows, at most once per period (never a full scan per request).
func (l *Limiter) sweep(now time.Time) {
	if now.Sub(l.lastSweep) < l.period {
		return
	}
	for k, w := range l.windows {
		if now.Sub(w.start) >= l.period {
			delete(l.windows, k)
		}
	}
	l.lastSweep = now
}

// Middleware rejects with 429 rate_limited and Retry-After (whole seconds, rounded up).
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ok, retry := l.Allow(Key(httpx.ClientIP(r.Context())), time.Now())
		if !ok {
			secs := int(math.Ceil(retry.Seconds()))
			w.Header().Set("Retry-After", strconv.Itoa(max(secs, 1)))
			httpx.WriteError(w, r, httpx.NewError(http.StatusTooManyRequests, "rate_limited", "Too many requests, try again later."))
			return
		}
		next.ServeHTTP(w, r)
	})
}
