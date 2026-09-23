package main

// Per-client rate limiting, counted in Redis.
//
// Counters live in Redis rather than process memory, so they survive restarts
// and are shared by every instance pointed at the same Redis. Each limiter is a
// fixed window: the first request creates the counter with a TTL of one window,
// later requests only increment it, and the counter disappears when the window
// ends (see Store.Hit for the atomic INCR+PEXPIRE script).
//
// Redis never holds a raw IP. The counter key is an HMAC-SHA256 of the client
// bucket under a server-side salt (RATE_LIMIT_SALT, or a random per-process salt
// when it is unset), and it expires with its window, so Redis keeps at most one
// window's worth of opaque hashes. Client addresses are never logged.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const (
	// limiterTimeout bounds each limiter round trip to Redis, so a slow Redis
	// falls through to the limiter's fail-open/fail-closed policy instead of
	// holding the request.
	limiterTimeout = 500 * time.Millisecond
	// unavailableRetryAfter is the Retry-After a fail-closed limiter sends while
	// it cannot reach Redis.
	unavailableRetryAfter = 10 * time.Second
	// defaultTrustedProxies is where cloudflared connects from on valensrv.
	defaultTrustedProxies = "127.0.0.0/8,::1/128"
)

type rateLimiter struct {
	name     string // "create" or "read": part of the Redis key and of log lines
	limit    int64  // requests allowed per client per window; <= 0 disables the limiter
	window   time.Duration
	failOpen bool // true: let requests through when Redis cannot count them
	store    *Store
	salt     []byte
}

func (l *rateLimiter) enabled() bool { return l != nil && l.limit > 0 }

// allow counts one request from client and reports whether it fits in the
// current window. When it does not, retryAfter is the time left in the window.
func (l *rateLimiter) allow(ctx context.Context, client string) (ok bool, retryAfter time.Duration, err error) {
	ctx, cancel := context.WithTimeout(ctx, limiterTimeout)
	defer cancel()
	count, ttl, err := l.store.Hit(ctx, l.name+":"+l.key(client), l.window)
	if err != nil {
		return false, 0, err
	}
	if count <= l.limit {
		return true, 0, nil
	}
	if ttl <= 0 {
		ttl = l.window
	}
	return false, ttl, nil
}

// key turns a client bucket into the opaque Redis key component.
func (l *rateLimiter) key(client string) string {
	mac := hmac.New(sha256.New, l.salt)
	mac.Write([]byte(client))
	return hex.EncodeToString(mac.Sum(nil)[:16])
}

// rateLimited wraps next with l. Over the limit it answers 429 with
// Retry-After. When Redis cannot count, a fail-open limiter logs and lets the
// request through; a fail-closed one answers 503 without calling next.
func (s *server) rateLimited(l *rateLimiter, next http.HandlerFunc) http.HandlerFunc {
	if !l.enabled() {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		client := clientBucket(clientAddr(r, s.cfg.trustedProxies))
		ok, retryAfter, err := l.allow(r.Context(), client)
		if err != nil {
			if l.failOpen {
				log.Printf("rate limit %s: redis unavailable, failing open: %v", l.name, err)
				next(w, r)
				return
			}
			log.Printf("rate limit %s: redis unavailable, failing closed: %v", l.name, err)
			w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(unavailableRetryAfter)))
			writeErr(w, http.StatusServiceUnavailable, "service temporarily unavailable - try again shortly")
			return
		}
		if !ok {
			secs := retryAfterSeconds(retryAfter)
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			writeErr(w, http.StatusTooManyRequests, fmt.Sprintf("too many requests - try again in %d seconds", secs))
			return
		}
		next(w, r)
	}
}

// retryAfterSeconds rounds up to whole seconds (Retry-After has no fractions)
// and never returns less than 1, so a client never retries too early.
func retryAfterSeconds(d time.Duration) int {
	secs := int((d + time.Second - 1) / time.Second)
	if secs < 1 {
		return 1
	}
	return secs
}

// clientAddr returns the address r is rate-limited by. Cloudflare sets
// CF-Connecting-IP and cloudflared forwards it from localhost, so the header is
// honoured only when the TCP peer is a trusted proxy (loopback by default).
// From any other peer the header is attacker-controlled and ignored: a direct
// connection over the LAN or tailnet cannot choose its own bucket.
// X-Forwarded-For is never read; nothing in this service relied on it.
func clientAddr(r *http.Request, trusted []netip.Prefix) netip.Addr {
	peer := parseAddr(r.RemoteAddr)
	if peer.IsValid() && inPrefixes(peer, trusted) {
		if forwarded := parseAddr(strings.TrimSpace(r.Header.Get("CF-Connecting-IP"))); forwarded.IsValid() {
			return forwarded
		}
	}
	return peer
}

// parseAddr accepts "ip:port", "[ip]:port" or a bare IP, and normalises
// IPv4-mapped IPv6 and zones away. It returns the zero Addr on garbage.
func parseAddr(s string) netip.Addr {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap().WithZone("")
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap().WithZone("")
	}
	return netip.Addr{}
}

func inPrefixes(a netip.Addr, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// clientBucket groups addresses the way a client can cheaply rotate them: one
// bucket per IPv4 address, one per IPv6 /64 (a single host usually has a whole
// /64 to itself, so per-address IPv6 limits are trivial to dodge).
func clientBucket(a netip.Addr) string {
	if !a.IsValid() {
		return "unknown"
	}
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.String()
	}
	return a.String()
}

// parseTrustedProxies reads a comma-separated list of CIDRs or bare IPs.
func parseTrustedProxies(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, field := range strings.Split(s, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		if p, err := netip.ParsePrefix(field); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a := parseAddr(field)
		if !a.IsValid() {
			return nil, fmt.Errorf("TRUSTED_PROXY_CIDRS: %q is not an IP or CIDR", field)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}
