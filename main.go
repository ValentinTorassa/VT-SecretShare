// VT-SecretShare - zero-knowledge one-time secret sharing.
//
// The browser encrypts the secret with a random AES-256-GCM key (WebCrypto).
// Only the ciphertext is POSTed here; the key lives in the URL #fragment and is
// never transmitted to this server. We hand the ciphertext to Redis with a TTL.
// The first GET burns it via GETDEL. The server therefore never sees plaintext,
// never sees the key, and keeps nothing after a single read or the TTL - there
// is nothing useful to steal from process memory, logs, or a Redis dump.
package main

import (
	"context"
	cryptorand "crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

//go:embed web
var webFS embed.FS

type config struct {
	port          string
	redisAddr     string
	redisPassword string
	baseURL       string
	maxCipherLen  int
	defaultTTL    time.Duration
	maxTTL        time.Duration

	// Per-client rate limits (see ratelimit.go). A limit <= 0 disables it.
	createLimit    int
	createWindow   time.Duration
	readLimit      int
	readWindow     time.Duration
	rateLimitSalt  string
	trustedProxies []netip.Prefix
}

func loadConfig() config {
	c := config{
		port:          env("PORT", "8080"),
		redisAddr:     env("REDIS_ADDR", "127.0.0.1:6379"),
		redisPassword: env("REDIS_PASSWORD", ""),
		baseURL:       strings.TrimRight(env("BASE_URL", ""), "/"),
		maxCipherLen:  envInt("MAX_CIPHERTEXT_BYTES", 256*1024), // ~256 KB ciphertext
		defaultTTL:    time.Duration(envInt("DEFAULT_TTL_SECONDS", 24*3600)) * time.Second,
		maxTTL:        time.Duration(envInt("MAX_TTL_SECONDS", 7*24*3600)) * time.Second,

		createLimit:   envInt("RATE_LIMIT_CREATE", 20),
		createWindow:  envSeconds("RATE_LIMIT_CREATE_WINDOW_SECONDS", 600),
		readLimit:     envInt("RATE_LIMIT_READ", 30),
		readWindow:    envSeconds("RATE_LIMIT_READ_WINDOW_SECONDS", 600),
		rateLimitSalt: os.Getenv("RATE_LIMIT_SALT"),
	}
	if c.baseURL == "" {
		c.baseURL = "http://localhost:" + c.port
	}
	proxies, err := parseTrustedProxies(env("TRUSTED_PROXY_CIDRS", defaultTrustedProxies))
	if err != nil {
		log.Fatal(err)
	}
	c.trustedProxies = proxies
	return c
}

type server struct {
	cfg   config
	store *Store

	createLimiter *rateLimiter
	readLimiter   *rateLimiter
}

func newServer(cfg config, store *Store) *server {
	salt := []byte(cfg.rateLimitSalt)
	if len(salt) == 0 {
		// Without a configured salt, counter keys change on every restart, so
		// counters reset then and are not shared between instances.
		salt = make([]byte, 32)
		if _, err := io.ReadFull(cryptorand.Reader, salt); err != nil {
			log.Fatalf("cannot generate rate-limit salt: %v", err)
		}
	}
	return &server{
		cfg:   cfg,
		store: store,
		// Creating is not a guessing surface, and with Redis down the Save that
		// follows fails anyway, so a limiter outage should not block anyone:
		// fail open (with a log line).
		createLimiter: &rateLimiter{name: "create", limit: int64(cfg.createLimit), window: cfg.createWindow, failOpen: true, store: store, salt: salt},
		// Reading is the brute-force surface (reveal, and meta as an existence
		// oracle). If we cannot count, we refuse rather than go silently
		// unlimited: fail closed. It costs nothing, since the secret lives in
		// the same Redis.
		readLimiter: &rateLimiter{name: "read", limit: int64(cfg.readLimit), window: cfg.readWindow, failOpen: false, store: store, salt: salt},
	}
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/secret", s.rateLimited(s.createLimiter, s.handleCreate))
	mux.HandleFunc("POST /api/secret/{id}/reveal", s.rateLimited(s.readLimiter, s.handleBurn))
	mux.HandleFunc("GET /api/secret/{id}/meta", s.rateLimited(s.readLimiter, s.handleMeta))
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /s/{id}", s.servePage("web/view.html"))
	mux.HandleFunc("GET /{$}", s.servePage("web/index.html"))
	mux.Handle("GET /web/", http.FileServerFS(webFS))
	return securityHeaders(mux)
}

func describeLimit(n int, window time.Duration) string {
	if n <= 0 {
		return "off"
	}
	return fmt.Sprintf("%d/%s", n, window)
}

func main() {
	cfg := loadConfig()
	store := NewStore(cfg.redisAddr, cfg.redisPassword)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := store.Ping(ctx); err != nil {
		log.Fatalf("cannot reach redis at %s: %v", cfg.redisAddr, err)
	}
	defer store.Close()

	s := newServer(cfg, store)

	srv := &http.Server{
		Addr:              ":" + cfg.port,
		Handler:           s.routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("VT-SecretShare listening on %s (base url %s, redis %s)", srv.Addr, cfg.baseURL, cfg.redisAddr)
	saltSource := "RATE_LIMIT_SALT"
	if cfg.rateLimitSalt == "" {
		saltSource = "random per process (counters reset on restart; set RATE_LIMIT_SALT to keep them)"
	}
	log.Printf("rate limits per client: create %s (fail-open), read %s (fail-closed); trusted proxies %v; key salt: %s",
		describeLimit(cfg.createLimit, cfg.createWindow), describeLimit(cfg.readLimit, cfg.readWindow), cfg.trustedProxies, saltSource)
	log.Fatal(srv.ListenAndServe())
}

// ---- handlers ----

type createRequest struct {
	Ciphertext string `json:"ciphertext"`
	TTLSeconds int    `json:"ttl_seconds"`
}

type createResponse struct {
	ID         string `json:"id"`
	ShareURL   string `json:"share_url"`
	TTLSeconds int    `json:"ttl_seconds"`
	ExpiresAt  string `json:"expires_at"`
}

func (s *server) handleCreate(w http.ResponseWriter, r *http.Request) {
	var req createRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, int64(s.cfg.maxCipherLen)+1024))
	if err := dec.Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}

	req.Ciphertext = strings.TrimSpace(req.Ciphertext)
	if req.Ciphertext == "" {
		writeErr(w, http.StatusBadRequest, "ciphertext is required")
		return
	}
	if len(req.Ciphertext) > s.cfg.maxCipherLen {
		writeErr(w, http.StatusRequestEntityTooLarge, "ciphertext too large")
		return
	}
	// We don't decrypt, but we sanity-check it's real base64 so we don't store junk.
	if _, err := base64.StdEncoding.DecodeString(req.Ciphertext); err != nil {
		writeErr(w, http.StatusBadRequest, "ciphertext must be base64")
		return
	}

	ttl := s.cfg.defaultTTL
	if req.TTLSeconds > 0 {
		ttlSeconds := req.TTLSeconds
		maxTTLSeconds := int(s.cfg.maxTTL / time.Second)
		if ttlSeconds > maxTTLSeconds {
			ttlSeconds = maxTTLSeconds
		}
		if ttlSeconds < int(time.Minute/time.Second) {
			ttlSeconds = int(time.Minute / time.Second)
		}
		ttl = time.Duration(ttlSeconds) * time.Second
	}
	if ttl > s.cfg.maxTTL {
		ttl = s.cfg.maxTTL
	}
	if ttl < time.Minute {
		ttl = time.Minute
	}

	id, err := newID()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not generate id")
		return
	}

	if err := s.store.Save(r.Context(), id, req.Ciphertext, ttl); err != nil {
		if errors.Is(err, ErrExists) {
			writeErr(w, http.StatusConflict, "id collision, retry")
			return
		}
		log.Printf("save error: %v", err)
		writeErr(w, http.StatusBadGateway, "storage unavailable")
		return
	}

	writeJSON(w, http.StatusCreated, createResponse{
		ID:         id,
		ShareURL:   s.cfg.baseURL + "/s/" + id,
		TTLSeconds: int(ttl.Seconds()),
		ExpiresAt:  time.Now().UTC().Add(ttl).Format(time.RFC3339),
	})
}

// handleBurn reads-and-deletes. POST plus a custom header prevents link previews
// and cross-origin simple requests from consuming the secret.
func (s *server) handleBurn(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-VT-Reveal") != "1" {
		writeErr(w, http.StatusForbidden, "explicit reveal required")
		return
	}
	id := r.PathValue("id")
	ciphertext, err := s.store.Burn(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeErr(w, http.StatusNotFound, "this secret is gone - wrong link, expired, or already viewed")
			return
		}
		log.Printf("burn error: %v", err)
		writeErr(w, http.StatusBadGateway, "storage unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ciphertext": ciphertext})
}

// handleMeta reports whether a secret is still alive (and for how long) WITHOUT
// consuming it, so the viewer page can warn "this will self-destruct" before
// the user commits to revealing it.
func (s *server) handleMeta(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ttl, err := s.store.TTL(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeErr(w, http.StatusNotFound, "gone")
			return
		}
		writeErr(w, http.StatusBadGateway, "storage unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"alive":       true,
		"ttl_seconds": int(ttl.Seconds()),
		"expires_at":  time.Now().UTC().Add(ttl).Format(time.RFC3339),
	})
}

// healthPingTimeout is how long /healthz waits for Redis to answer PING.
// Redis is on loopback, so anything slower than this is effectively down.
const healthPingTimeout = time.Second

// handleHealth answers 200 {"status":"ok"} only when Redis answers PING within
// healthPingTimeout, 503 otherwise. It is not rate limited; monitors poll it.
func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), healthPingTimeout)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		log.Printf("healthz: redis ping failed: %v", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable", "error": "redis unreachable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) servePage(name string) http.HandlerFunc {
	page, err := webFS.ReadFile(name)
	if err != nil {
		log.Fatalf("missing embedded page %s: %v", name, err)
	}
	body := renderPage(page)
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(body)
	}
}

// ---- helpers ----

func newID() (string, error) {
	b := make([]byte, 16) // 128 bits of entropy
	if _, err := io.ReadFull(cryptorand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// envSeconds reads a positive number of seconds, falling back to def.
func envSeconds(k string, def int) time.Duration {
	n := envInt(k, def)
	if n <= 0 {
		n = def
	}
	return time.Duration(n) * time.Second
}
