// VT-SecretShare — zero-knowledge one-time secret sharing.
//
// The browser encrypts the secret with a random AES-256-GCM key (WebCrypto).
// Only the ciphertext is POSTed here; the key lives in the URL #fragment and is
// never transmitted to this server. We hand the ciphertext to Redis with a TTL.
// The first GET burns it via GETDEL. The server therefore never sees plaintext,
// never sees the key, and keeps nothing after a single read or the TTL — there
// is nothing useful to steal from process memory, logs, or a Redis dump.
package main

import (
	"context"
	cryptorand "crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
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
	}
	if c.baseURL == "" {
		c.baseURL = "http://localhost:" + c.port
	}
	return c
}

type server struct {
	cfg   config
	store *Store
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

	s := &server{cfg: cfg, store: store}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/secret", s.handleCreate)
	mux.HandleFunc("GET /api/secret/{id}", s.handleBurn)
	mux.HandleFunc("GET /api/secret/{id}/meta", s.handleMeta)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /s/{id}", s.servePage("web/view.html"))
	mux.HandleFunc("GET /{$}", s.servePage("web/index.html"))
	mux.Handle("GET /web/", http.FileServerFS(webFS))

	srv := &http.Server{
		Addr:              ":" + cfg.port,
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("VT-SecretShare listening on %s (base url %s, redis %s)", srv.Addr, cfg.baseURL, cfg.redisAddr)
	log.Fatal(srv.ListenAndServe())
}

// ---- handlers ----

type createRequest struct {
	Ciphertext string `json:"ciphertext"`
	TTLSeconds int    `json:"ttl_seconds"`
}

type createResponse struct {
	ID         string `json:"id"`
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
		ttl = time.Duration(req.TTLSeconds) * time.Second
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
		TTLSeconds: int(ttl.Seconds()),
		ExpiresAt:  time.Now().UTC().Add(ttl).Format(time.RFC3339),
	})
}

// handleBurn reads-and-deletes. This is the destructive endpoint: it must only
// be hit on an explicit user action, never by link-preview crawlers, or the
// secret gets consumed before the human sees it. The front-end gates it behind
// a button click for exactly that reason.
func (s *server) handleBurn(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ciphertext, err := s.store.Burn(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeErr(w, http.StatusNotFound, "this secret is gone — wrong link, expired, or already viewed")
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
		"alive":           true,
		"ttl_seconds":     int(ttl.Seconds()),
		"expires_at":      time.Now().UTC().Add(ttl).Format(time.RFC3339),
	})
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "redis down")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) servePage(name string) http.HandlerFunc {
	body, err := webFS.ReadFile(name)
	if err != nil {
		log.Fatalf("missing embedded page %s: %v", name, err)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(body)
	}
}

// ---- helpers ----

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No referrer => the #fragment key can't leak via Referer headers.
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

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
