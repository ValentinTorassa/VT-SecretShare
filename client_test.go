package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ValentinTorassa/VT-SecretShare/internal/secretshare"
)

// The command line client (internal/secretshare, used by cmd/vtss) against the
// real handlers and an isolated Redis: what vtss does end to end.

func clientServer(t *testing.T, tune func(*config)) (*httptest.Server, *Store) {
	t.Helper()
	store := testStore(t)
	var h http.Handler
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	t.Cleanup(ts.Close)
	cfg := testConfig()
	cfg.baseURL = ts.URL
	cfg.maxCipherLen = 256 * 1024
	if tune != nil {
		tune(&cfg)
	}
	h = newServer(cfg, store).routes()
	return ts, store
}

func TestClientCreateThenRevealOnce(t *testing.T) {
	ts, store := clientServer(t, nil)
	ctx := context.Background()
	c := &secretshare.Client{}
	const secret = "sk_demo_not_a_real_key 🔒\nsecond line"

	created, err := c.Create(ctx, ts.URL, []byte(secret), 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if created.TTL != 10*time.Minute || time.Until(created.ExpiresAt) < 9*time.Minute {
		t.Fatalf("ttl %s, expires %s", created.TTL, created.ExpiresAt)
	}
	link := created.Link.String()
	if !strings.HasPrefix(link, ts.URL+"/s/") || strings.ContainsAny(link, "?&") {
		t.Fatalf("link %q", link)
	}
	// Zero-knowledge: what Redis holds contains neither the secret nor the key.
	stored, err := store.rdb.Get(ctx, keyPrefix+created.Link.ID).Result()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, "sk_demo") || strings.Contains(stored, created.Link.Key) {
		t.Fatal("the store holds the plaintext or the key")
	}

	parsed, err := secretshare.ParseLink(link, true)
	if err != nil {
		t.Fatal(err)
	}
	if st, err := c.Check(ctx, parsed); err != nil || st.TTL <= 0 {
		t.Fatalf("check before reveal: %+v, %v", st, err)
	}
	got, err := c.Reveal(ctx, parsed)
	if err != nil || string(got) != secret {
		t.Fatalf("reveal: %q, %v", got, err)
	}
	if _, err := c.Reveal(ctx, parsed); !errors.Is(err, secretshare.ErrGone) {
		t.Fatalf("second reveal: %v", err)
	}
	if _, err := c.Check(ctx, parsed); !errors.Is(err, secretshare.ErrGone) {
		t.Fatalf("check after reveal: %v", err)
	}
}

func TestClientWrongKeyKeepsTheSecret(t *testing.T) {
	ts, _ := clientServer(t, nil)
	ctx := context.Background()
	c := &secretshare.Client{}
	created, err := c.Create(ctx, ts.URL, []byte("synthetic"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if created.TTL != time.Hour { // the server's default in testConfig
		t.Fatalf("default ttl %s", created.TTL)
	}
	_, otherKey, _ := secretshare.Encrypt([]byte("x"))
	wrong := created.Link
	wrong.Key = otherKey
	if _, err := c.Reveal(ctx, wrong); !errors.Is(err, secretshare.ErrWrongKey) {
		t.Fatalf("wrong key: %v", err)
	}
	if got, err := c.Reveal(ctx, created.Link); err != nil || string(got) != "synthetic" {
		t.Fatalf("right key after a wrong one: %q, %v", got, err)
	}
}

func TestClientReportsRateLimitAsRetry(t *testing.T) {
	ts, _ := clientServer(t, func(c *config) { c.createLimit = 1 })
	ctx := context.Background()
	c := &secretshare.Client{}
	if _, err := c.Create(ctx, ts.URL, []byte("one"), 0); err != nil {
		t.Fatal(err)
	}
	_, err := c.Create(ctx, ts.URL, []byte("two"), 0)
	var retry *secretshare.RetryError
	if !errors.As(err, &retry) || retry.After <= 0 || retry.After > time.Minute {
		t.Fatalf("over the limit: %v", err)
	}
}

func TestClientLargestSecretIsAccepted(t *testing.T) {
	ts, _ := clientServer(t, nil)
	c := &secretshare.Client{}
	big := []byte(strings.Repeat("a", secretshare.MaxPlaintext))
	created, err := c.Create(context.Background(), ts.URL, big, 0)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Reveal(context.Background(), created.Link)
	if err != nil || len(got) != len(big) {
		t.Fatalf("reveal of the largest secret: %d bytes, %v", len(got), err)
	}
	if _, err := c.Create(context.Background(), ts.URL, append(big, 'a'), 0); !errors.Is(err, secretshare.ErrTooLarge) {
		t.Fatalf("one byte over: %v", err)
	}
}

func TestInstallScriptIsServed(t *testing.T) {
	h := newServer(testConfig(), deadStore(t)).routes()
	rec := do(t, h, request{method: http.MethodGet, path: "/install.sh", remote: "127.0.0.1:1"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type %q", ct)
	}
	body := rec.Body.String()
	if !strings.HasPrefix(body, "#!/bin/sh\n") || !strings.Contains(body, "checksums.txt") {
		t.Errorf("unexpected script: %.80q", body)
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != contentSecurityPolicy {
		t.Errorf("CSP %q", got)
	}
}
