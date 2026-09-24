package main

import (
	"context"
	"io/fs"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Uses the isolated redis-server and the request helpers of the other tests.

var wantSecurityHeaders = map[string]string{
	"Content-Security-Policy":      "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
	"Referrer-Policy":              "no-referrer",
	"X-Content-Type-Options":       "nosniff",
	"X-Frame-Options":              "DENY",
	"Cross-Origin-Opener-Policy":   "same-origin",
	"Cross-Origin-Resource-Policy": "same-origin",
	"Strict-Transport-Security":    "max-age=31536000",
}

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	store := testStore(t)
	cfg := testConfig()
	cfg.readLimit = 3
	h := newServer(cfg, store).routes()
	if err := store.Save(context.Background(), "live", "b3BhcXVl", time.Minute); err != nil {
		t.Fatal(err)
	}
	const client = "198.51.100.30:7000"
	get := func(path string) request { return request{method: http.MethodGet, path: path, remote: client} }
	cases := []struct {
		name        string
		rq          request
		status      int
		contentType string
		cache       string
	}{
		{"create page", get("/"), http.StatusOK, "text/html; charset=utf-8", "no-store"},
		{"view page", get("/s/live"), http.StatusOK, "text/html; charset=utf-8", "no-store"},
		{"stylesheet", get("/web/fx.css?v=" + assetVersion()), http.StatusOK, "text/css; charset=utf-8", "public, max-age=31536000, immutable"},
		{"script", get("/web/view.js?v=" + assetVersion()), http.StatusOK, "text/javascript; charset=utf-8", "public, max-age=31536000, immutable"},
		{"vendored module", get("/web/vendor/three.module.min.js"), http.StatusOK, "text/javascript; charset=utf-8", "public, max-age=31536000, immutable"},
		{"image", get("/web/penguin-ink.png"), http.StatusOK, "image/png", "public, max-age=31536000, immutable"},
		// The file server drops Cache-Control on errors: a 404 is not immutable.
		{"missing asset", get("/web/nope.js"), http.StatusNotFound, "", ""},
		{"api create", createReq(client, ""), http.StatusCreated, "application/json", "no-store"},
		{"api bad create", request{method: http.MethodPost, path: "/api/secret", remote: client, body: "{"}, http.StatusBadRequest, "application/json", "no-store"},
		{"api meta", get("/api/secret/live/meta"), http.StatusOK, "application/json", "no-store"},
		{"api reveal without header", request{method: http.MethodPost, path: "/api/secret/live/reveal", remote: client}, http.StatusForbidden, "application/json", "no-store"},
		{"api reveal", request{method: http.MethodPost, path: "/api/secret/live/reveal", remote: client, reveal: true}, http.StatusOK, "application/json", "no-store"},
		{"api over the limit", get("/api/secret/live/meta"), http.StatusTooManyRequests, "application/json", "no-store"},
		{"healthz", get("/healthz"), http.StatusOK, "application/json", "no-store"},
		{"unknown route", get("/nope"), http.StatusNotFound, "", "no-store"},
		{"wrong method", request{method: http.MethodDelete, path: "/", remote: client}, http.StatusMethodNotAllowed, "", "no-store"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := do(t, h, c.rq)
			if rec.Code != c.status {
				t.Fatalf("status %d want %d: %s", rec.Code, c.status, rec.Body)
			}
			for k, want := range wantSecurityHeaders {
				if got := rec.Header().Get(k); got != want {
					t.Errorf("%s: %q want %q", k, got, want)
				}
			}
			if pp := rec.Header().Get("Permissions-Policy"); !strings.Contains(pp, "camera=()") || !strings.Contains(pp, "clipboard-write=(self)") {
				t.Errorf("Permissions-Policy %q", pp)
			}
			if got := rec.Header().Get("Cache-Control"); got != c.cache {
				t.Errorf("Cache-Control %q want %q", got, c.cache)
			}
			if c.contentType != "" && rec.Header().Get("Content-Type") != c.contentType {
				t.Errorf("Content-Type %q want %q", rec.Header().Get("Content-Type"), c.contentType)
			}
		})
	}
}

func TestCSPHasNoUnsafeSources(t *testing.T) {
	for _, bad := range []string{"'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'", "'wasm-unsafe-eval'", "*", "data:", "blob:", "http:", "https:"} {
		for _, directive := range strings.Split(contentSecurityPolicy, "; ") {
			for _, source := range strings.Fields(directive)[1:] {
				if source == bad {
					t.Errorf("%q allows %s", directive, bad)
				}
			}
		}
	}
}

// The CSP blocks inline code, so the pages must not have any: it would fail
// silently in the browser (and only show up as a console error).
func TestPagesHaveNoInlineCode(t *testing.T) {
	h := newServer(testConfig(), deadStore(t)).routes()
	scriptTag := regexp.MustCompile(`(?i)<script\b[^>]*>`)
	for _, path := range []string{"/", "/s/abc"} {
		page := do(t, h, request{method: http.MethodGet, path: path, remote: "127.0.0.1:1"}).Body.String()
		for _, tag := range scriptTag.FindAllString(page, -1) {
			if !strings.Contains(tag, " src=") {
				t.Errorf("%s: inline script %s", path, tag)
			}
		}
		for _, re := range []string{`(?i)<style\b`, `(?i)\sstyle\s*=`, `(?i)\son[a-z]+\s*=`, `(?i)javascript:`} {
			if m := regexp.MustCompile(re).FindString(page); m != "" {
				t.Errorf("%s: inline code %q", path, m)
			}
		}
	}
	// Markup built from JS strings (innerHTML) is held to the same rule.
	err := fs.WalkDir(webFS, "web", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".js") || strings.HasPrefix(path, "web/vendor/") {
			return err
		}
		body, _ := webFS.ReadFile(path)
		for _, bad := range []string{"style=", `setAttribute("style"`, "cssText", "eval(", "new Function"} {
			if strings.Contains(string(body), bad) {
				t.Errorf("%s uses %s", path, bad)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Every asset a page loads must exist and carry the current asset version, or
// the year-long immutable cache would keep serving an old copy after a deploy.
func TestPageAssetsAreVersionedAndServed(t *testing.T) {
	h := newServer(testConfig(), deadStore(t)).routes()
	ref := regexp.MustCompile(`(?:src|href)="(/web/[^"]+)"`)
	for _, path := range []string{"/", "/s/abc"} {
		page := do(t, h, request{method: http.MethodGet, path: path, remote: "127.0.0.1:1"}).Body.String()
		if strings.Contains(page, assetVersionPlaceholder) {
			t.Fatalf("%s: unrendered %s", path, assetVersionPlaceholder)
		}
		refs := ref.FindAllStringSubmatch(page, -1)
		if len(refs) < 8 {
			t.Fatalf("%s: only %d asset references", path, len(refs))
		}
		for _, m := range refs {
			url := m[1]
			file, query, _ := strings.Cut(url, "?")
			if (strings.HasSuffix(file, ".js") || strings.HasSuffix(file, ".css")) && query != "v="+assetVersion() {
				t.Errorf("%s: %s is not versioned with %s", path, url, assetVersion())
			}
			if rec := do(t, h, request{method: http.MethodGet, path: url, remote: "127.0.0.1:1"}); rec.Code != http.StatusOK {
				t.Errorf("%s: %s -> %d", path, url, rec.Code)
			}
		}
	}
	if v := assetVersion(); len(v) != 12 || v != assetVersion() {
		t.Fatalf("asset version %q", v)
	}
}
