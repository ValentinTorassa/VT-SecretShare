package main

// Security headers sent on every response, and the version stamped on the
// URLs of the embedded static assets.
//
// The key that decrypts a secret lives in the #fragment of the share link, so
// any script that runs on the view page can read it. The Content-Security-Policy
// therefore lets the pages run only this origin's own files: no inline
// <script>, import maps, event-handler attributes or style attributes, no
// eval, nothing from a CDN. web/ is written to fit it (see headers_test.go).

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"sync"
)

var contentSecurityPolicy = strings.Join([]string{
	"default-src 'none'",
	"script-src 'self'",
	"style-src 'self'",
	"img-src 'self'",
	"connect-src 'self'",
	"base-uri 'none'",
	"form-action 'self'",
	"frame-ancestors 'none'",
}, "; ")

// permissionsPolicy turns off the powerful features the UI never uses. The
// clipboard stays writable by the page itself: the copy buttons need it.
var permissionsPolicy = strings.Join([]string{
	"accelerometer=()",
	"autoplay=()",
	"browsing-topics=()",
	"camera=()",
	"clipboard-read=()",
	"clipboard-write=(self)",
	"display-capture=()",
	"encrypted-media=()",
	"fullscreen=()",
	"geolocation=()",
	"gyroscope=()",
	"hid=()",
	"idle-detection=()",
	"magnetometer=()",
	"microphone=()",
	"midi=()",
	"payment=()",
	"picture-in-picture=()",
	"publickey-credentials-get=()",
	"screen-wake-lock=()",
	"serial=()",
	"usb=()",
	"xr-spatial-tracking=()",
}, ", ")

// hstsPolicy is sent even though the app itself speaks plain HTTP: browsers
// ignore Strict-Transport-Security over HTTP (localhost, a LAN port), and every
// remote deployment is HTTPS already, because WebCrypto only exists in secure
// contexts. In production Cloudflare terminates TLS and passes the header on.
// No includeSubDomains or preload: an instance on someone's apex domain must
// not pin every sibling service to HTTPS.
const hstsPolicy = "max-age=31536000"

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("Referrer-Policy", "no-referrer") // the key is in the page URL
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY") // frame-ancestors for older browsers
		h.Set("Permissions-Policy", permissionsPolicy)
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Strict-Transport-Security", hstsPolicy)
		// Static assets are cached for a year: their URLs carry ?v=<assetVersion>,
		// so a build that changes them changes the URL. HTML pages and API
		// responses must not be cached (zero-knowledge ensures nothing sensitive
		// is there, but stale UI or error pages are confusing).
		if strings.HasPrefix(r.URL.Path, "/web/") {
			h.Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// assetVersionPlaceholder is replaced by assetVersion() in the served pages.
const assetVersionPlaceholder = "{{ASSET_VERSION}}"

// assetVersion is a short hash of everything under web/. Browsers and the
// Cloudflare edge keep /web/ files for a year, so the pages load them as
// /web/<file>?v=<assetVersion>: any change to web/ gives every asset a new URL
// instead of a stale copy (vault.js passes its own ?v= on to bg.js).
var assetVersion = sync.OnceValue(func() string {
	sum := sha256.New()
	err := fs.WalkDir(webFS, "web", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		body, err := webFS.ReadFile(path)
		if err != nil {
			return err
		}
		sum.Write([]byte(path))
		sum.Write([]byte{0})
		sum.Write(body)
		sum.Write([]byte{0})
		return nil
	})
	if err != nil {
		log.Fatalf("cannot hash embedded web files: %v", err)
	}
	return hex.EncodeToString(sum.Sum(nil))[:12]
})

// renderPage fills in the asset version of an embedded HTML page.
func renderPage(page []byte) []byte {
	return bytes.ReplaceAll(page, []byte(assetVersionPlaceholder), []byte(assetVersion()))
}
