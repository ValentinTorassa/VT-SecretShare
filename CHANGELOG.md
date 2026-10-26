# Changelog

Notable changes to VT-SecretShare. Versions follow [Semantic Versioning](https://semver.org/).

## Unreleased

### Security

- Build with Go 1.27.3. Go 1.27.2's `crypto/x509` still trusted a set of
  compromised intermediate certificates
  ([GO-2026-6809](https://pkg.go.dev/vuln/GO-2026-6809)); govulncheck found the
  server reaching `x509.Certificate.Verify`. The Docker image builds with
  `golang:1.27.3-alpine` too.

## 1.0.0 - 2026-10-20

First tagged release. It covers everything built since June 2026, the same code
that runs secretshare.valentorassa.com.

### Sharing

- Paste a secret, pick how long it lives (10 minutes, 1 hour, 1 day or 7 days)
  and get a link that opens once.
- The secret is encrypted in the browser with a random AES-256-GCM key
  (WebCrypto). Only the ciphertext reaches the server; the key stays in the
  link's `#fragment`, which browsers never send.
- The first reveal reads and deletes the secret in one atomic Redis Lua script,
  so two people racing the same link can't both get it. Opening the link again
  says the secret is gone. Redis only holds ciphertext, with a hard TTL.
- A wrong key no longer burns the secret: the browser sends a verifier derived
  from the key (HKDF-SHA256; the server stores only its SHA-256), the same script
  checks it before deleting, and a truncated or mistyped link gets
  `403 wrong_key` while the secret stays.
- Revealing needs a click, so link-preview crawlers can't burn a secret.
- The view page removes the key from the address bar after reading it, and
  checks the secret on load so a dead link says so before the button is pressed.

### Interface

- Hacker mode (default): Three.js vault background (vendored, no CDN), matrix
  rain and cipher/decipher animations. Pro mode: a sober light theme with the
  effects paused. `?theme=` pins either one.
- Spanish and English. Generated links carry the sender's mode and language.
- VT Security penguin branding.

### Server and API

- `POST /api/secret`, `POST /api/secret/{id}/reveal`, `GET /api/secret/{id}/meta`
  and `GET /healthz`, which answers 200 only if Redis replies to `PING`.
- Per-client rate limits counted in Redis: 20 creates and 30 reads per 10
  minutes by default, configurable, `429` with `Retry-After` over the limit.
  Counter keys are HMACs, so no raw IPs are stored. `CF-Connecting-IP` is
  trusted only from `TRUSTED_PROXY_CIDRS` (loopback by default).
- Listens on `127.0.0.1` by default (`BIND_ADDR`) and drops stalled clients
  with read, write and idle timeouts.
- Configured through environment variables, listed in the README.

### Browser hardening

- A strict Content-Security-Policy on every response: only the site's own
  scripts and styles, nothing inline, no CDN. Trusted Types is enforced and no
  policy can be created; tests fail if UI code uses an HTML sink such as
  `innerHTML`.
- `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, `nosniff`, a
  Permissions-Policy that only allows clipboard writes, same-origin COOP and
  CORP, and HSTS.
- `POST /api/secret` only accepts `application/json`.
- Static files are cached as immutable and requested with a hash of `web/`, so
  a new build never mixes with stale cached files.

### Running it

- `docker compose up --build` runs the app and a Redis without persistence,
  published on loopback only. `./run.sh` starts a disposable Redis and
  `go run .` for development.
- Go 1.27.2, go-redis v9.23.0, and a distroless container image that runs as a
  non-root user.

### Tests and CI

- Go tests (run with `-race`) cover one-read races, expiry, the key verifier,
  rate limiting and the security headers, each against a throwaway Redis.
  Node tests cover the browser encryption.
- CI runs both on Ubuntu 24.04. A security workflow runs govulncheck and
  CodeQL (Go, JavaScript, Actions) on pushes to main, pull requests and every
  week.
- Apache-2.0 license.

### Fixes

- The view page's "copy to clipboard" button was a thin bar; it now has the
  same padding as the button below it, in both modes. A link that can no longer
  open now says so in the subtitle ("transmission terminated. nothing left to
  decrypt." or "no valid key in #fragment. cannot decrypt.", in Spanish and
  English) instead of "awaiting authorization".
