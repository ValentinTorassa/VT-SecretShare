# VT-SecretShare

Zero-knowledge **one-time secret sharing**, self-hosted. Paste a password / token /
API key → get a link that works **once** and then self-destructs. Built around two
Redis commands and a fancy hacker UI.

> `.env` no es seguridad. - VT Security

## Why it's actually secure (the demo-worthy part)

- **Zero-knowledge.** The secret is encrypted **in your browser** with a random
  AES-256-GCM key (WebCrypto). Only the ciphertext is sent to the server.
- **The key never touches the server.** It lives in the URL `#fragment`, which
  browsers never send in requests. `Referrer-Policy: no-referrer` stops it leaking.
- **Only its own scripts run.** Any script on the view page could read the key,
  so a strict Content-Security-Policy (`script-src 'self'`, no inline code, no
  CDN) keeps injected markup from running. See [Security headers](#security-headers).
- **One read, then gone.** The first reveal calls Redis `GETDEL` - an atomic
  read-and-delete. Two people racing the same link can never both win.
- **Nothing to steal at rest.** Redis only ever holds ciphertext, with a hard TTL.
  Dump Redis, read the logs, inspect server memory - there is no plaintext and no key.

So the entire server is basically: `SET key <ciphertext> EX <ttl>` on create,
`GETDEL key` on read. That's the whole persistence model. Redis is doing the
security-relevant work (atomic burn + TTL expiry), which makes it a clean story
for a video.

## Architecture

```
browser ──(AES-256-GCM encrypt)──▶ ciphertext ──POST──▶ Go ──SET..EX──▶ Redis
share link = /s/{id}?theme=pro&lang=en#{key}  (preferences in query, key in fragment)

browser ──POST──▶ Go ──GETDEL──▶ Redis ──ciphertext──▶ browser ──(decrypt with #key)──▶ secret
                         ▲ key is deleted in the same atomic op
```

- `main.go` - HTTP API + embedded static UI (`go:embed`). Tiny.
- `headers.go` - security headers on every response, and the asset version.
- `store.go` - the only thing that talks to Redis (`SetNX` + `GetDel` + `TTL`,
  plus the atomic rate-limit counter script).
- `ratelimit.go` - per-client rate limiting and client-IP resolution.
- `web/` - UI: `index.html` + `index.js` (create), `view.html` + `view.js`
  (reveal), `vault.js` (loads `bg.js`, the Three.js 3D vault-core), `matrix.js`
  (digital rain), `crypto.js` (WebCrypto), `anim.js` (cipher/decipher effects),
  `i18n.js` (ES/EN), `theme.js` (UI mode), `clipboard.js`, `fx.css`. No inline
  scripts or styles: the CSP would block them.
- `web/vendor/three.module.min.js` - Three.js vendored locally **on purpose**: a
  secrets tool shouldn't pull JS from a third-party CDN that could watch its users.

### UI modes & language

- **Hacker** (default): 3D vault background, matrix rain, glitch, neon, cipher/decipher
  animations. **Pro**: sober, mostly-static light theme for sharing with companies -
  effects are paused, not just hidden. Toggle in the header; choice persists, and
  `?theme=pro` (or `hacker`) pins it via URL.
- **ES/EN** toggle (Spanish default), persisted. Generated links include both the
  selected mode and language, so receivers open the intended UI. Branding: VT
  Security penguin lockup (off-white on dark, ink on light).

## Run it (local dev)

```bash
./run.sh        # starts a disposable Redis (docker) + the app on :8080
# then open http://localhost:8080
```

Or manually:

```bash
docker run -d --name vt-redis-dev -p 6379:6379 redis:7-alpine
go run .
```

## Run it (compose)

```bash
docker compose up --build      # or: podman compose up --build
```

Behind a VPN or reverse proxy, set `BASE_URL` so the generated links point at the
reachable host:

```bash
APP_PORT=8081 BASE_URL=https://secretshare.example.com docker compose up --build
```

Remote deployments must use HTTPS because browser WebCrypto is unavailable on
insecure origins (except `localhost`).

### How the live instance runs

secretshare.valentorassa.com is not the compose setup: it is the Go binary
under a systemd unit (tracked in the private infra repo) on the same host as
`cloudflared`, which forwards to `localhost:8081`. That is why the default
`TRUSTED_PROXY_CIDRS` is loopback only. To update it: pull, `go test ./...`,
build to a new file, smoke-test it on a spare port (`/healthz` → 200,
`/api/secret/x/meta` → 404, which also exercises the rate-limit script, and
`curl -sI /` carries the `Content-Security-Policy`), keep
the previous binary for rollback, swap, restart the unit. Keep
`RATE_LIMIT_SALT` in a root-owned `0600` EnvironmentFile, never in the unit.

## Config (env)

| Var | Default | Meaning |
| --- | --- | --- |
| `PORT` | `8080` | listen port |
| `APP_PORT` | `8080` | host port published by Docker Compose |
| `REDIS_ADDR` | `127.0.0.1:6379` | redis address |
| `REDIS_PASSWORD` | _(empty)_ | redis auth |
| `BASE_URL` | `http://localhost:$PORT` | used to build share links |
| `DEFAULT_TTL_SECONDS` | `86400` | default lifetime |
| `MAX_TTL_SECONDS` | `604800` | TTL ceiling |
| `MAX_CIPHERTEXT_BYTES` | `262144` | max blob size |
| `RATE_LIMIT_CREATE` | `20` | creates allowed per client per window (`0` disables) |
| `RATE_LIMIT_CREATE_WINDOW_SECONDS` | `600` | create window |
| `RATE_LIMIT_READ` | `30` | reveal + meta requests allowed per client per window (`0` disables) |
| `RATE_LIMIT_READ_WINDOW_SECONDS` | `600` | read window |
| `RATE_LIMIT_SALT` | _(random per process)_ | HMAC key for counter keys; set it so counters survive restarts and are shared across instances |
| `TRUSTED_PROXY_CIDRS` | `127.0.0.0/8,::1/128` | peers whose `CF-Connecting-IP` header is believed |

## API

| Method | Path | Notes |
| --- | --- | --- |
| `POST` | `/api/secret` | body `{ciphertext, ttl_seconds?}` → `{id, share_url, ttl_seconds, expires_at}`; create limit |
| `POST` | `/api/secret/{id}/reveal` | header `X-VT-Reveal: 1`; **burns** it (GETDEL) → `{ciphertext}` or 404; read limit |
| `GET` | `/api/secret/{id}/meta` | TTL/alive without burning; read limit |
| `GET` | `/healthz` | `200 {"status":"ok"}` if Redis answers `PING` within 1 s, else `503`; not rate limited |

Over a limit the API answers `429` with `Retry-After` (seconds until the window
resets) and `{"error":"too many requests - try again in N seconds"}`.

## Rate limiting

- **Per client, counted in Redis.** A fixed window per client: one Lua script does
  `INCR` and, on the first hit, `PEXPIRE`, so the pair is atomic and a counter can
  never be left without a TTL. Counters live in Redis, not in process memory.
- **Two budgets.** Creating (`POST /api/secret`) and reading (`reveal` and `meta`)
  are counted separately. Reading is the guessing surface: `meta` is an existence
  oracle and `reveal` burns. The limiter runs before `GETDEL`, so a rejected
  reveal never burns the secret.
- **When Redis is down.** The create limiter **fails open** and logs: creating is
  not a guessing surface, and the `SET` that follows fails anyway. The read
  limiter **fails closed** with `503` + `Retry-After`: reads must not become
  silently unlimited, and refusing costs nothing because the secret lives in the
  same Redis.
- **Client IP.** `CF-Connecting-IP` is used only when the TCP peer is in
  `TRUSTED_PROXY_CIDRS` (loopback by default, where `cloudflared` connects from).
  From any other peer the header is ignored and the socket address is used, so a
  direct LAN/tailnet connection cannot choose its own bucket. `X-Forwarded-For`
  is never read. IPv6 clients are grouped per `/64`.
- **No raw IPs at rest.** Counter keys are `ratelimit:{create|read}:` plus an
  HMAC-SHA256 of the client bucket under `RATE_LIMIT_SALT`, and they expire with
  their window (10 minutes by default). Client IPs are never logged. Without
  `RATE_LIMIT_SALT` a random salt is generated at start-up: counters then reset on
  restart and are not shared between instances. Generate one with
  `openssl rand -hex 32` and keep it out of git.
- **Behind Docker port publishing** the app sees the bridge gateway (for example
  `172.17.0.1`), not loopback, for connections from the host. Every client then
  shares one bucket unless you add that gateway to `TRUSTED_PROXY_CIDRS`. Only do
  that if nothing else can reach the container directly.

## Security headers

Every response (pages, API, static files, errors) carries:

| Header | Value | Why |
| --- | --- | --- |
| `Content-Security-Policy` | `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'` | the key is in the page URL, so only this origin's own files run: no inline scripts, styles or event handlers, no `eval`, no CDN |
| `Referrer-Policy` | `no-referrer` | never send the page URL anywhere |
| `X-Frame-Options` | `DENY` | `frame-ancestors 'none'` for older browsers |
| `X-Content-Type-Options` | `nosniff` | no MIME sniffing |
| `Permissions-Policy` | camera, microphone, geolocation, payment, USB, ... `=()`; `clipboard-write=(self)` | the copy buttons are the only feature the UI uses |
| `Cross-Origin-Opener-Policy` | `same-origin` | the page that opened a link gets no handle on it |
| `Cross-Origin-Resource-Policy` | `same-origin` | other sites cannot embed these responses |
| `Strict-Transport-Security` | `max-age=31536000` | browsers ignore it over plain HTTP (localhost), and remote deployments are HTTPS anyway because WebCrypto needs it; no `includeSubDomains` or `preload` |

`headers_test.go` checks them on every kind of route, and fails if a page gains
an inline `<script>`, `<style>`, `style=` or `on*=` attribute.

`/web/` files are served `immutable` for a year, and browsers and the Cloudflare
edge keep them, so the pages load them as `/web/<file>?v=<hash of web/>`
(computed at start-up; `vault.js` passes its `?v=` on to `bg.js`). Any change
under `web/` changes every asset URL. The vendored Three.js and the images are
not versioned: give them a new file name if you ever replace them.

## Notes / hardening ideas

- Reveal is gated behind an explicit button click so link-preview crawlers
  (Slack/Discord/WhatsApp) can't burn the secret before the human sees it.
- The container runs Redis with persistence off (`--save "" --appendonly no`) so
  secrets never hit disk.
- Possible next steps: optional passphrase (extra PBKDF2 layer), a `/metrics`
  endpoint, and Trusted Types (`require-trusted-types-for 'script'`) once
  `i18n.js` stops setting `innerHTML`.

## Verificación de regresiones - 2026-09-14

```bash
go test -race ./...
go build ./...
node --test tests/*.test.mjs
```

Redis 6.2+ debe estar disponible como `redis-server`. Cada test inicia una instancia efímera sin persistencia y con socket privado; nunca usa Redis de producción. Se verifican carrera de una lectura, expiración, colisiones y cifrado WebCrypto.

## License

[Apache License 2.0](LICENSE). Copyright 2026 Valentín Torassa.
