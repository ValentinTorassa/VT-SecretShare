# VT-SecretShare

Zero-knowledge **one-time secret sharing**, self-hosted. Paste a password / token /
API key → get a link that works **once** and then self-destructs. Built around two
Redis commands and a fancy hacker UI.

> `.env` no es seguridad. — VT Security

## Why it's actually secure (the demo-worthy part)

- **Zero-knowledge.** The secret is encrypted **in your browser** with a random
  AES-256-GCM key (WebCrypto). Only the ciphertext is sent to the server.
- **The key never touches the server.** It lives in the URL `#fragment`, which
  browsers never send in requests. `Referrer-Policy: no-referrer` stops it leaking.
- **One read, then gone.** The first reveal calls Redis `GETDEL` — an atomic
  read-and-delete. Two people racing the same link can never both win.
- **Nothing to steal at rest.** Redis only ever holds ciphertext, with a hard TTL.
  Dump Redis, read the logs, inspect server memory — there is no plaintext and no key.

So the entire server is basically: `SET key <ciphertext> EX <ttl>` on create,
`GETDEL key` on read. That's the whole persistence model. Redis is doing the
security-relevant work (atomic burn + TTL expiry), which makes it a clean story
for a video.

## Architecture

```
browser ──(AES-256-GCM encrypt)──▶ ciphertext ──POST──▶ Go ──SET..EX──▶ Redis
share link = /s/{id}#{key}        (key stays in the #fragment, client-side only)

browser ──GET──▶ Go ──GETDEL──▶ Redis ──ciphertext──▶ browser ──(decrypt with #key)──▶ secret
                         ▲ key is deleted in the same atomic op
```

- `main.go` — HTTP API + embedded static UI (`go:embed`). Tiny.
- `store.go` — the only thing that talks to Redis (`SetNX` + `GetDel` + `TTL`).
- `web/` — UI: `bg.js` (Three.js 3D vault-core), `matrix.js` (digital rain),
  `crypto.js` (WebCrypto), `anim.js` (cipher/decipher effects), `i18n.js` (ES/EN),
  `theme.js` (UI mode), `fx.css`, `index.html`, `view.html`.
- `web/vendor/three.module.min.js` — Three.js vendored locally **on purpose**: a
  secrets tool shouldn't pull JS from a third-party CDN that could watch its users.

### UI modes & language

- **Hacker** (default): 3D vault background, matrix rain, glitch, neon, cipher/decipher
  animations. **Pro**: sober, mostly-static light theme for sharing with companies —
  effects are paused, not just hidden. Toggle in the header; choice persists, and
  `?theme=pro` (or `hacker`) pins it via URL.
- **ES/EN** toggle (Spanish default), persisted. Branding: VT Security penguin lockup
  (off-white on dark, ink on light).

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

## Run it (compose / valenpi)

```bash
docker compose up --build      # on valenpi: podman compose up --build
```

On valenpi behind Tailscale, set `BASE_URL` so the generated links point at the
reachable host:

```bash
BASE_URL=http://valenpi.tail1dbe79.ts.net:8080 docker compose up --build
```

## Config (env)

| Var | Default | Meaning |
| --- | --- | --- |
| `PORT` | `8080` | listen port |
| `REDIS_ADDR` | `127.0.0.1:6379` | redis address |
| `REDIS_PASSWORD` | _(empty)_ | redis auth |
| `BASE_URL` | `http://localhost:$PORT` | used to build share links |
| `DEFAULT_TTL_SECONDS` | `86400` | default lifetime |
| `MAX_TTL_SECONDS` | `604800` | TTL ceiling |
| `MAX_CIPHERTEXT_BYTES` | `262144` | max blob size |

## API

| Method | Path | Notes |
| --- | --- | --- |
| `POST` | `/api/secret` | body `{ciphertext, ttl_seconds?}` → `{id, ttl_seconds, expires_at}` |
| `GET` | `/api/secret/{id}` | **burns** it (GETDEL) → `{ciphertext}` or 404 |
| `GET` | `/api/secret/{id}/meta` | TTL/alive without burning |
| `GET` | `/healthz` | pings Redis |

## Notes / hardening ideas

- Reveal is gated behind an explicit button click so link-preview crawlers
  (Slack/Discord/WhatsApp) can't burn the secret before the human sees it.
- The container runs Redis with persistence off (`--save "" --appendonly no`) so
  secrets never hit disk.
- Possible next steps: optional passphrase (extra PBKDF2 layer), rate limiting on
  `POST /api/secret`, a `/metrics` endpoint, and a CSP without `unsafe-inline`.
