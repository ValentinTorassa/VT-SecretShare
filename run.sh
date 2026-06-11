#!/usr/bin/env bash
# Dev runner: ensures a disposable Redis is up, then runs the app locally.
# Uses docker on this machine; on valenpi you'd use `podman` instead.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

CONTAINER=vt-redis-dev
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
  echo "[run] starting disposable Redis ($CONTAINER)..."
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker run -d --name "$CONTAINER" -p 6379:6379 redis:7-alpine >/dev/null
fi

[ -f .env ] && { set -a; . ./.env; set +a; }
echo "[run] starting VT-SecretShare on :${PORT:-8080}"
exec go run .
