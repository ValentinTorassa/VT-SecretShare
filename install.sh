#!/bin/sh
# Installs vtss, the command line client of VT-SecretShare.
#
#   curl -fsSL https://secretshare.valentorassa.com/install.sh | sh
#
# It downloads the binary for this machine from the project's GitHub releases,
# checks its SHA-256 against the release's checksums.txt and puts it in
# ~/.local/bin. Nothing runs as root.
#
#   VTSS_INSTALL_DIR=/usr/local/bin   install somewhere else
#   VTSS_VERSION=v1.1.0               a specific release instead of the latest
set -eu

REPO="ValentinTorassa/VT-SecretShare"
DIR="${VTSS_INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${VTSS_VERSION:-latest}"

fail() {
  echo "vtss install: $1" >&2
  exit 1
}

command -v curl >/dev/null 2>&1 || fail "curl is required"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$os" in
  linux | darwin) ;;
  *) fail "no binary for $os. With Go installed: go install github.com/$REPO/cmd/vtss@latest" ;;
esac
case "$arch" in
  x86_64 | amd64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) fail "no binary for $arch. With Go installed: go install github.com/$REPO/cmd/vtss@latest" ;;
esac

asset="vtss_${os}_${arch}"
if [ "$VERSION" = latest ]; then
  base="https://github.com/$REPO/releases/latest/download"
else
  base="https://github.com/$REPO/releases/download/$VERSION"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "Downloading $asset ($VERSION)..."
curl -fsSL "$base/$asset" -o "$tmp/$asset" || fail "could not download $base/$asset"
curl -fsSL "$base/checksums.txt" -o "$tmp/checksums.txt" || fail "could not download the checksums"

want=$(awk -v f="$asset" '$2 == f { print $1 }' "$tmp/checksums.txt")
[ -n "$want" ] || fail "the release has no checksum for $asset"
if command -v sha256sum >/dev/null 2>&1; then
  got=$(sha256sum "$tmp/$asset" | awk '{ print $1 }')
elif command -v shasum >/dev/null 2>&1; then
  got=$(shasum -a 256 "$tmp/$asset" | awk '{ print $1 }')
else
  fail "sha256sum or shasum is required to check the download"
fi
[ "$got" = "$want" ] || fail "checksum mismatch for $asset: got $got, expected $want"

mkdir -p "$DIR"
chmod 755 "$tmp/$asset"
mv "$tmp/$asset" "$DIR/vtss"

echo "Installed $("$DIR/vtss" --version) in $DIR"
case ":$PATH:" in
  *":$DIR:"*) ;;
  *) echo "$DIR is not in your PATH. Add it with: export PATH=\"$DIR:\$PATH\"" ;;
esac
echo 'Try it: echo "hello" | vtss'
