#!/bin/sh
# Beagle one-line installer (curl channel, R1). Downloads the signed,
# per-platform binary from GitHub releases — NEVER fetches or runs code on a
# post-install hook (supply-chain rule). Verifies the checksum before install.
set -eu

REPO="boundedhq/beagle"
VERSION="${BEAGLE_VERSION:-latest}"
PREFIX="${BEAGLE_PREFIX:-/usr/local/bin}"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch="x64" ;;
  arm64|aarch64) arch="arm64" ;;
  *) echo "beagle: unsupported architecture: $arch" >&2; exit 1 ;;
esac
case "$os" in
  darwin|linux) ;;
  *) echo "beagle: unsupported OS: $os (macOS and Linux only in v1)" >&2; exit 1 ;;
esac

asset="beagle-${os}-${arch}"
if [ "$VERSION" = "latest" ]; then
  base="https://github.com/${REPO}/releases/latest/download"
else
  base="https://github.com/${REPO}/releases/download/${VERSION}"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "beagle: downloading ${asset}…"
curl -fsSL "${base}/${asset}" -o "$tmp/beagle"
curl -fsSL "${base}/${asset}.sha256" -o "$tmp/beagle.sha256"

echo "beagle: verifying checksum…"
expected="$(cut -d' ' -f1 < "$tmp/beagle.sha256")"
if command -v shasum >/dev/null 2>&1; then
  actual="$(shasum -a 256 "$tmp/beagle" | cut -d' ' -f1)"
else
  actual="$(sha256sum "$tmp/beagle" | cut -d' ' -f1)"
fi
if [ "$expected" != "$actual" ]; then
  echo "beagle: checksum mismatch — refusing to install" >&2
  exit 1
fi

chmod +x "$tmp/beagle"
if [ -w "$PREFIX" ]; then
  mv "$tmp/beagle" "$PREFIX/beagle"
else
  echo "beagle: installing to $PREFIX (needs sudo)…"
  sudo mv "$tmp/beagle" "$PREFIX/beagle"
fi

echo "beagle: installed to $PREFIX/beagle"
"$PREFIX/beagle" detect || true
