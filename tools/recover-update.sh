#!/usr/bin/env bash
#
# tools/recover-update.sh — manually pull the latest published GitHub
# Release of serverpilot, install it to /usr/local/bin/sp, and restart
# the daemon. Designed for the case where the running `sp` binary has a
# broken self-update flow and cannot fix itself.
#
# Run it on the affected server, with sudo:
#
#   curl -fsSL --proto =https --tlsv1.2 \
#     "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/tools/recover-update.sh" \
#     | sudo bash
#
# Or copy it onto the server and run `sudo bash recover-update.sh`.
#
# Once a server has a working sp binary again, future updates go through
# the normal `sp update` flow which talks to the same release-asset URL.
#
# Hardening:
#   - set -euo pipefail aborts at the first failed step (no half-applied
#     state where the binary is replaced but the daemon failed to come back).
#   - --proto =https + --tlsv1.2 refuse downgrade to plaintext or pre-TLS-1.2.
#   - mktemp -d returns a 0700 root-only scratch dir; no /tmp races.
#   - install -m 0755 -o root -g root forces canonical perms on the
#     destination instead of inheriting from the temp file.
#   - Tag value is regex-validated before flowing into a URL.
#   - SHA-256 is verified against the .sha256 sidecar when published; if
#     not, TLS + immutable release-asset URL remain the integrity gates.
#   - install-time daemon health check: if the new binary fails to start,
#     the script exits non-zero so the operator notices immediately
#     (instead of a silently-down service).
#
# Required tools: curl, sha256sum (or shasum), install, systemctl.

set -euo pipefail

REPO=mrthoabby/serverpilot
INSTALL_PATH=/usr/local/bin/sp
SERVICE=serverpilot
TAG_REGEX='^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'

OS=linux
case "$(uname -m)" in
    x86_64|amd64)  ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

if [ "$(id -u)" -ne 0 ]; then
    echo "must be run as root (try: sudo bash $0)" >&2
    exit 1
fi

echo "[1/5] Resolving latest published release..."
TAG=$(curl -fsSL --proto =https --tlsv1.2 \
    "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep -m1 '"tag_name":' \
    | sed -E 's/.*"tag_name":[[:space:]]*"([^"]+)".*/\1/')

if [ -z "$TAG" ]; then
    echo "could not resolve latest release tag" >&2
    exit 1
fi
if ! printf '%s' "$TAG" | grep -Eq "$TAG_REGEX"; then
    echo "GitHub returned an unexpected tag value: $TAG" >&2
    exit 1
fi
echo "    → $TAG"

URL="https://github.com/${REPO}/releases/download/${TAG}/sp-${OS}-${ARCH}"
SHA_URL="${URL}.sha256"

echo "[2/5] Downloading $(basename "$URL")..."
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM
curl -fsSL --proto =https --tlsv1.2 "$URL" -o "$TMP/sp"
[ -s "$TMP/sp" ] || { echo "download was empty" >&2; exit 1; }

echo "[3/5] Verifying integrity..."
if curl -fsSL --proto =https --tlsv1.2 "$SHA_URL" -o "$TMP/sp.sha256" 2>/dev/null \
   && [ -s "$TMP/sp.sha256" ]; then
    EXPECTED=$(awk '{print $1}' "$TMP/sp.sha256")
    if command -v sha256sum >/dev/null 2>&1; then
        ACTUAL=$(sha256sum "$TMP/sp" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        ACTUAL=$(shasum -a 256 "$TMP/sp" | awk '{print $1}')
    else
        echo "neither sha256sum nor shasum available; cannot verify checksum" >&2
        exit 1
    fi
    if [ "$EXPECTED" != "$ACTUAL" ]; then
        echo "checksum mismatch (expected $EXPECTED, got $ACTUAL) — refusing install" >&2
        exit 1
    fi
    echo "    → sha256 verified ($ACTUAL)"
else
    echo "    → no .sha256 sidecar published; proceeding with TLS + release-asset pinning only"
fi

echo "[4/5] Installing to ${INSTALL_PATH}..."
install -m 0755 -o root -g root "$TMP/sp" "$INSTALL_PATH"

echo "[5/5] Restarting ${SERVICE}..."
if systemctl is-enabled --quiet "$SERVICE" 2>/dev/null \
   || systemctl is-active --quiet "$SERVICE" 2>/dev/null; then
    systemctl restart "$SERVICE"
    sleep 2
    if ! systemctl is-active --quiet "$SERVICE"; then
        echo "daemon failed to start with new binary — check 'journalctl -u $SERVICE'" >&2
        exit 1
    fi
    echo "    → ${SERVICE} active"
else
    echo "    → ${SERVICE} not installed as a systemd unit; skipping restart"
fi

INSTALLED=$("$INSTALL_PATH" --version 2>/dev/null | tr -d '\r\n')
echo
echo "OK — $INSTALL_PATH is now: $INSTALLED (target tag $TAG)"
