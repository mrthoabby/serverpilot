#!/bin/sh
# ServerPilot installation script
#
# RECOMMENDED USAGE — verify the script before executing it:
#   curl -fsSLO https://github.com/mrthoabby/serverpilot/releases/latest/download/install.sh
#   curl -fsSLO https://github.com/mrthoabby/serverpilot/releases/latest/download/install.sh.sha256
#   sha256sum -c install.sh.sha256
#   sh ./install.sh
#
# The traditional "curl | sh" pattern is supported but discouraged because it
# offers zero opportunity to inspect the script before it runs as root.

set -eu
# pipefail is bash/zsh; only enable when supported by the running shell.
# shellcheck disable=SC3040
(set -o pipefail 2>/dev/null) && set -o pipefail || true

REPO="mrthoabby/serverpilot"
BIN_NAME="sp"
INSTALL_DIR_SYSTEM="/usr/local/bin"
INSTALL_DIR_USER="$HOME/.local/bin"

# Strict semver regex — refuse any tag value that does not match. Accepts
# both "v1.2.3" and "1.2.3" because the project tags both ways.
# Closes a URL-injection channel via the GitHub API JSON response.
TAG_REGEX='^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

info()  { printf "\033[1;34m[info]\033[0m  %s\n" "$1"; }
ok()    { printf "\033[1;32m[ok]\033[0m    %s\n" "$1"; }
warn()  { printf "\033[1;33m[warn]\033[0m  %s\n" "$1"; }
error() { printf "\033[1;31m[error]\033[0m %s\n" "$1" >&2; exit 1; }

# Default mode: verify if a sidecar is present, warn otherwise.
# Set SP_REQUIRE_CHECKSUM=strict (or =1) to REFUSE install when the
# sidecar is missing — recommended once vs-pre-run/Makefile starts
# emitting sha256 files alongside each binary.
: "${SP_REQUIRE_CHECKSUM:=optional}"

# ---------------------------------------------------------------------------
# Detect OS
# ---------------------------------------------------------------------------

detect_os() {
    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    case "$OS" in
        linux)  OS="linux" ;;
        darwin) OS="darwin" ;;
        *)      error "Unsupported operating system: $OS. ServerPilot currently supports Linux only." ;;
    esac

    if [ "$OS" = "darwin" ]; then
        warn "macOS detected. ServerPilot is designed for Linux servers."
        warn "Installing anyway for local development purposes."
    fi
}

# ---------------------------------------------------------------------------
# Detect architecture
# ---------------------------------------------------------------------------

detect_arch() {
    ARCH="$(uname -m)"
    case "$ARCH" in
        x86_64|amd64)   ARCH="amd64"  ;;
        aarch64|arm64)  ARCH="arm64"  ;;
        *)              error "Unsupported architecture: $ARCH. Supported: amd64, arm64." ;;
    esac
}

# ---------------------------------------------------------------------------
# Fetch latest version tag from GitHub
# ---------------------------------------------------------------------------

fetch_latest_version() {
    info "Fetching latest version..."

    if command -v curl >/dev/null 2>&1; then
        # --tlsv1.2: refuse pre-TLS-1.2 negotiations.
        # --proto =https: refuse plaintext HTTP redirects.
        FETCHER="curl --proto =https --tlsv1.2 -fsSL"
    elif command -v wget >/dev/null 2>&1; then
        FETCHER="wget --secure-protocol=TLSv1_2 -qO-"
    else
        error "Neither curl nor wget found. Please install one of them."
    fi

    # Use /releases/latest — only formally PUBLISHED releases come back. A
    # bare tag without a published Release will not be picked up, which is
    # the correct behaviour for this project's distribution flow.
    VERSION="$($FETCHER "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' \
        | head -1 \
        | sed 's/.*"tag_name": *"//;s/".*//')"

    if [ -z "$VERSION" ]; then
        error "Could not determine the latest released version. Check your network connection or whether any release has been published."
    fi

    # Strict-validate the tag BEFORE letting it flow into a download URL.
    if ! printf '%s' "$VERSION" | grep -Eq "$TAG_REGEX"; then
        error "GitHub returned an unexpected tag value; refusing to continue."
    fi

    info "Latest published release: $VERSION"
}

# ---------------------------------------------------------------------------
# Download binary
# ---------------------------------------------------------------------------

download_binary() {
    # Pin downloads to the IMMUTABLE TAG ref via raw.githubusercontent.com.
    # The release flow commits binaries to the repo under release/<VER>/
    # and tags. Pinning at the tag (instead of master) neutralises the
    # "force-push to master replaces binaries" attack vector while keeping
    # the existing distribution path unchanged.
    VER_PATH="${VERSION#v}"
    BASE_URL="https://raw.githubusercontent.com/${REPO}/${VERSION}/release/${VER_PATH}"
    DOWNLOAD_URL="${BASE_URL}/${BIN_NAME}-${OS}-${ARCH}"
    SHA_URL="${BASE_URL}/${BIN_NAME}-${OS}-${ARCH}.sha256"

    # mktemp -d guarantees a unique directory; mode is 0700 by default.
    TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t spinst)"
    chmod 0700 "$TMP_DIR"
    trap 'rm -rf "$TMP_DIR"' EXIT INT TERM
    TMP_BIN="${TMP_DIR}/${BIN_NAME}"
    TMP_SHA="${TMP_DIR}/${BIN_NAME}.sha256"

    info "Downloading ${BIN_NAME}-${OS}-${ARCH} (${VERSION})..."

    # Use the same hardened curl/wget invocation as the version probe.
    if command -v curl >/dev/null 2>&1; then
        curl --proto =https --tlsv1.2 -fsSL "$DOWNLOAD_URL" -o "$TMP_BIN" \
            || error "Download failed: $DOWNLOAD_URL"
    else
        wget --secure-protocol=TLSv1_2 -qO "$TMP_BIN" "$DOWNLOAD_URL" \
            || error "Download failed: $DOWNLOAD_URL"
    fi

    if [ ! -s "$TMP_BIN" ]; then
        error "Download produced an empty file: $DOWNLOAD_URL"
    fi

    # Verify SHA-256 checksum if a sidecar exists. The project doesn't
    # currently publish .sha256 files alongside the binaries, so by default
    # we treat absence as a warning. Set SP_REQUIRE_CHECKSUM=1 (or "strict")
    # to refuse installation when the sidecar is missing — recommended once
    # the release pipeline starts emitting them.
    info "Probing for SHA-256 sidecar..."
    SUM_OK=0
    if command -v curl >/dev/null 2>&1; then
        curl --proto =https --tlsv1.2 -fsSL "$SHA_URL" -o "$TMP_SHA" 2>/dev/null && SUM_OK=1
    else
        wget --secure-protocol=TLSv1_2 -qO "$TMP_SHA" "$SHA_URL" 2>/dev/null && SUM_OK=1
    fi

    if [ "$SUM_OK" = "1" ] && [ -s "$TMP_SHA" ]; then
        EXPECTED="$(awk '{print $1}' "$TMP_SHA")"
        if [ -z "$EXPECTED" ]; then
            error "Checksum file is empty. Refusing to install."
        fi
        if command -v sha256sum >/dev/null 2>&1; then
            ACTUAL="$(sha256sum "$TMP_BIN" | awk '{print $1}')"
        elif command -v shasum >/dev/null 2>&1; then
            ACTUAL="$(shasum -a 256 "$TMP_BIN" | awk '{print $1}')"
        else
            error "Neither sha256sum nor shasum available; cannot verify the published checksum. Install one or wait for a release without sidecar."
        fi
        if [ "$ACTUAL" != "$EXPECTED" ]; then
            error "Checksum mismatch! Expected $EXPECTED but got $ACTUAL. Refusing to install — possible tampered binary."
        fi
        ok "Checksum verified."
    else
        if [ "$SP_REQUIRE_CHECKSUM" = "strict" ] || [ "$SP_REQUIRE_CHECKSUM" = "1" ]; then
            error "SP_REQUIRE_CHECKSUM=$SP_REQUIRE_CHECKSUM but the sidecar at $SHA_URL is missing. Refusing to install."
        fi
        warn "No SHA-256 sidecar at $SHA_URL — proceeding with TLS + tag pinning only."
    fi

    chmod 0755 "$TMP_BIN"
}

# ---------------------------------------------------------------------------
# Install binary
# ---------------------------------------------------------------------------

install_binary() {
    # Decide install dir based on actual UID, not directory writability,
    # so we don't accidentally trust an attacker-writable /usr/local/bin.
    if [ "$(id -u)" -eq 0 ]; then
        INSTALL_DIR="$INSTALL_DIR_SYSTEM"
        install -m 0755 "$TMP_BIN" "${INSTALL_DIR}/${BIN_NAME}" \
            || error "Failed to install to ${INSTALL_DIR}"
        ok "Installed to ${INSTALL_DIR}/${BIN_NAME}"
    elif command -v sudo >/dev/null 2>&1; then
        info "Requesting elevated privileges to install to ${INSTALL_DIR_SYSTEM}..."
        sudo install -m 0755 "$TMP_BIN" "${INSTALL_DIR_SYSTEM}/${BIN_NAME}" \
            || error "sudo install failed"
        INSTALL_DIR="$INSTALL_DIR_SYSTEM"
        ok "Installed to ${INSTALL_DIR}/${BIN_NAME}"
    else
        INSTALL_DIR="$INSTALL_DIR_USER"
        mkdir -p "$INSTALL_DIR"
        install -m 0755 "$TMP_BIN" "${INSTALL_DIR}/${BIN_NAME}" \
            || error "Failed to install to ${INSTALL_DIR}"
        ok "Installed to ${INSTALL_DIR}/${BIN_NAME}"
    fi
}

# ---------------------------------------------------------------------------
# Ensure install directory is in PATH
# ---------------------------------------------------------------------------

ensure_path() {
    case ":$PATH:" in
        *":${INSTALL_DIR}:"*) return ;;
    esac

    warn "${INSTALL_DIR} is not in your PATH."

    SHELL_NAME="$(basename "${SHELL:-sh}" 2>/dev/null || echo "sh")"
    case "$SHELL_NAME" in
        bash) RC_FILE="$HOME/.bashrc" ;;
        zsh)  RC_FILE="$HOME/.zshrc"  ;;
        *)    RC_FILE="$HOME/.profile" ;;
    esac

    EXPORT_LINE="export PATH=\"${INSTALL_DIR}:\$PATH\""

    # Idempotency guard: only append if our specific export line is not already
    # present. The previous version checked for any occurrence of $INSTALL_DIR
    # which produced false positives for unrelated PATH entries.
    if [ -f "$RC_FILE" ] && grep -qF "$EXPORT_LINE" "$RC_FILE" 2>/dev/null; then
        info "PATH entry already exists in $RC_FILE"
    else
        printf '\n# Added by ServerPilot installer\n%s\n' "$EXPORT_LINE" >> "$RC_FILE"
        info "Added ${INSTALL_DIR} to PATH in $RC_FILE"
        warn "Run 'source $RC_FILE' or open a new terminal to use sp."
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    printf "\n"
    info "ServerPilot Installer"
    info "====================="
    printf "\n"

    detect_os
    detect_arch
    fetch_latest_version
    download_binary
    install_binary
    ensure_path

    printf "\n"
    ok "ServerPilot ($VERSION) installed successfully!"
    printf "\n"
    info "Get started by running:"
    printf "\n"
    printf "    \033[1msp setup\033[0m\n"
    printf "\n"
    info "This will configure your server environment, set up Docker,"
    info "and launch the management dashboard."
    printf "\n"
}

main
