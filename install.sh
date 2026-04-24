#!/bin/sh
# ServerPilot installation script
# Usage: curl -fsSL https://raw.githubusercontent.com/mrthoabby/serverpilot/master/install.sh | sh

set -e

REPO="mrthoabby/serverpilot"
BIN_NAME="sp"
INSTALL_DIR_SYSTEM="/usr/local/bin"
INSTALL_DIR_USER="$HOME/.local/bin"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

info()  { printf "\033[1;34m[info]\033[0m  %s\n" "$1"; }
ok()    { printf "\033[1;32m[ok]\033[0m    %s\n" "$1"; }
warn()  { printf "\033[1;33m[warn]\033[0m  %s\n" "$1"; }
error() { printf "\033[1;31m[error]\033[0m %s\n" "$1"; exit 1; }

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
        aarch64|arm64)   ARCH="arm64"  ;;
        *)               error "Unsupported architecture: $ARCH. Supported: amd64, arm64." ;;
    esac
}

# ---------------------------------------------------------------------------
# Fetch latest version tag from GitHub
# ---------------------------------------------------------------------------

fetch_latest_version() {
    info "Fetching latest version..."

    if command -v curl >/dev/null 2>&1; then
        FETCHER="curl -fsSL"
    elif command -v wget >/dev/null 2>&1; then
        FETCHER="wget -qO-"
    else
        error "Neither curl nor wget found. Please install one of them."
    fi

    VERSION="$($FETCHER "https://api.github.com/repos/${REPO}/tags?per_page=1" \
        | grep '"name"' \
        | head -1 \
        | sed 's/.*"name": *"//;s/".*//')"

    if [ -z "$VERSION" ]; then
        error "Could not determine the latest version. Check your network connection."
    fi

    info "Latest version: $VERSION"
}

# ---------------------------------------------------------------------------
# Download binary
# ---------------------------------------------------------------------------

download_binary() {
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${BIN_NAME}-${OS}-${ARCH}"
    TMP_DIR="$(mktemp -d)"
    TMP_BIN="${TMP_DIR}/${BIN_NAME}"

    info "Downloading ${BIN_NAME}-${OS}-${ARCH} (${VERSION})..."

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$DOWNLOAD_URL" -o "$TMP_BIN"
    else
        wget -qO "$TMP_BIN" "$DOWNLOAD_URL"
    fi

    if [ ! -f "$TMP_BIN" ]; then
        error "Download failed. Please check the URL: $DOWNLOAD_URL"
    fi

    chmod +x "$TMP_BIN"
}

# ---------------------------------------------------------------------------
# Install binary
# ---------------------------------------------------------------------------

install_binary() {
    # Try system-wide install first
    if [ -d "$INSTALL_DIR_SYSTEM" ] && [ -w "$INSTALL_DIR_SYSTEM" ]; then
        INSTALL_DIR="$INSTALL_DIR_SYSTEM"
    elif command -v sudo >/dev/null 2>&1; then
        info "Requesting elevated privileges to install to ${INSTALL_DIR_SYSTEM}..."
        sudo mv "$TMP_BIN" "${INSTALL_DIR_SYSTEM}/${BIN_NAME}"
        INSTALL_DIR="$INSTALL_DIR_SYSTEM"
        ok "Installed to ${INSTALL_DIR}/${BIN_NAME}"
        rm -rf "$TMP_DIR"
        return
    else
        # Fall back to user directory
        INSTALL_DIR="$INSTALL_DIR_USER"
        mkdir -p "$INSTALL_DIR"
    fi

    mv "$TMP_BIN" "${INSTALL_DIR}/${BIN_NAME}"
    ok "Installed to ${INSTALL_DIR}/${BIN_NAME}"
    rm -rf "$TMP_DIR"
}

# ---------------------------------------------------------------------------
# Ensure install directory is in PATH
# ---------------------------------------------------------------------------

ensure_path() {
    case ":$PATH:" in
        *":${INSTALL_DIR}:"*) return ;;
    esac

    warn "${INSTALL_DIR} is not in your PATH."

    SHELL_NAME="$(basename "$SHELL" 2>/dev/null || echo "sh")"
    case "$SHELL_NAME" in
        bash)
            RC_FILE="$HOME/.bashrc"
            ;;
        zsh)
            RC_FILE="$HOME/.zshrc"
            ;;
        *)
            RC_FILE="$HOME/.profile"
            ;;
    esac

    EXPORT_LINE="export PATH=\"${INSTALL_DIR}:\$PATH\""

    if [ -f "$RC_FILE" ] && grep -qF "$INSTALL_DIR" "$RC_FILE" 2>/dev/null; then
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
