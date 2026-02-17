#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────
# Shanon — Solana Security Platform
# One-line installer: curl -sSfL https://shanon.security/install.sh | sh
# ──────────────────────────────────────────────────────────

set -euo pipefail

REPO="shanon-web3/shanon"
BINARY_NAME="shanon"
INSTALL_DIR="${SHANON_INSTALL_DIR:-$HOME/.shanon/bin}"

# ─── Detect platform ────────────────────────────────────

detect_platform() {
    local os arch

    os="$(uname -s)"
    arch="$(uname -m)"

    case "$os" in
        Linux)  os="linux" ;;
        Darwin) os="darwin" ;;
        MINGW*|MSYS*|CYGWIN*) os="windows" ;;
        *)
            echo "Error: Unsupported OS: $os" >&2
            exit 1
            ;;
    esac

    case "$arch" in
        x86_64|amd64) arch="x86_64" ;;
        arm64|aarch64) arch="aarch64" ;;
        *)
            echo "Error: Unsupported architecture: $arch" >&2
            exit 1
            ;;
    esac

    echo "${os}_${arch}"
}

# ─── Get latest release version ─────────────────────────

get_latest_version() {
    curl -sSf "https://api.github.com/repos/${REPO}/releases/latest" |
        grep '"tag_name"' |
        sed -E 's/.*"tag_name": *"([^"]+)".*/\1/'
}

# ─── Download and install ────────────────────────────────

install() {
    local platform version download_url archive_name

    platform="$(detect_platform)"
    version="${SHANON_VERSION:-$(get_latest_version)}"

    echo ""
    echo "  🛡️  Shanon — Solana Security Platform"
    echo "  ─────────────────────────────────────"
    echo "  Version:  ${version}"
    echo "  Platform: ${platform}"
    echo "  Install:  ${INSTALL_DIR}"
    echo ""

    archive_name="${BINARY_NAME}-${version}-${platform}.tar.gz"
    download_url="https://github.com/${REPO}/releases/download/${version}/${archive_name}"

    # Create install directory
    mkdir -p "$INSTALL_DIR"

    # Download and extract
    echo "  Downloading ${archive_name}..."
    curl -sSfL "$download_url" | tar xz -C "$INSTALL_DIR"
    chmod +x "${INSTALL_DIR}/${BINARY_NAME}"

    echo ""
    echo "  ✅ Shanon installed to ${INSTALL_DIR}/${BINARY_NAME}"
    echo ""

    # Shell PATH update hint
    if [[ ":$PATH:" != *":${INSTALL_DIR}:"* ]]; then
        echo "  ⚠️  Add Shanon to your PATH:"
        echo ""
        echo "    export PATH=\"\$PATH:${INSTALL_DIR}\""
        echo ""
        echo "  Or add to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
        echo ""
        echo "    echo 'export PATH=\"\$PATH:${INSTALL_DIR}\"' >> ~/.bashrc"
        echo ""
    fi

    echo "  Get started:"
    echo ""
    echo "    shanon scan ./programs/my-program   # Vulnerability scan"
    echo "    shanon guard                        # Dependency firewall"
    echo "    shanon --help                       # All commands"
    echo ""
}

install
