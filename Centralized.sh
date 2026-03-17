#!/usr/bin/env bash

set -Eeuo pipefail

# ======================================
#  Centralized — Installation Script
#  Linux + macOS
# ======================================

REPO_URL="https://github.com/R3coNYT/Centralized.git"
INSTALL_ROOT_LINUX="/opt/centralized"
INSTALL_ROOT_MACOS="$HOME/Tools/Centralized"
APP_PORT=5000

COLOR_RED="\033[1;31m"
COLOR_GREEN="\033[1;32m"
COLOR_YELLOW="\033[1;33m"
COLOR_BLUE="\033[1;34m"
COLOR_RESET="\033[0m"

log()  { echo -e "${COLOR_BLUE}[+]${COLOR_RESET} $*"; }
ok()   { echo -e "${COLOR_GREEN}[✓]${COLOR_RESET} $*"; }
warn() { echo -e "${COLOR_YELLOW}[!]${COLOR_RESET} $*"; }
err()  { echo -e "${COLOR_RED}[✗]${COLOR_RESET} $*" >&2; }

cleanup_on_error() {
    err "Installation failed on line $1"
    exit 1
}
trap 'cleanup_on_error $LINENO' ERR

retry() {
    local attempts="$1"; shift
    local count=1
    until "$@"; do
        if [ "$count" -ge "$attempts" ]; then return 1; fi
        warn "Command failed. Retry $count/$attempts..."
        count=$((count + 1))
        sleep 2
    done
}

need_cmd() { command -v "$1" >/dev/null 2>&1; }

# ── Platform detection ─────────────────────────────────────────────────────────

detect_platform() {
    case "$(uname -s)" in
        Linux)  PLATFORM="linux" ;;
        Darwin) PLATFORM="macos" ;;
        *)
            err "Unsupported platform: $(uname -s)"
            exit 1
            ;;
    esac
    ok "Detected platform: $PLATFORM"
}

set_install_root() {
    if [ "$PLATFORM" = "linux" ]; then
        INSTALL_DIR="$INSTALL_ROOT_LINUX"
    else
        INSTALL_DIR="$INSTALL_ROOT_MACOS"
    fi
    ok "Install directory: $INSTALL_DIR"
}

get_sudo() {
    if [ "$PLATFORM" = "linux" ]; then
        if need_cmd sudo; then
            SUDO="sudo"
        else
            err "sudo is required on Linux"
            exit 1
        fi
    else
        SUDO=""
    fi
}

# ── Base dependencies ──────────────────────────────────────────────────────────

install_base_deps_linux() {
    log "Installing Linux system dependencies"
    retry 3 $SUDO apt-get update -qq

    local deps=(git curl python3 python3-pip python3-venv ca-certificates libxml2-dev libxslt1-dev)
    for pkg in "${deps[@]}"; do
        if dpkg -s "$pkg" >/dev/null 2>&1; then
            ok "$pkg already installed"
        else
            retry 3 $SUDO apt-get install -y "$pkg"
            ok "$pkg installed"
        fi
    done
}

install_base_deps_macos() {
    log "Installing macOS dependencies"
    if ! need_cmd brew; then
        err "Homebrew is required on macOS. Install it from https://brew.sh"
        exit 1
    fi

    local deps=(git curl python3)
    for pkg in "${deps[@]}"; do
        if brew list "$pkg" >/dev/null 2>&1; then
            ok "$pkg already installed"
        else
            retry 3 brew install "$pkg"
            ok "$pkg installed"
        fi
    done
}

# ── Python version check ───────────────────────────────────────────────────────

check_python() {
    local py_cmd=""
    for cmd in python3.12 python3.11 python3.10 python3 python; do
        if need_cmd "$cmd"; then
            local ver
            ver="$($cmd -c 'import sys; print(sys.version_info.minor)' 2>/dev/null || echo "0")"
            local major
            major="$($cmd -c 'import sys; print(sys.version_info.major)' 2>/dev/null || echo "0")"
            if [ "$major" -eq 3 ] && [ "$ver" -ge 10 ]; then
                py_cmd="$cmd"
                break
            fi
        fi
    done

    if [ -z "$py_cmd" ]; then
        err "Python 3.10+ is required but not found."
        if [ "$PLATFORM" = "linux" ]; then
            err "Run: sudo apt-get install python3.11"
        else
            err "Run: brew install python@3.11"
        fi
        exit 1
    fi

    PYTHON_CMD="$py_cmd"
    ok "Python detected: $PYTHON_CMD ($("$PYTHON_CMD" --version))"
}

# ── Clone / update repository ──────────────────────────────────────────────────

clone_or_update_repo() {
    log "Installing Centralized files"

    if [ "$PLATFORM" = "linux" ]; then
        $SUDO mkdir -p "$INSTALL_DIR"
        $SUDO chown -R "$USER":"$USER" "$INSTALL_DIR"
    else
        mkdir -p "$INSTALL_DIR"
    fi

    if [ -d "$INSTALL_DIR/.git" ]; then
        ok "Repository already present — pulling latest"
        git -C "$INSTALL_DIR" pull
    else
        retry 3 git clone "$REPO_URL" "$INSTALL_DIR"
    fi

    chmod +x "$INSTALL_DIR/update.sh"
}

# ── Python virtual environment ─────────────────────────────────────────────────

create_venv() {
    log "Creating Python virtual environment"
    cd "$INSTALL_DIR"

    if [ ! -d "$INSTALL_DIR/venv" ]; then
        "$PYTHON_CMD" -m venv "$INSTALL_DIR/venv"
    else
        ok "Virtual environment already exists"
    fi

    # shellcheck disable=SC1091
    source "$INSTALL_DIR/venv/bin/activate"

    retry 3 pip install --upgrade pip --quiet
    retry 3 pip install -r "$INSTALL_DIR/requirements.txt" --quiet

    deactivate
    ok "Python environment ready"
}

# ── Uploads directory ──────────────────────────────────────────────────────────

create_uploads_dir() {
    mkdir -p "$INSTALL_DIR/uploads"
    ok "Uploads directory ready"
}

# ── Global launcher script ─────────────────────────────────────────────────────

create_global_command_linux() {
    log "Creating global launcher: centralized"

    $SUDO tee /usr/local/bin/centralized >/dev/null <<EOF
#!/usr/bin/env bash
set -e
source "$INSTALL_DIR/venv/bin/activate"
cd "$INSTALL_DIR"
exec python app.py "\$@"
EOF

    $SUDO chmod +x /usr/local/bin/centralized
    ok "Global command created: centralized"
}

create_global_command_macos() {
    log "Creating global launcher: centralized"

    mkdir -p "$HOME/.local/bin"
    cat > "$HOME/.local/bin/centralized" <<EOF
#!/usr/bin/env bash
set -e
source "$INSTALL_DIR/venv/bin/activate"
cd "$INSTALL_DIR"
exec python app.py "\$@"
EOF

    chmod +x "$HOME/.local/bin/centralized"

    # Ensure ~/.local/bin is in PATH
    for rc in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.bash_profile"; do
        if [ -f "$rc" ] && ! grep -q 'HOME/.local/bin' "$rc"; then
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$rc"
        fi
    done

    export PATH="$HOME/.local/bin:$PATH"
    ok "Global command created: centralized"
}

# ── systemd service (Linux only, optional) ─────────────────────────────────────

create_systemd_service() {
    if ! need_cmd systemctl; then return; fi
    if [ "$PLATFORM" != "linux" ]; then return; fi

    log "Creating systemd service (centralized.service)"

    $SUDO tee /etc/systemd/system/centralized.service >/dev/null <<EOF
[Unit]
Description=Centralized Pentest Audit Platform
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$INSTALL_DIR/venv/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/app.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    $SUDO systemctl daemon-reload
    ok "Systemd service created"
    warn "To enable auto-start: sudo systemctl enable --now centralized"
}

# ── Final summary ─────────────────────────────────────────────────────────────

print_done() {
    echo
    echo "========================================"
    echo "     Centralized — Installation Done"
    echo "========================================"
    echo
    echo "  Install dir : $INSTALL_DIR"
    echo "  App URL     : http://127.0.0.1:$APP_PORT"
    echo "  Login       : admin / admin"
    echo
    echo "  Start the app:"
    echo "    centralized"
    echo
    if [ "$PLATFORM" = "linux" ] && need_cmd systemctl; then
        echo "  Or as a service:"
        echo "    sudo systemctl start centralized"
        echo
    fi
    if [ "$PLATFORM" = "macos" ]; then
        echo "  If 'centralized' is not found, reopen your terminal."
        echo
    fi
    echo "  IMPORTANT: Change the default admin password after first login!"
    echo
}

# ── Entry point ───────────────────────────────────────────────────────────────

main() {
    detect_platform
    set_install_root
    get_sudo
    check_python

    if [ "$PLATFORM" = "linux" ]; then
        install_base_deps_linux
    else
        install_base_deps_macos
    fi

    clone_or_update_repo
    create_venv
    create_uploads_dir

    if [ "$PLATFORM" = "linux" ]; then
        create_global_command_linux
        create_systemd_service
    else
        create_global_command_macos
    fi

    print_done
}

main "$@"
