#!/usr/bin/env bash

set -Eeuo pipefail

# ======================================
#  Centralized — Uninstall Script
#  Linux + macOS
# ======================================

INSTALL_ROOT_LINUX="/opt/centralized"
INSTALL_ROOT_MACOS="$HOME/Tools/Centralized"
SERVICE_NAME="centralized"
GLOBAL_CMD_LINUX="/usr/local/bin/centralized"
GLOBAL_CMD_MACOS="$HOME/.local/bin/centralized"
SUDOERS_FILE="/etc/sudoers.d/centralized-restart"

COLOR_RED="\033[1;31m"
COLOR_GREEN="\033[1;32m"
COLOR_YELLOW="\033[1;33m"
COLOR_BLUE="\033[1;34m"
COLOR_RESET="\033[0m"

log()  { echo -e "${COLOR_BLUE}[+]${COLOR_RESET} $*"; }
ok()   { echo -e "${COLOR_GREEN}[✓]${COLOR_RESET} $*"; }
warn() { echo -e "${COLOR_YELLOW}[!]${COLOR_RESET} $*"; }
err()  { echo -e "${COLOR_RED}[✗]${COLOR_RESET} $*" >&2; }

KEEP_DATA=false
FORCE=false

usage() {
    echo "Usage: $0 [--keep-data] [--force]"
    echo ""
    echo "  --keep-data   Keep centralized.db, uploads/ and backups/"
    echo "  --force       Skip interactive confirmation"
    exit 0
}

for arg in "$@"; do
    case "$arg" in
        --keep-data) KEEP_DATA=true ;;
        --force)     FORCE=true ;;
        --help|-h)   usage ;;
        *) err "Unknown option: $arg"; usage ;;
    esac
done

# ── Platform detection ────────────────────────────────────────────────────────

detect_platform() {
    case "$(uname -s)" in
        Linux)  PLATFORM="linux" ;;
        Darwin) PLATFORM="macos" ;;
        *)
            err "Unsupported platform: $(uname -s)"
            exit 1
            ;;
    esac
}

need_cmd() { command -v "$1" >/dev/null 2>&1; }

get_sudo() {
    if [ "$PLATFORM" = "linux" ]; then
        need_cmd sudo && SUDO="sudo" || { err "sudo required on Linux"; exit 1; }
    else
        SUDO=""
    fi
}

set_install_dir() {
    if [ "$PLATFORM" = "linux" ]; then
        INSTALL_DIR="$INSTALL_ROOT_LINUX"
    else
        INSTALL_DIR="$INSTALL_ROOT_MACOS"
    fi
}

# ── Banner ────────────────────────────────────────────────────────────────────

print_banner() {
    echo ""
    echo "========================================"
    echo "   Centralized - Uninstall"
    echo "========================================"
    echo ""
    echo "  Platform    : $PLATFORM"
    echo "  Directory   : $INSTALL_DIR"
    if [ "$KEEP_DATA" = true ]; then
        echo "  Mode        : keep data (db + uploads)"
    else
        echo "  Mode        : full removal"
    fi
    echo ""
}

# ── Confirmation ──────────────────────────────────────────────────────────────

confirm() {
    if [ "$FORCE" = true ]; then return; fi
    read -r -p "Confirm uninstall? [y/N] " answer
    case "$answer" in
        [yY]*) ;;
        *) warn "Cancelled."; exit 0 ;;
    esac
}

# -- 1. Stop and remove systemd service (Linux) ------------------------------

remove_systemd_service() {
    if [ "$PLATFORM" != "linux" ]; then return; fi
    if ! need_cmd systemctl; then return; fi

    log "Removing systemd service '$SERVICE_NAME'..."

    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        $SUDO systemctl stop "$SERVICE_NAME"
        ok "Service stopped"
    fi

    if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        $SUDO systemctl disable "$SERVICE_NAME"
        ok "Service disabled"
    fi

    local unit_file="/etc/systemd/system/${SERVICE_NAME}.service"
    if [ -f "$unit_file" ]; then
        $SUDO rm -f "$unit_file"
        $SUDO systemctl daemon-reload
        ok "Unit file removed"
    else
        warn "Unit file '$unit_file' not found (already removed?)"
    fi

    # Remove sudoers rule
    if [ -f "$SUDOERS_FILE" ]; then
        $SUDO rm -f "$SUDOERS_FILE"
        ok "Sudoers rule removed"
    fi
}

# -- 2. Remove global launcher -----------------------------------------------

remove_global_command() {
    log "Removing global 'centralized' launcher..."

    if [ "$PLATFORM" = "linux" ]; then
        if [ -f "$GLOBAL_CMD_LINUX" ]; then
            $SUDO rm -f "$GLOBAL_CMD_LINUX"
            ok "Launcher removed: $GLOBAL_CMD_LINUX"
        else
            warn "Launcher '$GLOBAL_CMD_LINUX' not found"
        fi
    else
        if [ -f "$GLOBAL_CMD_MACOS" ]; then
            rm -f "$GLOBAL_CMD_MACOS"
            ok "Launcher removed: $GLOBAL_CMD_MACOS"
        else
            warn "Launcher '$GLOBAL_CMD_MACOS' not found"
        fi
    fi
}

# -- 3. Remove install directory ---------------------------------------------

remove_install_dir() {
    if [ ! -d "$INSTALL_DIR" ]; then
        warn "Directory '$INSTALL_DIR' not found (already removed?)"
        return
    fi

    if [ "$KEEP_DATA" = true ]; then
        log "Removing files (keeping db + uploads + backups)..."
        find "$INSTALL_DIR" -mindepth 1 -maxdepth 1 \
            ! -name "centralized.db" \
            ! -name "uploads" \
            ! -name "backups" \
            -exec $SUDO rm -rf {} +
        ok "Files removed - data kept in $INSTALL_DIR"
    else
        log "Removing $INSTALL_DIR..."
        if [ "$PLATFORM" = "linux" ]; then
            $SUDO rm -rf "$INSTALL_DIR"
        else
            rm -rf "$INSTALL_DIR"
        fi
        ok "Directory removed"

        # Remove parent ~/Tools directory if empty (macOS)
        if [ "$PLATFORM" = "macos" ]; then
            local parent
            parent="$(dirname "$INSTALL_DIR")"
            if [ -d "$parent" ] && [ -z "$(ls -A "$parent" 2>/dev/null)" ]; then
                rmdir "$parent"
                ok "$parent removed (was empty)"
            fi
        fi
    fi
}

# -- Summary -----------------------------------------------------------------

print_done() {
    echo ""
    echo "========================================"
    echo "   Centralized - Uninstalled"
    echo "========================================"
    echo ""
    if [ "$KEEP_DATA" = true ]; then
        echo "  Data kept in: $INSTALL_DIR"
        echo ""
    fi
}

# ── Entry point ───────────────────────────────────────────────────────────────

main() {
    detect_platform
    get_sudo
    set_install_dir
    print_banner
    confirm
    remove_systemd_service
    remove_global_command
    remove_install_dir
    print_done
}

main "$@"
