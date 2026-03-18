#!/usr/bin/env bash

set -Eeuo pipefail

# ======================================
#  Centralized — Rollback Script
#  Linux + macOS
# ======================================

INSTALL_ROOT_LINUX="/opt/centralized"
INSTALL_ROOT_MACOS="$HOME/Tools/Centralized"

COLOR_RED="\033[1;31m"
COLOR_GREEN="\033[1;32m"
COLOR_YELLOW="\033[1;33m"
COLOR_BLUE="\033[1;34m"
COLOR_CYAN="\033[1;36m"
COLOR_RESET="\033[0m"

log()  { echo -e "${COLOR_BLUE}[+]${COLOR_RESET} $*"; }
ok()   { echo -e "${COLOR_GREEN}[✓]${COLOR_RESET} $*"; }
warn() { echo -e "${COLOR_YELLOW}[!]${COLOR_RESET} $*"; }
err()  { echo -e "${COLOR_RED}[✗]${COLOR_RESET} $*" >&2; }
info() { echo -e "${COLOR_CYAN}[i]${COLOR_RESET} $*"; }

cleanup_on_error() {
    err "Rollback failed on line $1"
    err "Your data has NOT been modified — check the backup directory if needed."
    exit 1
}
trap 'cleanup_on_error $LINENO' ERR

# ── Detect platform ────────────────────────────────────────────────────────────

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

# ── Locate install directory ───────────────────────────────────────────────────

find_install_dir() {
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [ -f "$script_dir/app.py" ] && [ -d "$script_dir/.git" ]; then
        INSTALL_DIR="$script_dir"
        return
    fi

    local default_dir
    if [ "$PLATFORM" = "linux" ]; then
        default_dir="$INSTALL_ROOT_LINUX"
    else
        default_dir="$INSTALL_ROOT_MACOS"
    fi

    if [ -f "$default_dir/app.py" ] && [ -d "$default_dir/.git" ]; then
        INSTALL_DIR="$default_dir"
        return
    fi

    err "Could not locate the Centralized install directory."
    err "Run this script from inside the install directory, or install first with Centralized.sh"
    exit 1
}

# ── Backup data ────────────────────────────────────────────────────────────────

backup_data() {
    local timestamp
    timestamp="$(date +%Y%m%d_%H%M%S)"
    BACKUP_DIR="$INSTALL_DIR/backups/$timestamp"

    log "Creating backup → $BACKUP_DIR"
    mkdir -p "$BACKUP_DIR"

    if [ -f "$INSTALL_DIR/centralized.db" ]; then
        cp "$INSTALL_DIR/centralized.db" "$BACKUP_DIR/centralized.db"
        ok "Database backed up ($(du -sh "$INSTALL_DIR/centralized.db" | cut -f1))"
    else
        warn "No database found — nothing to back up"
    fi

    if [ -d "$INSTALL_DIR/uploads" ] && [ "$(ls -A "$INSTALL_DIR/uploads" 2>/dev/null)" ]; then
        cp -r "$INSTALL_DIR/uploads" "$BACKUP_DIR/uploads"
        ok "Uploads backed up"
    fi

    if [ -f "$INSTALL_DIR/.env" ]; then
        cp "$INSTALL_DIR/.env" "$BACKUP_DIR/.env"
        ok ".env backed up"
    fi

    ok "Backup complete → $BACKUP_DIR"
}

# ── Git rollback to specific commit ───────────────────────────────────────────

git_rollback() {
    log "Rolling back to commit $COMMIT"
    cd "$INSTALL_DIR"

    local stash_result
    stash_result="$(git stash 2>&1)" || true
    if ! echo "$stash_result" | grep -q "No local changes"; then
        info "Local file changes stashed: $stash_result"
    fi

    # Untrack data files so git never touches them
    git rm --cached centralized.db -q 2>/dev/null || true
    git rm --cached -r uploads/ -q 2>/dev/null || true

    # Fetch all refs so the target commit is available locally
    git fetch origin

    # Reset to the requested commit
    git reset --hard "$COMMIT"

    # Restore data files from the backup taken at the start of this rollback
    log "Restoring data from backup → $BACKUP_DIR"

    if [ -f "$BACKUP_DIR/centralized.db" ]; then
        cp -f "$BACKUP_DIR/centralized.db" "$INSTALL_DIR/centralized.db"
        ok "Database restored"
    else
        warn "No database in backup — skipping DB restore"
    fi

    if [ -d "$BACKUP_DIR/uploads" ]; then
        cp -rf "$BACKUP_DIR/uploads/." "$INSTALL_DIR/uploads/"
        ok "Uploads restored"
    fi

    if [ -f "$BACKUP_DIR/.env" ] && [ ! -f "$INSTALL_DIR/.env" ]; then
        cp -f "$BACKUP_DIR/.env" "$INSTALL_DIR/.env"
        ok ".env restored"
    fi

    local actual
    actual="$(git rev-parse --short HEAD)"
    ok "Code rolled back → commit $actual"
}

# ── Sync Python dependencies ───────────────────────────────────────────────────

update_deps() {
    local venv_python="$INSTALL_DIR/venv/bin/python"
    local venv_pip="$INSTALL_DIR/venv/bin/pip"

    if [ ! -f "$venv_python" ]; then
        err "Virtual environment not found at $INSTALL_DIR/venv"
        err "Please run Centralized.sh to reinstall."
        exit 1
    fi

    log "Syncing Python dependencies"
    "$venv_pip" install --upgrade pip --quiet
    # Install (not --upgrade) to match the requirements of the rolled-back version exactly
    "$venv_pip" install -r "$INSTALL_DIR/requirements.txt" --quiet
    ok "Dependencies ready"
}

# ── Apply DB migrations ────────────────────────────────────────────────────────

apply_db_migrations() {
    log "Applying database migrations"
    cd "$INSTALL_DIR"
    "$INSTALL_DIR/venv/bin/python" - <<'PYEOF'
from app import create_app
app = create_app()
print("  Database schema up-to-date.")
PYEOF
    ok "Database migrations complete"
}

# ── Clean up old backups (keep last 5) ────────────────────────────────────────

prune_backups() {
    local backup_root="$INSTALL_DIR/backups"
    if [ ! -d "$backup_root" ]; then return; fi

    local count
    count="$(find "$backup_root" -maxdepth 1 -mindepth 1 -type d | wc -l)"
    if [ "$count" -le 5 ]; then return; fi

    info "Pruning old backups (keeping last 5 of $count)"
    find "$backup_root" -maxdepth 1 -mindepth 1 -type d \
        | sort \
        | head -n "$((count - 5))" \
        | xargs rm -rf
    ok "Old backups pruned"
}

# ── Restart service ────────────────────────────────────────────────────────────

restart_service() {
    if [ "${NO_RESTART:-0}" = "1" ]; then
        warn "Service restart skipped (--no-restart flag set)"
        return
    fi
    if [ "$PLATFORM" != "linux" ]; then return; fi
    if ! command -v systemctl >/dev/null 2>&1; then return; fi
    if ! systemctl list-unit-files centralized.service >/dev/null 2>&1; then
        warn "systemd service 'centralized' not found — start manually"
        return
    fi

    log "Restarting centralized service"
    sudo systemctl restart centralized
    sleep 2
    if systemctl is-active --quiet centralized; then
        ok "Service restarted and running"
    else
        err "Service failed to start after restart"
        err "Check logs: sudo journalctl -u centralized -n 50"
        exit 1
    fi
}

# ── Summary ───────────────────────────────────────────────────────────────────

print_done() {
    echo
    echo "========================================"
    echo "     Centralized — Rollback Complete"
    echo "========================================"
    echo
    echo "  Install dir : $INSTALL_DIR"
    echo "  Backup      : $BACKUP_DIR"
    echo "  Rolled to   : $(git -C "$INSTALL_DIR" rev-parse --short HEAD)"
    echo
    echo "  Your clients, audits and uploaded files are intact."
    echo
}

# ── Entry point ───────────────────────────────────────────────────────────────

main() {
    echo
    echo "========================================"
    echo "   Centralized — Rollback Script"
    echo "========================================"
    echo

    NO_RESTART=0
    COMMIT=""

    while [ $# -gt 0 ]; do
        case "$1" in
            --no-restart) NO_RESTART=1; shift ;;
            --commit)     COMMIT="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    export NO_RESTART

    if [ -z "$COMMIT" ]; then
        err "--commit <sha> is required"
        exit 1
    fi
    # Validate commit SHA (7-40 hex chars only — prevents command injection)
    if ! echo "$COMMIT" | grep -qE '^[0-9a-fA-F]{7,40}$'; then
        err "Invalid commit SHA: '$COMMIT' (must be 7-40 hex characters)"
        exit 1
    fi
    export COMMIT

    detect_platform
    find_install_dir
    info "Install directory: $INSTALL_DIR"
    info "Target commit    : $COMMIT"

    backup_data
    git_rollback
    update_deps
    apply_db_migrations
    prune_backups
    restart_service
    chmod +x "$INSTALL_DIR/rollback.sh"
    print_done
}

main "$@"
