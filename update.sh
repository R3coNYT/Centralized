#!/usr/bin/env bash

set -Eeuo pipefail

# ======================================
#  Centralized — Update Script
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
    err "Update failed on line $1"
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
    # 1) Script's own directory (if update.sh lives inside the install dir)
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [ -f "$script_dir/app.py" ] && [ -d "$script_dir/.git" ]; then
        INSTALL_DIR="$script_dir"
        return
    fi

    # 2) Default platform paths
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

    # SQLite database
    if [ -f "$INSTALL_DIR/centralized.db" ]; then
        cp "$INSTALL_DIR/centralized.db" "$BACKUP_DIR/centralized.db"
        ok "Database backed up ($(du -sh "$INSTALL_DIR/centralized.db" | cut -f1))"
    else
        warn "No database found — nothing to back up"
    fi

    # Uploaded files
    if [ -d "$INSTALL_DIR/uploads" ] && [ "$(ls -A "$INSTALL_DIR/uploads" 2>/dev/null)" ]; then
        cp -r "$INSTALL_DIR/uploads" "$BACKUP_DIR/uploads"
        ok "Uploads backed up ($(du -sh "$INSTALL_DIR/uploads" | cut -f1))"
    fi

    # Local config override (.env)
    if [ -f "$INSTALL_DIR/.env" ]; then
        cp "$INSTALL_DIR/.env" "$BACKUP_DIR/.env"
        ok ".env backed up"
    fi

    ok "Backup complete → $BACKUP_DIR"
}

# ── Git pull ───────────────────────────────────────────────────────────────────

git_update() {
    log "Pulling latest code from GitHub"
    cd "$INSTALL_DIR"

    # Stash any local modifications to tracked files (e.g. accidental edits)
    local stash_result
    stash_result="$(git stash 2>&1)" || true
    if echo "$stash_result" | grep -q "No local changes"; then
        : # nothing to stash
    else
        info "Local file changes stashed: $stash_result"
    fi

    # Untrack data files BEFORE reset so git never tries to write/delete them
    # (critical on Windows where the DB file may be locked by a running process)
    git rm --cached centralized.db -q 2>/dev/null || true
    git rm --cached -r uploads/ -q 2>/dev/null || true

    # Fetch + reset to match remote
    git fetch origin
    local current_branch
    current_branch="$(git rev-parse --abbrev-ref HEAD)"
    git reset --hard "origin/$current_branch"

    # Restore data files from the backup taken at the start of this update
    log "Restoring data from backup → $BACKUP_DIR"

    if [ -f "$BACKUP_DIR/centralized.db" ]; then
        cp -f "$BACKUP_DIR/centralized.db" "$INSTALL_DIR/centralized.db"
        ok "Database restored ($(du -sh "$INSTALL_DIR/centralized.db" | cut -f1))"
    else
        warn "No database in backup — skipping DB restore"
    fi

    if [ -d "$BACKUP_DIR/uploads" ]; then
        cp -rf "$BACKUP_DIR/uploads/." "$INSTALL_DIR/uploads/"
        ok "Uploads restored ($(du -sh "$INSTALL_DIR/uploads" | cut -f1))"
    else
        warn "No uploads in backup — skipping uploads restore"
    fi

    if [ -f "$BACKUP_DIR/.env" ]; then
        cp -f "$BACKUP_DIR/.env" "$INSTALL_DIR/.env"
        ok ".env restored"
    fi

    local new_commit
    new_commit="$(git rev-parse --short HEAD)"
    ok "Code updated → commit $new_commit (branch: $current_branch)"
    ok "Data files are intact"
}

# ── Update Python dependencies ─────────────────────────────────────────────────

update_deps() {
    local venv_python="$INSTALL_DIR/venv/bin/python"
    local venv_pip="$INSTALL_DIR/venv/bin/pip"

    if [ ! -f "$venv_python" ]; then
        err "Virtual environment not found at $INSTALL_DIR/venv"
        err "Please run Centralized.sh to reinstall."
        exit 1
    fi

    log "Updating Python dependencies"
    "$venv_pip" install --upgrade pip --quiet
    "$venv_pip" install -r "$INSTALL_DIR/requirements.txt" --upgrade --quiet
    ok "Dependencies updated"
}

# ── Apply DB migrations (create new tables / columns) ─────────────────────────

apply_db_migrations() {
    log "Applying database migrations"
    cd "$INSTALL_DIR"
    # create_app() calls db.create_all() (new tables) then _migrate_db() which
    # auto-detects every missing column across all models and runs ALTER TABLE.
    # No manual maintenance needed — any column added to models is handled here.
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

# ── Restart service ──────────────────────────────────────────────────────────

restart_service() {
    if [ "$PLATFORM" != "linux" ]; then return; fi
    if ! command -v systemctl >/dev/null 2>&1; then return; fi
    if ! systemctl list-unit-files centralized.service >/dev/null 2>&1; then
        warn "systemd service 'centralized' not found — skipping restart"
        warn "Start manually with: centralized"
        return
    fi

    log "Restarting centralized service"
    sudo systemctl restart centralized
    # Give it a moment to come up
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
    echo "     Centralized — Update Complete"
    echo "========================================"
    echo
    echo "  Install dir : $INSTALL_DIR"
    echo "  Backup      : $BACKUP_DIR"
    echo "  Commit      : $(git -C "$INSTALL_DIR" rev-parse --short HEAD)"
    echo
    echo "  Your clients, audits and uploaded files are intact."
    echo
    if [ "$PLATFORM" = "linux" ] && command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet centralized 2>/dev/null; then
        echo "  Service     : running (sudo systemctl status centralized)"
    else
        echo "  Start the app: centralized"
    fi
    echo
}

# ── Entry point ───────────────────────────────────────────────────────────────

main() {
    echo
    echo "========================================"
    echo "   Centralized — Update Script"
    echo "========================================"
    echo

    detect_platform
    find_install_dir
    info "Install directory: $INSTALL_DIR"

    backup_data
    git_update
    update_deps
    apply_db_migrations
    prune_backups
    restart_service
    chmod +x "$INSTALL_DIR/update.sh"
    print_done
}

main "$@"
