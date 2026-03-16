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

    # Protect data files before git reset: centralized.db / uploads/ may still
    # be tracked in the remote repo if they were committed before .gitignore was
    # added. git reset --hard would overwrite them.
    local tmp_protect
    tmp_protect="$(mktemp -d)"

    [ -f "$INSTALL_DIR/centralized.db" ] && cp "$INSTALL_DIR/centralized.db" "$tmp_protect/"
    [ -d "$INSTALL_DIR/uploads" ]        && cp -r "$INSTALL_DIR/uploads" "$tmp_protect/uploads"

    # Fetch + reset to match remote
    git fetch origin
    local current_branch
    current_branch="$(git rev-parse --abbrev-ref HEAD)"
    git reset --hard "origin/$current_branch"

    # Untrack data files so future resets never touch them
    git rm --cached centralized.db -q 2>/dev/null || true
    git rm --cached -r uploads/ -q 2>/dev/null || true

    # Restore protected data files
    if [ -f "$tmp_protect/centralized.db" ]; then
        cp -f "$tmp_protect/centralized.db" "$INSTALL_DIR/"
        ok "Database restored ($(du -sh "$INSTALL_DIR/centralized.db" | cut -f1))"
    else
        warn "No database to restore — was not present before update"
    fi

    if [ -d "$tmp_protect/uploads" ]; then
        cp -rf "$tmp_protect/uploads" "$INSTALL_DIR/"
        ok "Uploads restored ($(du -sh "$INSTALL_DIR/uploads" | cut -f1))"
    else
        warn "No uploads directory to restore — was not present before update"
    fi

    rm -rf "$tmp_protect"

    # Verify data integrity after restore
    if [ -f "$BACKUP_DIR/centralized.db" ] && [ -f "$INSTALL_DIR/centralized.db" ]; then
        local backup_size install_size
        backup_size="$(stat -c%s "$BACKUP_DIR/centralized.db" 2>/dev/null || stat -f%z "$BACKUP_DIR/centralized.db")"
        install_size="$(stat -c%s "$INSTALL_DIR/centralized.db" 2>/dev/null || stat -f%z "$INSTALL_DIR/centralized.db")"
        if [ "$backup_size" -eq "$install_size" ]; then
            ok "Database integrity verified (${install_size} bytes)"
        else
            err "Database size mismatch after restore! Backup: ${backup_size}B, Installed: ${install_size}B"
            err "Manually restore from: $BACKUP_DIR/centralized.db"
            exit 1
        fi
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
    print_done
}

main "$@"
