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

    # Fetch + reset to match remote exactly (safe because data files are in .gitignore)
    git fetch origin
    local current_branch
    current_branch="$(git rev-parse --abbrev-ref HEAD)"
    git reset --hard "origin/$current_branch"

    local new_commit
    new_commit="$(git rev-parse --short HEAD)"
    ok "Code updated → commit $new_commit (branch: $current_branch)"
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
    echo "  Restart the app to apply changes:"
    echo "    centralized"
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
    print_done
}

main "$@"
