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

# ── Resolve sudo ───────────────────────────────────────────────────────────────

get_sudo() {
    if [ "$PLATFORM" = "linux" ]; then
        if command -v sudo >/dev/null 2>&1; then
            SUDO="sudo"
        else
            err "sudo is required on Linux but was not found"
            exit 1
        fi
    else
        SUDO=""
    fi
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

# ── Refresh sudoers rule (adds !requiretty if missing) ───────────────────────

refresh_sudoers() {
    if [ "$PLATFORM" != "linux" ]; then return; fi
    if [ ! -d /etc/sudoers.d ]; then return; fi

    local systemctl_path
    systemctl_path="$(command -v systemctl 2>/dev/null || echo '/usr/bin/systemctl')"
    local sudoers_file="/etc/sudoers.d/centralized-restart"
    local expected_rule="Defaults:$USER !requiretty
$USER ALL=(ALL) NOPASSWD: $systemctl_path restart centralized"

    # Only rewrite if the !requiretty line is missing (avoids unnecessary sudo prompts)
    if [ ! -f "$sudoers_file" ] || ! grep -q "!requiretty" "$sudoers_file" 2>/dev/null; then
        printf '%s\n' "$expected_rule" | sudo tee "$sudoers_file" >/dev/null 2>&1 \
            && sudo chmod 440 "$sudoers_file" 2>/dev/null \
            && ok "Sudoers rule updated (added !requiretty for passwordless restart)" \
            || warn "Could not update sudoers rule — web-UI restart may prompt for a password"
    fi
}

# ── Trust SSL certificate in system + browser stores ───────────────────────────────

# Run a command with sudo if available, but never prompt for a password.
# Falls back to running without sudo (may fail silently).
_sudo_n() {
    if [ -n "$SUDO" ]; then
        sudo -n "$@" 2>/dev/null || return 0
    else
        "$@" 2>/dev/null || return 0
    fi
}

trust_ssl_cert() {
    local cert="$1"
    [ -f "$cert" ] || return

    if [ "$PLATFORM" = "linux" ]; then
        if [ -d /usr/local/share/ca-certificates ]; then
            _sudo_n cp "$cert" /usr/local/share/ca-certificates/centralized-local.crt
            _sudo_n update-ca-certificates --fresh >/dev/null 2>&1 && \
                ok "System CA store updated" || true
        elif [ -d /etc/pki/ca-trust/source/anchors ]; then
            _sudo_n cp "$cert" /etc/pki/ca-trust/source/anchors/centralized-local.crt
            _sudo_n update-ca-trust extract >/dev/null 2>&1 && \
                ok "System CA trust store updated" || true
        fi
    fi

    if [ "$PLATFORM" = "linux" ] && ! need_cmd certutil; then
        if need_cmd apt-get; then
            _sudo_n apt-get install -y -qq libnss3-tools >/dev/null 2>&1 || true
        elif need_cmd dnf; then
            _sudo_n dnf install -y -q nss-tools >/dev/null 2>&1 || true
        fi
    fi

    if need_cmd certutil; then
        local nss_dirs=("$HOME/.pki/nssdb" "$HOME/.local/share/pki/nssdb")
        local nss_pass
        nss_pass="$(mktemp)"
        printf '' > "$nss_pass"
        for nssdb in "${nss_dirs[@]}"; do
            if [ ! -d "$nssdb" ]; then
                mkdir -p "$nssdb"
                certutil -d "sql:$nssdb" -N --empty-password >/dev/null 2>&1 || continue
            fi
            certutil -d "sql:$nssdb" -D -n "Centralized" -f "$nss_pass" >/dev/null 2>&1 || true
            certutil -d "sql:$nssdb" -A -n "Centralized" -t "CT,," -i "$cert" -f "$nss_pass" >/dev/null 2>&1 && \
                ok "Certificate trusted in Chrome NSS db ($nssdb)"
        done
        rm -f "$nss_pass"
    fi
}

# ── SSL certificate check / renewal ───────────────────────────────────────────────────

ensure_ssl() {
    local ssl_dir="$INSTALL_DIR/ssl"
    mkdir -p "$ssl_dir"
    chmod 700 "$ssl_dir"

    # Check if a valid cert exists (more than 30 days remaining)
    if [ -f "$ssl_dir/cert.pem" ] && [ -f "$ssl_dir/key.pem" ]; then
        if openssl x509 -checkend 2592000 -noout -in "$ssl_dir/cert.pem" >/dev/null 2>&1; then
            local expiry
            expiry="$(openssl x509 -enddate -noout -in "$ssl_dir/cert.pem" 2>/dev/null | cut -d= -f2)"
            ok "SSL certificate valid (expires: $expiry)"
            trust_ssl_cert "$ssl_dir/cert.pem"
            return
        fi
        warn "SSL certificate expiring within 30 days"
    else
        log "No SSL certificate found — generating self-signed"
    fi

    # If the existing cert was issued by Let\'s Encrypt, try certbot renew first
    if [ -f "$ssl_dir/cert.pem" ] && \
       openssl x509 -issuer -noout -in "$ssl_dir/cert.pem" 2>/dev/null | grep -qi "let.*encrypt"; then
        log "Detected Let's Encrypt certificate — running certbot renew"
        local domain
        domain="$(openssl x509 -subject -noout -in "$ssl_dir/cert.pem" 2>/dev/null | \
            sed 's/.*CN[[:space:]]*=[[:space:]]*\([^,/]*\).*/\1/')"
        if [ -n "$domain" ] && _sudo_n certbot renew --quiet --cert-name "$domain" 2>/dev/null; then
            _sudo_n cp "/etc/letsencrypt/live/$domain/fullchain.pem" "$ssl_dir/cert.pem"
            _sudo_n cp "/etc/letsencrypt/live/$domain/privkey.pem"   "$ssl_dir/key.pem"
            _sudo_n chown "$USER:$USER" "$ssl_dir/cert.pem" "$ssl_dir/key.pem"
            chmod 600 "$ssl_dir/key.pem"
            ok "Let's Encrypt certificate renewed for $domain"
            return
        fi
        warn "certbot renew failed — falling back to self-signed"
    fi

    # Generate / regenerate a self-signed certificate
    local ip="" san cfg
    if [ "$PLATFORM" = "linux" ]; then
        ip="$(hostname -I 2>/dev/null | awk '{print $1}')" || ip=""
    else
        ip="$(ipconfig getifaddr en0 2>/dev/null)" || ip=""
    fi
    san="DNS:localhost,IP:127.0.0.1"
    [ -n "$ip" ] && [ "$ip" != "127.0.0.1" ] && san="$san,IP:$ip"

    cfg="$(mktemp /tmp/cent_ssl_XXXXXX.cnf)"
    cat > "$cfg" <<SSLCNF
[req]
default_bits       = 2048
prompt             = no
distinguished_name = dn
x509_extensions    = san
[dn]
CN = localhost
O  = Centralized
[san]
subjectAltName = $san
SSLCNF

    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$ssl_dir/key.pem" \
        -out    "$ssl_dir/cert.pem" \
        -config "$cfg" 2>/dev/null
    rm -f "$cfg"
    chmod 600 "$ssl_dir/key.pem"
    ok "Self-signed certificate generated (365 days)"
    trust_ssl_cert "$ssl_dir/cert.pem"
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
    local scheme="http"
    [ -f "$INSTALL_DIR/ssl/cert.pem" ] && scheme="https"
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
        echo "  URL         : $scheme://127.0.0.1:5000"
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
    get_sudo
    find_install_dir
    info "Install directory: $INSTALL_DIR"

    backup_data
    git_update
    update_deps
    apply_db_migrations
    ensure_ssl
    prune_backups
    refresh_sudoers
    restart_service
    chmod +x "$INSTALL_DIR/update.sh"
    print_done
}

main "$@"
