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

    local deps=(git curl python3 python3-pip python3-venv ca-certificates libxml2-dev libxslt1-dev)

    # Check if every dependency is already present — skip apt-get update entirely
    local all_installed=true
    for pkg in "${deps[@]}"; do
        if ! dpkg -s "$pkg" >/dev/null 2>&1; then
            all_installed=false
            break
        fi
    done

    if $all_installed; then
        ok "All system dependencies already installed — skipping apt update"
    else
        retry 3 $SUDO apt-get update -qq

        for pkg in "${deps[@]}"; do
            if dpkg -s "$pkg" >/dev/null 2>&1; then
                ok "$pkg already installed"
            else
                retry 3 $SUDO apt-get install -y "$pkg"
                ok "$pkg installed"
            fi
        done
    fi
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
    chmod +x "$INSTALL_DIR/rollback.sh"
    chmod +x "$INSTALL_DIR/uninstall.sh"
}
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

# ── SSL certificate setup ──────────────────────────────────────────────────────

_ssl_selfcert() {
    # Usage: _ssl_selfcert <ssl_dir> [<CN>]
    local ssl_dir="$1" cn="${2:-localhost}" ip="" san cfg
    if [ "$PLATFORM" = "linux" ]; then
        ip="$(hostname -I 2>/dev/null | awk '{print $1}')" || ip=""
    else
        ip="$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null)" || ip=""
    fi
    san="DNS:localhost,IP:127.0.0.1"
    [ -n "$ip" ] && [ "$ip" != "127.0.0.1" ] && san="$san,IP:$ip"
    [ "$cn" != "localhost" ]                   && san="$san,DNS:$cn"

    # Use a config file for SAN — compatible with OpenSSL and LibreSSL (macOS)
    cfg="$(mktemp /tmp/cent_ssl_XXXXXX.cnf)"
    cat > "$cfg" <<SSLCNF
[req]
default_bits       = 2048
prompt             = no
distinguished_name = dn
x509_extensions    = san
[dn]
CN = $cn
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
    local expiry
    expiry="$(openssl x509 -enddate -noout -in "$ssl_dir/cert.pem" 2>/dev/null | cut -d= -f2)"
    ok "Self-signed certificate generated (CN=$cn, expires: $expiry)"
}

_ssl_letsencrypt() {
    local ssl_dir="$1" domain="$2"
    if ! need_cmd certbot; then
        if [ "$PLATFORM" = "linux" ]; then
            log "Installing certbot"
            retry 3 $SUDO apt-get install -y certbot >/dev/null 2>&1 || { warn "Could not install certbot"; return 1; }
        else
            warn "certbot not available — using self-signed"; return 1
        fi
    fi
    log "Requesting Let's Encrypt certificate for $domain (port 80 must be open)"
    $SUDO certbot certonly --standalone -d "$domain" \
        --non-interactive --agree-tos --email "admin@$domain" --quiet 2>/dev/null || {
        warn "Let's Encrypt request failed — using self-signed"; return 1
    }
    $SUDO cp "/etc/letsencrypt/live/$domain/fullchain.pem" "$ssl_dir/cert.pem"
    $SUDO cp "/etc/letsencrypt/live/$domain/privkey.pem"   "$ssl_dir/key.pem"
    $SUDO chown "$USER:$USER" "$ssl_dir/cert.pem" "$ssl_dir/key.pem"
    chmod 600 "$ssl_dir/key.pem"
    ok "Let's Encrypt certificate obtained for $domain"
    return 0
}

_ssl_setup_renewal() {
    local ssl_dir="$1" mode="$2" domain="${3:-}"
    local renew_script="$ssl_dir/renew.sh"

    # Build the renewal script using printf (avoids nested heredoc issues)
    printf '#!/usr/bin/env bash\n# Centralized SSL renewal — managed by installer\nSSL_DIR="%s"\n' "$ssl_dir" > "$renew_script"
    printf '# Exit if cert has more than 30 days left\n' >> "$renew_script"
    printf 'openssl x509 -checkend 2592000 -noout -in "$SSL_DIR/cert.pem" >/dev/null 2>&1 && exit 0\n' >> "$renew_script"
    printf 'echo "[$(date)] Certificate expiring within 30 days — renewing"\n' >> "$renew_script"

    if [ "$mode" = "letsencrypt" ] && [ -n "$domain" ]; then
        printf 'DOMAIN="%s"\n' "$domain" >> "$renew_script"
        printf 'certbot renew --quiet --cert-name "$DOMAIN" 2>/dev/null && \\\n' >> "$renew_script"
        printf '    cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$SSL_DIR/cert.pem" && \\\n' >> "$renew_script"
        printf '    cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem"   "$SSL_DIR/key.pem"  && \\\n' >> "$renew_script"
        printf '    chmod 600 "$SSL_DIR/key.pem" && systemctl restart centralized 2>/dev/null || true\n' >> "$renew_script"
        printf 'echo "[$(date)] Renewal complete"\n' >> "$renew_script"
    else
        # Self-signed regeneration
        local ip="" san="DNS:localhost,IP:127.0.0.1"
        ip="$(hostname -I 2>/dev/null | awk '{print $1}')" || ip=""
        [ -n "$ip" ] && [ "$ip" != "127.0.0.1" ] && san="$san,IP:$ip"
        printf 'CFG="$(mktemp /tmp/cent_ssl_XXXXXX.cnf)"\n' >> "$renew_script"
        printf 'printf "[req]\\ndefault_bits=2048\\nprompt=no\\ndistinguished_name=dn\\nx509_extensions=san\\n[dn]\\nCN=localhost\\nO=Centralized\\n[san]\\nsubjectAltName=%s" > "$CFG"\n' "$san" >> "$renew_script"
        printf 'openssl req -x509 -nodes -days 365 -newkey rsa:2048 \\\n' >> "$renew_script"
        printf '    -keyout "$SSL_DIR/key.pem" -out "$SSL_DIR/cert.pem" \\\n' >> "$renew_script"
        printf '    -config "$CFG" 2>/dev/null && rm -f "$CFG" && chmod 600 "$SSL_DIR/key.pem"\n' >> "$renew_script"
        printf 'systemctl restart centralized 2>/dev/null || true\n' >> "$renew_script"
        printf 'echo "[$(date)] Self-signed certificate regenerated"\n' >> "$renew_script"
    fi
    chmod +x "$renew_script"
    ok "Renewal script: $renew_script"

    mkdir -p "$INSTALL_DIR/logs"
    if [ "$PLATFORM" = "linux" ] && need_cmd systemctl; then
        local ssl_abs
        ssl_abs="$(realpath "$ssl_dir" 2>/dev/null || echo "$ssl_dir")"
        $SUDO tee /etc/systemd/system/centralized-ssl-renew.service >/dev/null <<SVC
[Unit]
Description=Centralized SSL certificate renewal
[Service]
Type=oneshot
User=$USER
ExecStart=${ssl_abs}/renew.sh
StandardOutput=append:${INSTALL_DIR}/logs/ssl_renew.log
SVC
        $SUDO tee /etc/systemd/system/centralized-ssl-renew.timer >/dev/null <<TMR
[Unit]
Description=Daily Centralized SSL renewal check
[Timer]
OnCalendar=*-*-* 03:30:00
Persistent=true
[Install]
WantedBy=timers.target
TMR
        $SUDO systemctl daemon-reload
        $SUDO systemctl enable --now centralized-ssl-renew.timer
        ok "SSL auto-renewal: systemd timer enabled (daily at 03:30)"
    else
        local cron_line
        cron_line="30 3 * * * \"$ssl_dir/renew.sh\" >> \"$INSTALL_DIR/logs/ssl_renew.log\" 2>&1"
        ( crontab -l 2>/dev/null | grep -v 'ssl/renew\.sh'; printf '%s\n' "$cron_line" ) | crontab -
        ok "SSL auto-renewal: cron job added (daily at 03:30)"
    fi
}

# ── Trust SSL certificate in system + browser stores ───────────────────────────────

trust_ssl_cert() {
    local cert="$1"
    [ -f "$cert" ] || return

    # ── 1. System CA store ─────────────────────────────────────────────────
    if [ "$PLATFORM" = "linux" ]; then
        if [ -d /usr/local/share/ca-certificates ]; then
            # Debian / Ubuntu
            $SUDO cp "$cert" /usr/local/share/ca-certificates/centralized-local.crt
            $SUDO update-ca-certificates --fresh >/dev/null 2>&1 && \
                ok "System CA store updated (Debian/Ubuntu)"
        elif [ -d /etc/pki/ca-trust/source/anchors ]; then
            # RHEL / CentOS / Fedora / Rocky
            $SUDO cp "$cert" /etc/pki/ca-trust/source/anchors/centralized-local.crt
            $SUDO update-ca-trust extract >/dev/null 2>&1 && \
                ok "System CA trust store updated (RHEL/Fedora)"
        fi
    fi

    # ── 2. Chrome / Chromium NSS database ──────────────────────────────────────
    # Chrome on Linux reads ~/.pki/nssdb rather than the OS cert store;
    # certutil is the only reliable way to make it trust a self-signed cert.
    if [ "$PLATFORM" = "linux" ] && ! need_cmd certutil; then
        if need_cmd apt-get; then
            log "Installing certutil (libnss3-tools) for Chrome NSS trust"
            $SUDO apt-get install -y -qq libnss3-tools >/dev/null 2>&1 || true
        elif need_cmd dnf; then
            $SUDO dnf install -y -q nss-tools >/dev/null 2>&1 || true
        elif need_cmd yum; then
            $SUDO yum install -y -q nss-tools >/dev/null 2>&1 || true
        fi
    fi

    if need_cmd certutil; then
        # Standard Chrome/Chromium path; also covers Brave, Edge on Linux
        local nss_dirs=("$HOME/.pki/nssdb" "$HOME/.local/share/pki/nssdb")
        local found=false
        # Use an empty password file to avoid interactive prompts
        local nss_pass
        nss_pass="$(mktemp)"
        printf '' > "$nss_pass"
        for nssdb in "${nss_dirs[@]}"; do
            # Create the NSS db if it doesn't exist yet (happens before first Chrome launch)
            if [ ! -d "$nssdb" ]; then
                mkdir -p "$nssdb"
                certutil -d "sql:$nssdb" -N --empty-password >/dev/null 2>&1 || continue
            fi
            # Remove any previous import of this cert, then re-add
            certutil -d "sql:$nssdb" -D -n "Centralized" -f "$nss_pass" >/dev/null 2>&1 || true
            if certutil -d "sql:$nssdb" -A -n "Centralized" -t "CT,," -i "$cert" -f "$nss_pass" >/dev/null 2>&1; then
                ok "Certificate trusted in Chrome NSS db ($nssdb)"
                found=true
            fi
        done
        rm -f "$nss_pass"
        $found || warn "certutil: no NSS db found — open Chrome once, then re-run update.sh"
    else
        warn "certutil not available — Chrome may not trust the cert (restart Chrome after adding cert manually)"
    fi
}

setup_ssl() {
    local ssl_dir="$INSTALL_DIR/ssl"
    mkdir -p "$ssl_dir"
    chmod 700 "$ssl_dir"

    # Skip if a valid certificate already exists (more than 30 days remaining)
    if [ -f "$ssl_dir/cert.pem" ] && [ -f "$ssl_dir/key.pem" ]; then
        if openssl x509 -checkend 2592000 -noout -in "$ssl_dir/cert.pem" >/dev/null 2>&1; then
            ok "SSL certificate valid — $(openssl x509 -enddate -noout -in "$ssl_dir/cert.pem" 2>/dev/null | cut -d= -f2)"
            trust_ssl_cert "$ssl_dir/cert.pem"
            SSL_ENABLED=true; return
        fi
        warn "SSL certificate expiring soon — will regenerate"
    fi

    echo
    log "SSL / TLS Certificate Setup"
    echo "  A TLS certificate enables HTTPS and the PWA desktop install button."
    echo "  • Enter a public domain → Let's Encrypt (requires port 80 open)"
    echo "  • Leave empty           → self-signed   (localhost / internal network)"
    echo
    read -rp "  Domain (Enter for self-signed): " _SSL_DOMAIN

    local mode="selfsigned"
    if [ -n "${_SSL_DOMAIN:-}" ]; then
        _ssl_letsencrypt "$ssl_dir" "$_SSL_DOMAIN" && mode="letsencrypt" || \
            _ssl_selfcert "$ssl_dir" "$_SSL_DOMAIN"
    else
        _ssl_selfcert "$ssl_dir" "localhost"
    fi

    mkdir -p "$INSTALL_DIR/logs"
    _ssl_setup_renewal "$ssl_dir" "$mode" "${_SSL_DOMAIN:-}"
    trust_ssl_cert "$ssl_dir/cert.pem"
    SSL_ENABLED=true
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

    # Allow the app user to restart the service from the web UI without a password
    if [ -d /etc/sudoers.d ]; then
        local systemctl_path
        systemctl_path="$(command -v systemctl 2>/dev/null || echo '/usr/bin/systemctl')"
        # !requiretty lets sudo work from a non-interactive process (web server / script)
        printf 'Defaults:%s !requiretty\n%s ALL=(ALL) NOPASSWD: %s restart centralized\n' \
            "$USER" "$USER" "$systemctl_path" \
            | $SUDO tee /etc/sudoers.d/centralized-restart >/dev/null
        $SUDO chmod 440 /etc/sudoers.d/centralized-restart
        ok "Sudoers rule added — web UI can auto-restart the service"
    fi
}

# ── Open firewall port ─────────────────────────────────────────────────────────────────────────

open_firewall_port() {
    local port="$APP_PORT"
    if [ "$PLATFORM" != "linux" ]; then return; fi

    if need_cmd ufw; then
        if $SUDO ufw status 2>/dev/null | grep -q 'Status: active'; then
            $SUDO ufw allow "$port"/tcp >/dev/null 2>&1
            ok "ufw: allowed TCP $port"
        fi
    elif need_cmd firewall-cmd; then
        if $SUDO firewall-cmd --state 2>/dev/null | grep -q running; then
            $SUDO firewall-cmd --permanent --add-port="$port"/tcp >/dev/null 2>&1
            $SUDO firewall-cmd --reload >/dev/null 2>&1
            ok "firewall-cmd: allowed TCP $port"
        fi
    fi
}

# ── Final summary ─────────────────────────────────────────────────────────────

print_done() {
    local scheme="http"
    [ "${SSL_ENABLED:-false}" = "true" ] && scheme="https"
    echo
    echo "========================================"
    echo "     Centralized — Installation Done"
    echo "========================================"
    echo
    echo "  Install dir : $INSTALL_DIR"
    echo "  App URL     : $scheme://127.0.0.1:$APP_PORT"
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
    if [ "${SSL_ENABLED:-false}" = "true" ]; then
        echo "  NOTE: Self-signed certificate — your browser will show a warning."
        echo "  Add an exception or import ssl/cert.pem into your OS trust store."
        echo
    fi
    echo "  IMPORTANT: Change the default admin password after first login!"
    echo
}

# ── Entry point ───────────────────────────────────────────────────────────────

main() {
    SSL_ENABLED=false
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
    setup_ssl

    if [ "$PLATFORM" = "linux" ]; then
        create_global_command_linux
        create_systemd_service
        open_firewall_port
    else
        create_global_command_macos
    fi

    print_done
}

main "$@"
