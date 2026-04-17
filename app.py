from flask import Flask, send_from_directory, make_response, request
import os
import shutil
from extensions import db, login_manager, csrf


def create_app():
    app = Flask(__name__)
    app.config.from_object("config.Config")

    # Ensure upload folder exists
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    # Init extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in to access this page."
    login_manager.login_message_category = "warning"

    @login_manager.user_loader
    def load_user(user_id):
        from models import User
        return User.query.get(int(user_id))

    # Register blueprints
    from routes.auth import auth_bp
    from routes.dashboard import dashboard_bp
    from routes.audits import audits_bp
    from routes.uploads import uploads_bp
    from routes.hosts import hosts_bp
    from routes.api import api_bp
    from routes.clients import clients_bp
    from routes.cve_search import cve_bp
    from routes.cve_remediation import cve_remediation_bp
    from routes.admin import admin_bp
    from routes.autorecon_results import autorecon_results_bp
    from routes.autorecon_launch import autorecon_launch_bp
    from routes.autorecon_versioning import autorecon_versioning_bp
    from routes.ad_miner import ad_miner_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(audits_bp)
    app.register_blueprint(uploads_bp)
    app.register_blueprint(hosts_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(clients_bp)
    app.register_blueprint(cve_bp)
    app.register_blueprint(cve_remediation_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(autorecon_results_bp)
    app.register_blueprint(autorecon_launch_bp)
    app.register_blueprint(autorecon_versioning_bp)
    app.register_blueprint(ad_miner_bp)

    # ── PWA routes ───────────────────────────────────────────────────────────
    # Service worker MUST be served from the root scope to control all pages.
    @app.route('/sw.js')
    def pwa_sw():
        from models import SiteSettings
        import re as _re
        row = SiteSettings.query.filter_by(key='app_icon').first()
        icon_val = row.value if row and row.value else ''
        _m = _re.search(r'app_icon_(\d+)', icon_val)
        icon_ts = _m.group(1) if _m else '0'
        # Read sw.js and inject icon version into CACHE_NAME so Chrome sees a new SW
        sw_path = os.path.join(app.static_folder, 'sw.js')
        with open(sw_path, 'r', encoding='utf-8') as _f:
            sw_content = _f.read()
        sw_content = sw_content.replace(
            "const STATIC_CACHE = 'centralized-static-v1';",
            f"const STATIC_CACHE = 'centralized-static-icon{icon_ts}';"
        )
        resp = make_response(sw_content)
        resp.headers['Content-Type']  = 'application/javascript'
        resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        resp.headers['Service-Worker-Allowed'] = '/'
        return resp

    @app.route('/manifest.json')
    def pwa_manifest():
        import json as _json
        from models import SiteSettings
        row = SiteSettings.query.filter_by(key='app_icon').first()
        icon_url = f"/static/img/{row.value}" if row and row.value else None
        icon_img  = icon_url or '/static/img/icon-192.png'
        icons = [
            {"src": icon_img, "sizes": "192x192", "type": "image/png", "purpose": "any maskable"},
            {"src": icon_img, "sizes": "512x512", "type": "image/png", "purpose": "any maskable"},
        ]
        if not icon_url:
            icons.append({"src": "/static/img/icon.svg", "sizes": "any", "type": "image/svg+xml", "purpose": "any"})
        manifest = {
            "name": "Centralized",
            "short_name": "Centralized",
            "description": "Security audit & vulnerability management platform",
            "start_url": "/",
            "scope": "/",
            "display": "standalone",
            "orientation": "any",
            "theme_color": "#0f1117",
            "background_color": "#0f1117",
            "lang": "en",
            "categories": ["security", "productivity", "utilities"],
            "icons": icons,
            "shortcuts": [
                {"name": "Dashboard", "short_name": "Dashboard", "url": "/",         "icons": [{"src": icon_img, "sizes": "192x192"}]},
                {"name": "Audits",    "short_name": "Audits",    "url": "/audits/",  "icons": [{"src": icon_img, "sizes": "192x192"}]},
                {"name": "CVE Search","short_name": "CVEs",      "url": "/cve/",     "icons": [{"src": icon_img, "sizes": "192x192"}]},
            ],
            "screenshots": [],
            "prefer_related_applications": False,
        }
        resp = make_response(_json.dumps(manifest))
        resp.headers['Content-Type']  = 'application/manifest+json'
        resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        return resp

    @app.route('/ssl/cert.pem')
    def pwa_ssl_cert():
        """Serve the self-signed CA cert so users can install it as a trusted root."""
        import os as _os
        cert_path = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), 'ssl', 'cert.pem')
        if not _os.path.isfile(cert_path):
            return '', 404
        resp = make_response(send_from_directory(
            _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), 'ssl'),
            'cert.pem'
        ))
        # application/x-x509-ca-cert prompts "install certificate" in most browsers/OS
        resp.headers['Content-Type']        = 'application/x-x509-ca-cert'
        resp.headers['Content-Disposition'] = 'attachment; filename="centralized-ca.crt"'
        resp.headers['Cache-Control']       = 'no-store'
        return resp

    @app.route('/ssl/trust.ps1')
    def pwa_trust_ps1():
        """Serve a PowerShell script that imports the CA cert into Windows Trusted Root."""
        import os as _os
        cert_path = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), 'ssl', 'cert.pem')
        if not _os.path.isfile(cert_path):
            return '', 404
        base_url = request.host_url.rstrip('/')
        script = f"""# Centralized — Trust SSL certificate
# Run this script as Administrator in PowerShell

$CertUrl = "{base_url}/ssl/cert.pem"

Write-Host "[*] Downloading certificate from $CertUrl ..."
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {{ $true }}
try {{
    $pem = (New-Object System.Net.WebClient).DownloadString($CertUrl)
}} finally {{
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
}}

$b64   = ($pem -replace '-----BEGIN CERTIFICATE-----', '' `
               -replace '-----END CERTIFICATE-----', '' `
               -replace '\\s', '')
$bytes = [Convert]::FromBase64String($b64)
$tmp   = Join-Path $env:TEMP 'centralized-ca.cer'
[System.IO.File]::WriteAllBytes($tmp, $bytes)

Write-Host "[*] Importing into Windows Trusted Root CA store ..."
try {{
    $cert = Import-Certificate -FilePath $tmp -CertStoreLocation Cert:\\LocalMachine\\Root -ErrorAction Stop
    Write-Host "[+] Certificate trusted (thumbprint: $($cert.Thumbprint.Substring(0,8))...)"
}} catch {{
    Write-Error "[-] Import failed: $_"
    Write-Host "    Manual fix: double-click centralized-ca.cer -> Install -> Trusted Root Certification Authorities"
}} finally {{
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
}}

Write-Host "[*] Done. Please restart Chrome / Edge."
Read-Host  "Press Enter to close"
"""
        resp = make_response(script)
        resp.headers['Content-Type']        = 'text/plain; charset=utf-8'
        resp.headers['Content-Disposition'] = 'attachment; filename="trust-centralized.ps1"'
        resp.headers['Cache-Control']       = 'no-store'
        return resp

    @app.route('/ssl/trust.sh')
    def pwa_trust_sh():
        """Serve a bash script that imports the CA cert into Linux system/Chrome NSS stores."""
        import os as _os
        cert_path = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), 'ssl', 'cert.pem')
        if not _os.path.isfile(cert_path):
            return '', 404
        base_url = request.host_url.rstrip('/')
        script = f"""#!/usr/bin/env bash
# Centralized — Trust SSL certificate
set -e

CERT_URL="{base_url}/ssl/cert.pem"
CERT="/tmp/centralized-ca.crt"

echo "[*] Downloading certificate ..."
curl -sk "$CERT_URL" -o "$CERT"

# ── System CA store ────────────────────────────────────────────────────────
if [ -d /usr/local/share/ca-certificates ]; then
    echo "[*] Installing into system CA store (Debian/Ubuntu) ..."
    sudo cp "$CERT" /usr/local/share/ca-certificates/centralized-local.crt
    sudo update-ca-certificates
elif [ -d /etc/pki/ca-trust/source/anchors ]; then
    echo "[*] Installing into system CA store (RHEL/Fedora) ..."
    sudo cp "$CERT" /etc/pki/ca-trust/source/anchors/centralized-local.crt
    sudo update-ca-trust
else
    echo "[!] Unknown distro — skipping system CA store"
fi

# ── Chrome NSS database ────────────────────────────────────────────────────
if ! command -v certutil &>/dev/null; then
    echo "[*] Installing libnss3-tools ..."
    if command -v apt-get &>/dev/null; then
        sudo apt-get install -y -q libnss3-tools
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y nss-tools
    elif command -v yum &>/dev/null; then
        sudo yum install -y nss-tools
    fi
fi

if command -v certutil &>/dev/null; then
    PASS="$(mktemp)"
    printf '' > "$PASS"
    for nssdb in "$HOME/.pki/nssdb" "$HOME/.local/share/pki/nssdb"; do
        if [ ! -d "$nssdb" ]; then
            echo "[*] Creating NSS db at $nssdb ..."
            mkdir -p "$nssdb"
            certutil -N -d "sql:$nssdb" --empty-password 2>/dev/null || true
        fi
        echo "[*] Importing into $nssdb ..."
        certutil -d "sql:$nssdb" -D -n "Centralized" -f "$PASS" 2>/dev/null || true
        certutil -d "sql:$nssdb" -A -n "Centralized" -t "CT,," -i "$CERT" -f "$PASS"
    done
    rm -f "$PASS"
    echo "[+] Certificate trusted in Chrome NSS db"
fi

rm -f "$CERT"
echo "[*] Done. Please restart Chrome."
"""
        resp = make_response(script)
        resp.headers['Content-Type']        = 'text/plain; charset=utf-8'
        resp.headers['Content-Disposition'] = 'attachment; filename="trust-centralized.sh"'
        resp.headers['Cache-Control']       = 'no-store'
        return resp
    # ────────────────────────────────────────────────────────────────────────

    # Inject theme CSS and tool availability into every template
    from routes.admin import get_all_settings, build_theme_css

    # Custom Jinja2 filters
    import json as _json
    @app.template_filter("from_json")
    def from_json_filter(value):
        try:
            return _json.loads(value) if value else []
        except Exception:
            return []

    @app.context_processor
    def inject_globals():
        try:
            _settings = get_all_settings()
            css = build_theme_css(_settings)
            glass_enabled = _settings.get("glassmorphic") == "1"
            _app_icon = _settings.get("app_icon", "")
            _icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "img", _app_icon)
            app_icon_url = f"/static/img/{_app_icon}" if _app_icon and os.path.isfile(_icon_path) else ""
            # Extract timestamp from filename e.g. app_icon_1744032123.png → "1744032123"
            import re as _re
            _m = _re.search(r'app_icon_(\d+)', _app_icon)
            app_icon_version = _m.group(1) if _m else "0"
        except Exception:
            css = ""
            glass_enabled = False
            app_icon_url = ""
            app_icon_version = "0"
        autorecon_installed = bool(
            (os.name == "nt" and os.path.isfile(r"C:\Tools\AutoRecon\AutoRecon.bat")) or
            shutil.which("AutoRecon") or
            shutil.which("autorecon") or
            os.path.isfile("/opt/autorecon/autorecon.py") or
            os.path.isfile(os.path.expanduser("~/Tools/AutoRecon/AutoRecon.py"))
        )
        return {"theme_css": css, "autorecon_installed": autorecon_installed, "glass_enabled": glass_enabled, "app_icon_url": app_icon_url, "app_icon_version": app_icon_version}

    # Import models here so SQLAlchemy sees them before create_all()
    import models  # noqa: F401

    # Create tables and default admin if needed
    with app.app_context():
        db.create_all()
        _migrate_db()
        _migrate_uploads()
        _seed_admin()

    return app


def _migrate_uploads():
    """
    One-time migration: move flat uploaded files (stored_filename = 'uuid_name.ext')
    into the new client/audit sub-directory structure.
    """
    import re
    import shutil
    from models import UploadedFile, Audit

    upload_root = os.path.join(os.path.abspath(os.path.dirname(__file__)), "uploads")

    def slugify(text):
        text = text.strip().lower()
        text = re.sub(r"[^\w\s-]", "", text)
        text = re.sub(r"[\s_-]+", "_", text)
        return text[:60] or "unknown"

    files = UploadedFile.query.all()
    for uf in files:
        # Already migrated if stored_filename contains a directory separator
        if os.sep in uf.stored_filename or "/" in uf.stored_filename:
            continue

        audit = Audit.query.get(uf.audit_id)
        if not audit:
            continue

        client_slug = slugify(audit.client.name) if audit.client else "_no_client"
        audit_slug = f"{slugify(audit.name)}_{audit.id}"
        new_dir = os.path.join(upload_root, client_slug, audit_slug)
        os.makedirs(new_dir, exist_ok=True)

        old_path = os.path.join(upload_root, uf.stored_filename)
        new_relative = os.path.join(client_slug, audit_slug, uf.stored_filename)
        new_path = os.path.join(upload_root, new_relative)

        if os.path.exists(old_path) and not os.path.exists(new_path):
            shutil.move(old_path, new_path)

        uf.stored_filename = new_relative

    db.session.commit()


def _migrate_db():
    """
    Auto-detect and apply any schema changes to the existing database.
    - New tables  : handled by db.create_all() above
    - New columns : detected via SQLAlchemy inspect(), added with ALTER TABLE
    - Removed cols: intentionally ignored (SQLite limitation + data safety)
    """
    from sqlalchemy import inspect as sa_inspect, text

    inspector = sa_inspect(db.engine)
    added = []

    with db.engine.connect() as conn:
        for table in db.metadata.sorted_tables:
            if not inspector.has_table(table.name):
                continue  # new tables are created by create_all()

            existing = {col["name"] for col in inspector.get_columns(table.name)}

            for col in table.columns:
                if col.name in existing:
                    continue

                col_type = col.type.compile(dialect=db.engine.dialect)

                # Build DEFAULT clause (required when adding NOT NULL columns to filled tables)
                default_clause = ""
                if col.default is not None and col.default.is_scalar:
                    val = col.default.arg
                    if isinstance(val, str):
                        default_clause = f" DEFAULT '{val}'"
                    elif isinstance(val, bool):
                        default_clause = f" DEFAULT {1 if val else 0}"
                    elif val is not None:
                        default_clause = f" DEFAULT {val}"
                elif not col.nullable:
                    # NOT NULL with no explicit default — pick a safe fallback
                    ct = col_type.upper()
                    if any(t in ct for t in ("INT", "REAL", "NUMERIC", "FLOAT")):
                        default_clause = " DEFAULT 0"
                    else:
                        default_clause = " DEFAULT ''"

                nullable_clause = "" if col.nullable else " NOT NULL"
                stmt = (
                    f"ALTER TABLE {table.name} ADD COLUMN "
                    f"{col.name} {col_type}{nullable_clause}{default_clause}"
                )
                try:
                    conn.execute(text(stmt))
                    conn.commit()
                    added.append(f"{table.name}.{col.name}")
                except Exception:
                    pass  # column already exists or type not supported

    if added:
        print(f"  Schema updated — added {len(added)} column(s): {', '.join(added)}")


def _seed_admin():
    """Create default admin user if no users exist."""
    from models import User
    if User.query.count() == 0:
        from werkzeug.security import generate_password_hash
        admin = User(
            username="admin",
            email="admin@centralized.local",
            password_hash=generate_password_hash("admin"),
            role="admin",
        )
        db.session.add(admin)
        db.session.commit()


if __name__ == "__main__":
    import os as _os
    import threading as _threading
    from wsgiref.simple_server import make_server as _make_server, WSGIRequestHandler as _WSGIRequestHandler
    application  = create_app()
    _base        = _os.path.dirname(_os.path.abspath(__file__))
    _cert        = _os.path.join(_base, "ssl", "cert.pem")
    _key         = _os.path.join(_base, "ssl", "key.pem")
    _http_port   = int(_os.environ.get("CENTRALIZED_HTTP_PORT", 80))
    _port        = int(_os.environ.get("CENTRALIZED_PORT", 5000))
    _has_ssl     = _os.path.isfile(_cert) and _os.path.isfile(_key)

    if _has_ssl:
        def _redirect_app(environ, start_response):
            host = (environ.get("HTTP_HOST") or "localhost").split(":")[0]
            target = f"https://{host}:{_port}{environ.get('PATH_INFO', '/')}"
            qs = environ.get("QUERY_STRING", "")
            if qs:
                target += "?" + qs
            start_response("301 Moved Permanently", [("Location", target), ("Content-Length", "0")])
            return [b""]

        class _SilentHandler(_WSGIRequestHandler):
            def log_message(self, *args):
                pass

        try:
            _redirect_srv = _make_server("0.0.0.0", _http_port, _redirect_app, handler_class=_SilentHandler)
            _t = _threading.Thread(target=_redirect_srv.serve_forever, daemon=True)
            _t.start()
            print(f"[Centralized] HTTP→HTTPS redirect  →  http://0.0.0.0:{_http_port}")
        except OSError as _e:
            print(f"[Centralized] Could not bind port {_http_port} for redirect ({_e})")

        print(f"[Centralized] HTTPS enabled  →  https://0.0.0.0:{_port}")
        application.run(host="0.0.0.0", port=_port, debug=False,
                        threaded=True, ssl_context=(_cert, _key))
    else:
        try:
            from waitress import serve
            print(f"[Centralized] Serving via waitress  →  http://0.0.0.0:{_port}")
            serve(application, host="0.0.0.0", port=_port)
        except ImportError:
            application.run(host="0.0.0.0", port=_port, debug=False)
