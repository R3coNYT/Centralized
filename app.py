from flask import Flask, send_from_directory, make_response
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
    app.register_blueprint(ad_miner_bp)

    # ── PWA routes ───────────────────────────────────────────────────────────
    # Service worker MUST be served from the root scope to control all pages.
    @app.route('/sw.js')
    def pwa_sw():
        resp = make_response(
            send_from_directory(app.static_folder, 'sw.js')
        )
        resp.headers['Content-Type']  = 'application/javascript'
        resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        resp.headers['Service-Worker-Allowed'] = '/'
        return resp

    @app.route('/manifest.json')
    def pwa_manifest():
        resp = make_response(
            send_from_directory(app.static_folder, 'manifest.json')
        )
        resp.headers['Content-Type']  = 'application/manifest+json'
        resp.headers['Cache-Control'] = 'public, max-age=86400'
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
        except Exception:
            css = ""
            glass_enabled = False
        autorecon_installed = bool(
            (os.name == "nt" and os.path.isfile(r"C:\Tools\AutoRecon\AutoRecon.bat")) or
            shutil.which("AutoRecon") or
            shutil.which("autorecon") or
            os.path.isfile("/opt/autorecon/autorecon.py") or
            os.path.isfile(os.path.expanduser("~/Tools/AutoRecon/AutoRecon.py"))
        )
        return {"theme_css": css, "autorecon_installed": autorecon_installed, "glass_enabled": glass_enabled}

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
    application  = create_app()
    _base        = _os.path.dirname(_os.path.abspath(__file__))
    _cert        = _os.path.join(_base, "ssl", "cert.pem")
    _key         = _os.path.join(_base, "ssl", "key.pem")
    _port        = int(_os.environ.get("CENTRALIZED_PORT", 5000))
    _has_ssl     = _os.path.isfile(_cert) and _os.path.isfile(_key)

    if _has_ssl:
        print(f"[Centralized] HTTPS enabled  →  https://0.0.0.0:{_port}")
        # threaded=True lets Werkzeug handle each request in its own thread,
        # avoiding the single-threaded bottleneck of the dev server.
        application.run(host="0.0.0.0", port=_port, debug=False,
                        threaded=True, ssl_context=(_cert, _key))
    else:
        try:
            from waitress import serve
            print(f"[Centralized] Serving via waitress  →  http://0.0.0.0:{_port}")
            serve(application, host="0.0.0.0", port=_port)
        except ImportError:
            application.run(host="0.0.0.0", port=_port, debug=False)
