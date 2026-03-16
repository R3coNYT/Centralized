from flask import Flask
import os
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
    from routes.admin import admin_bp
    from routes.autorecon_results import autorecon_results_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(audits_bp)
    app.register_blueprint(uploads_bp)
    app.register_blueprint(hosts_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(clients_bp)
    app.register_blueprint(cve_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(autorecon_results_bp)

    # Inject theme CSS into every template
    from routes.admin import get_all_settings, build_theme_css

    @app.context_processor
    def inject_theme():
        try:
            css = build_theme_css(get_all_settings())
        except Exception:
            css = ""
        return {"theme_css": css}

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
    """Apply lightweight column migrations for existing databases."""
    from sqlalchemy import text
    with db.engine.connect() as conn:
        for stmt in [
            "ALTER TABLE vulnerabilities ADD COLUMN cve_status VARCHAR(30) NOT NULL DEFAULT 'active'",
            "ALTER TABLE hosts ADD COLUMN tag VARCHAR(100)",
        ]:
            try:
                conn.execute(text(stmt))
                conn.commit()
            except Exception:
                pass  # Column already exists


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
    application = create_app()
    application.run(host="0.0.0.0", port=5000, debug=False)
