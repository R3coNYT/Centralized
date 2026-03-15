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

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(audits_bp)
    app.register_blueprint(uploads_bp)
    app.register_blueprint(hosts_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(clients_bp)
    app.register_blueprint(cve_bp)

    # Import models here so SQLAlchemy sees them before create_all()
    import models  # noqa: F401

    # Create tables and default admin if needed
    with app.app_context():
        db.create_all()
        _seed_admin()

    return app


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
    application.run(host="127.0.0.1", port=5000, debug=False)
