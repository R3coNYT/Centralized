import os
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-in-production-use-random-32bytes")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'centralized.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
    MAX_CONTENT_LENGTH = 64 * 1024 * 1024  # 64 MB
    ALLOWED_EXTENSIONS = {"xml", "json", "pdf"}

    # NVD API
    NVD_API_KEY = os.environ.get("NVD_API_KEY", "")  # optional – raises rate limit
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_RATE_LIMIT_DELAY = 0.7  # seconds between NVD requests (without key: ~6 req/30s)

    # Session
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # WTF / CSRF
    WTF_CSRF_ENABLED = True
