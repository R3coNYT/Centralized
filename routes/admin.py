import json
import os
import re
import subprocess
import urllib.error
import urllib.request

from flask import Blueprint, jsonify, redirect, render_template, request, url_for, flash
from flask_login import current_user, login_required

from extensions import db
from models import SiteSettings, CveSource

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HEX_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")

SETTING_KEYS = ["accent_color", "sidebar_bg", "bg_card", "bg_surface", "glass_blob1", "glass_blob2"]

DEFAULT_SETTINGS = {
    "accent_color": "#0d6efd",
    "sidebar_bg":   "#0f1117",
    "bg_card":      "#1a1d23",
    "bg_surface":   "#13161b",
    "glass_blob1":  "#8c28e6",
    "glass_blob2":  "#00bea2",
}

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

GITHUB_REPO = "R3coNYT/Centralized"
GITHUB_TOKEN_FILE = os.path.join(BASE_DIR, "github_token.txt")


def _get_github_token() -> str:
    """Read the user-supplied GitHub PAT from github_token.txt (if present)."""
    try:
        with open(GITHUB_TOKEN_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()
    except FileNotFoundError:
        return ""
    except Exception:
        return ""


def _github_headers() -> dict:
    """Return GitHub API headers, adding Authorization if a token is configured."""
    headers = {
        "Accept":     "application/vnd.github.v3+json",
        "User-Agent": "Centralized-App/1.0",
    }
    token = _get_github_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_all_settings() -> dict:
    """Return merged {key: value} dict (DB values override defaults)."""
    result = dict(DEFAULT_SETTINGS)
    try:
        for row in SiteSettings.query.all():
            result[row.key] = row.value
    except Exception:
        pass
    return result


def build_theme_css(settings: dict) -> str:
    """
    Generate a <style> block content that overrides CSS variables and targeted
    selectors based on the stored settings.  Colors are re-validated here so
    that only safe #RRGGBB values are ever emitted.
    """
    parts: list[str] = []
    root_vars: dict[str, str] = {}

    accent = settings.get("accent_color", "")
    if HEX_COLOR_RE.match(accent):
        h = accent.lstrip("#")
        r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
        root_vars["--bs-primary"] = accent
        root_vars["--bs-primary-rgb"] = f"{r},{g},{b}"
        root_vars["--bs-link-color"] = accent
        root_vars["--bs-link-color-rgb"] = f"{r},{g},{b}"

    for css_var, key in [("--bg-card", "bg_card"), ("--bg-surface", "bg_surface")]:
        val = settings.get(key, "")
        if HEX_COLOR_RE.match(val):
            root_vars[css_var] = val

    # RGB variants for glassmorphic CSS (rgba(var(--xx-rgb), alpha) pattern)
    for css_var_rgb, key in [
        ("--bg-card-rgb",     "bg_card"),
        ("--bg-surface-rgb",  "bg_surface"),
        ("--sidebar-bg-rgb",  "sidebar_bg"),
        ("--glass-blob1-rgb", "glass_blob1"),
        ("--glass-blob2-rgb", "glass_blob2"),
    ]:
        val = settings.get(key, "")
        if HEX_COLOR_RE.match(val):
            h2 = val.lstrip("#")
            r2, g2, b2 = int(h2[0:2], 16), int(h2[2:4], 16), int(h2[4:6], 16)
            root_vars[css_var_rgb] = f"{r2},{g2},{b2}"

    if root_vars:
        decls = "".join(f"{k}:{v};" for k, v in root_vars.items())
        parts.append(f":root{{{decls}}}")

    sidebar_bg = settings.get("sidebar_bg", "")
    if HEX_COLOR_RE.match(sidebar_bg):
        parts.append(
            f".sidebar{{background-color:{sidebar_bg}!important}}"
            f".topbar{{background-color:{sidebar_bg}!important}}"
        )

    if HEX_COLOR_RE.match(accent):
        h = accent.lstrip("#")
        r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
        parts.append(
            f".sidebar .nav-link.active{{"
            f"background-color:rgba({r},{g},{b},0.25)!important;"
            f"color:{accent}!important}}"
        )
        parts.append(f".sidebar-brand i{{color:{accent}!important}}")
        parts.append(
            f".avatar-circle{{background:linear-gradient(135deg,{accent},{accent})!important}}"
        )
        parts.append(
            f".btn-primary{{background-color:{accent}!important;"
            f"border-color:{accent}!important}}"
        )

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Interface routes
# ---------------------------------------------------------------------------

@admin_bp.route("/interface", methods=["GET", "POST"])
@login_required
def interface():
    if current_user.role != "admin":
        flash("Access denied.", "danger")
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        for key in SETTING_KEYS:
            value = request.form.get(key, "").strip()
            if not value:
                continue
            if not HEX_COLOR_RE.match(value):
                flash(f"Invalid color value for {key}.", "danger")
                return redirect(url_for("admin.interface"))
            row = SiteSettings.query.filter_by(key=key).first()
            if row:
                row.value = value
            else:
                db.session.add(SiteSettings(key=key, value=value))
        db.session.commit()
        flash("Interface settings saved successfully.", "success")
        return redirect(url_for("admin.interface"))

    settings = get_all_settings()
    return render_template(
        "admin/interface.html",
        settings=settings,
        defaults=DEFAULT_SETTINGS,
        github_token_active=bool(_get_github_token()),
    )


@admin_bp.route("/interface/reset", methods=["POST"])
@login_required
def interface_reset():
    if current_user.role != "admin":
        flash("Access denied.", "danger")
        return redirect(url_for("dashboard.index"))
    SiteSettings.query.delete()
    db.session.commit()
    flash("Interface settings reset to defaults.", "info")
    return redirect(url_for("admin.interface"))


@admin_bp.route("/interface/glassmorphic", methods=["POST"])
@login_required
def toggle_glassmorphic():
    if current_user.role != "admin":
        return jsonify({"error": "Access denied"}), 403
    row = SiteSettings.query.filter_by(key="glassmorphic").first()
    current_val = row.value if row else "0"
    new_val = "0" if current_val == "1" else "1"
    if row:
        row.value = new_val
    else:
        db.session.add(SiteSettings(key="glassmorphic", value=new_val))
    db.session.commit()
    return jsonify({"enabled": new_val == "1"})


def _ensure_nvd_source():
    """Make sure the built-in NVD source row exists, and re-detect drivers for generic rows."""
    if not CveSource.query.filter_by(is_builtin=True).first():
        db.session.add(CveSource(
            url="https://nvd.nist.gov",
            label="NVD \u2014 National Vulnerability Database",
            driver="nvd",
            enabled=True,
            is_builtin=True,
        ))
        db.session.commit()

    # Re-classify any row whose driver is still "generic" now that more drivers are known
    import urllib.parse as _up
    changed = False
    for src in CveSource.query.filter_by(driver="generic").all():
        host = _up.urlparse(src.url if "://" in src.url else "https://" + src.url).hostname or ""
        for pattern, (driver, label) in _KNOWN_DRIVERS.items():
            if pattern in host and driver != "generic":
                src.driver = driver
                if not src.label or src.label == host:
                    src.label = label
                changed = True
                break
    if changed:
        db.session.commit()


@admin_bp.route("/settings", methods=["GET"])
@login_required
def settings():
    if current_user.role != "admin":
        flash("Access denied.", "danger")
        return redirect(url_for("dashboard.index"))
    _ensure_nvd_source()
    cve_sources = CveSource.query.order_by(CveSource.is_builtin.desc(), CveSource.id).all()
    return render_template(
        "admin/settings.html",
        github_token_active=bool(_get_github_token()),
        cve_sources=cve_sources,
    )


# ── CVE Sources CRUD ────────────────────────────────────────────────────────

_KNOWN_DRIVERS = {
    "nvd.nist.gov":           ("nvd",        "NVD \u2014 National Vulnerability Database"),
    "cve.circl.lu":           ("circl",       "CIRCL CVE Search"),
    "vulnerability.circl.lu": ("circl",       "CIRCL CVE Search"),
    "circl.lu":               ("circl",       "CIRCL CVE Search"),
    "cve.org":                ("mitre",       "MITRE CVE Program"),
    "cveawg.mitre.org":       ("mitre",       "MITRE CVE Program"),
    "api.first.org":          ("epss",        "FIRST EPSS"),
    "first.org":              ("epss",        "FIRST EPSS"),
    "osv.dev":                ("osv",         "OSV \u2014 Open Source Vulnerabilities"),
    "api.osv.dev":            ("osv",         "OSV \u2014 Open Source Vulnerabilities"),
    "euvd.enisa.europa.eu":   ("euvd",        "ENISA EUVD \u2014 European Vulnerability Database"),
    "enisa.europa.eu":        ("euvd",        "ENISA EUVD \u2014 European Vulnerability Database"),
    "cvedetails.com":         ("cvedetails",  "CVE Details"),
    "tenable.com":            ("tenable",     "Tenable Research"),
    "wiz.io":                 ("wiz",         "Wiz Vulnerability Database"),
    "vuldb.com":              ("vuldb",       "VulDB"),
    "cvefind.com":            ("cvefind",     "CVEFind"),
}
}


def _auto_detect_source(url: str) -> tuple[str, str]:
    """Return (driver, label) guessed from URL."""
    import urllib.parse
    host = urllib.parse.urlparse(url if "://" in url else "https://" + url).hostname or ""
    for pattern, (driver, label) in _KNOWN_DRIVERS.items():
        if pattern in host:
            return driver, label
    return "generic", host


@admin_bp.route("/cve-sources", methods=["GET"])
@login_required
def list_cve_sources():
    if current_user.role != "admin":
        return jsonify({"error": "Access denied"}), 403
    _ensure_nvd_source()
    sources = CveSource.query.order_by(CveSource.is_builtin.desc(), CveSource.id).all()
    return jsonify([s.to_dict() for s in sources])


@admin_bp.route("/cve-sources", methods=["POST"])
@login_required
def add_cve_source():
    if current_user.role != "admin":
        return jsonify({"error": "Access denied"}), 403
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip().rstrip("/")
    if not url:
        return jsonify({"error": "URL is required"}), 400
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    if CveSource.query.filter_by(url=url).first():
        return jsonify({"error": "This source already exists"}), 409
    driver, label = _auto_detect_source(url)
    custom_label = (data.get("label") or "").strip()
    src = CveSource(
        url=url,
        label=custom_label or label,
        driver=driver,
        enabled=True,
        is_builtin=False,
    )
    db.session.add(src)
    db.session.commit()
    return jsonify(src.to_dict()), 201


@admin_bp.route("/cve-sources/<int:source_id>", methods=["PATCH"])
@login_required
def toggle_cve_source(source_id):
    if current_user.role != "admin":
        return jsonify({"error": "Access denied"}), 403
    src = db.session.get(CveSource, source_id)
    if not src:
        return jsonify({"error": "Not found"}), 404
    if src.is_builtin:
        return jsonify({"error": "Built-in source cannot be disabled"}), 400
    src.enabled = not src.enabled
    db.session.commit()
    return jsonify(src.to_dict())


@admin_bp.route("/cve-sources/<int:source_id>", methods=["DELETE"])
@login_required
def delete_cve_source(source_id):
    if current_user.role != "admin":
        return jsonify({"error": "Access denied"}), 403
    src = db.session.get(CveSource, source_id)
    if not src:
        return jsonify({"error": "Not found"}), 404
    if src.is_builtin:
        return jsonify({"error": "Built-in source cannot be deleted"}), 400
    db.session.delete(src)
    db.session.commit()
    return jsonify({"ok": True})


@admin_bp.route("/github-token", methods=["GET"])
@login_required
def get_github_token():
    """Return the stored GitHub token (admin only)."""
    if current_user.role != "admin":
        return jsonify({"error": "Access denied"}), 403
    token = _get_github_token()
    return jsonify({"token": token or "", "active": bool(token)})


@admin_bp.route("/github-token", methods=["POST"])
@login_required
def save_github_token():
    """Save (or clear) the GitHub Personal Access Token used for API calls."""
    if current_user.role != "admin":
        return jsonify({"error": "Access denied"}), 403

    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()

    # Validate: GitHub PATs are alphanumeric + underscores, 20-255 chars
    # Allow empty string to clear the token
    if token and not re.match(r'^[A-Za-z0-9_\-]{20,255}$', token):
        return jsonify({"error": "Invalid token format."}), 400

    try:
        if token:
            with open(GITHUB_TOKEN_FILE, "w", encoding="utf-8") as f:
                f.write(token)
        else:
            # Clear: delete the file
            if os.path.exists(GITHUB_TOKEN_FILE):
                os.remove(GITHUB_TOKEN_FILE)
        # Invalidate cached GitHub results so next call uses new credentials
        _update_cache.clear()
        _GITHUB_COMMIT_CACHE.clear()
        _VERSIONS_CACHE.clear()
        return jsonify({"ok": True, "active": bool(token)})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@admin_bp.route("/github-token/test")
@login_required
def test_github_token():
    """Test the configured GitHub token and return rate-limit info."""
    if current_user.role != "admin":
        return jsonify({"error": "Access denied"}), 403
    try:
        req = urllib.request.Request(
            "https://api.github.com/rate_limit",
            headers=_github_headers(),
        )
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read())
        core = data.get("rate") or data.get("resources", {}).get("core", {})
        limit     = core.get("limit", 0)
        remaining = core.get("remaining", 0)
        reset_ts  = core.get("reset", 0)
        import datetime
        reset_dt = datetime.datetime.fromtimestamp(reset_ts).strftime("%H:%M:%S") if reset_ts else "?"
        authenticated = limit >= 5000
        return jsonify({
            "ok":            True,
            "authenticated": authenticated,
            "limit":         limit,
            "remaining":     remaining,
            "reset":         reset_dt,
        })
    except urllib.error.HTTPError as exc:
        return jsonify({"error": f"GitHub API error {exc.code}: {exc.reason}"}), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 200


# ---------------------------------------------------------------------------
# Update routes
# ---------------------------------------------------------------------------

import time as _time

_update_cache: dict = {}   # {"ts": float, "available": bool}
_UPDATE_CACHE_TTL = 300     # seconds (5 minutes)


def _check_update_available() -> bool:
    """Return True if a newer commit exists on GitHub. Result is cached for 5 min."""
    now = _time.monotonic()
    if _update_cache.get("ts") and now - _update_cache["ts"] < _UPDATE_CACHE_TTL:
        return _update_cache["available"]
    current, _ = _get_local_commit()
    latest, _, _ = _get_github_latest_commit()
    available = bool(latest and current and current != latest)
    _update_cache["ts"] = now
    _update_cache["available"] = available
    return available


@admin_bp.route("/update-status")
@login_required
def update_status():
    """Lightweight JSON endpoint used by the sidebar to poll update availability."""
    if current_user.role != "admin":
        return jsonify({"available": False})
    return jsonify({"available": _check_update_available()})


@admin_bp.route("/update")
@login_required
def update_page():
    if current_user.role != "admin":
        flash("Access denied.", "danger")
        return redirect(url_for("dashboard.index"))

    current_hash, current_short = _get_local_commit()
    latest_hash, latest_short, latest_message = _get_github_latest_commit()

    is_outdated = bool(latest_hash and current_hash and current_hash != latest_hash)
    up_to_date  = bool(latest_hash and current_hash and current_hash == latest_hash)

    import platform as _platform
    return render_template(
        "admin/update.html",
        current_hash=current_hash,
        current_short=current_short,
        latest_hash=latest_hash,
        latest_short=latest_short,
        latest_message=latest_message,
        is_outdated=is_outdated,
        up_to_date=up_to_date,
        is_windows=(_platform.system() == "Windows"),
    )


@admin_bp.route("/update/run", methods=["POST"])
@login_required
def run_update():
    import platform
    if current_user.role != "admin":
        return jsonify({"error": "Access denied"}), 403

    # Strip ANSI escape sequences from terminal output
    _ansi = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

    if platform.system() == "Windows":
        script = os.path.join(BASE_DIR, "update.ps1")
        if not os.path.exists(script):
            return jsonify({"error": "update.ps1 not found in the application directory."}), 404
        cmd = [
            "powershell.exe",
            "-NonInteractive",
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", script,
        ]
    else:
        script = os.path.join(BASE_DIR, "update.sh")
        if not os.path.exists(script):
            return jsonify({"error": "update.sh not found in the application directory."}), 404
        cmd = ["bash", script]

    try:
        result = subprocess.run(
            cmd,
            cwd=BASE_DIR,
            capture_output=True,
            text=True,
            timeout=300,
            encoding="utf-8",
            errors="replace",
        )
        stdout = _ansi.sub("", result.stdout or "")
        stderr = _ansi.sub("", result.stderr or "")

        auto_restarting = False
        if result.returncode == 0 and platform.system() != "Windows":
            # Attempt to restart the systemd service automatically.
            # This works only when the sudoers rule installed by Centralized.sh is present.
            import shutil as _shutil
            if _shutil.which("systemctl"):
                import threading
                def _restart_service():
                    import time as _time
                    _time.sleep(2)  # give the response time to reach the browser
                    subprocess.run(
                        ["sudo", "systemctl", "restart", "centralized"],
                        capture_output=True,
                        timeout=30,
                    )
                t = threading.Thread(target=_restart_service, daemon=True)
                t.start()
                auto_restarting = True

        return jsonify({
            "returncode": result.returncode,
            "stdout": stdout[-3000:],
            "stderr": stderr[-1000:],
            "restart_required": result.returncode == 0,
            "auto_restarting": auto_restarting,
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Update timed out after 300 seconds."}), 500
    except FileNotFoundError as exc:
        return jsonify({"error": f"Interpreter not found: {exc}"}), 500
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ---------------------------------------------------------------------------
# Version history routes
# ---------------------------------------------------------------------------

_VERSIONS_CACHE: dict = {}
_VERSIONS_CACHE_TTL = 1800  # 30 minutes


@admin_bp.route("/versions")
@login_required
def get_versions():
    """Return a list of merge-commit versions from GitHub, cached for 10 min."""
    if current_user.role != "admin":
        return jsonify({"error": "Access denied"}), 403

    now = _time.monotonic()
    if _VERSIONS_CACHE.get("ts") and now - _VERSIONS_CACHE["ts"] < _VERSIONS_CACHE_TTL:
        return jsonify(_VERSIONS_CACHE["data"])

    commits = []
    rate_limited = False
    try:
        page = 1
        while len(commits) < 200:
            req = urllib.request.Request(
                f"https://api.github.com/repos/{GITHUB_REPO}/commits?sha=main&per_page=100&page={page}",
                headers=_github_headers(),
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
            if not data:
                break
            for commit in data:
                msg = (commit.get("commit", {}).get("message") or "").strip()
                first_line = msg.split("\n")[0]
                m = re.search(r"Merge pull request #(\d+)", first_line)
                if not m:
                    continue
                pr_num = int(m.group(1))
                sha = commit.get("sha") or ""
                date_str = (commit.get("commit", {}).get("author", {}).get("date") or "")[:10]
                # PR title is on the second non-empty line of the merge commit message
                non_empty = [l.strip() for l in msg.split("\n") if l.strip()]
                title = non_empty[1] if len(non_empty) > 1 else first_line
                commits.append({
                    "sha": sha,
                    "short": sha[:7] if sha else "",
                    "pr": pr_num,
                    "title": title,
                    "date": date_str,
                    "installable": pr_num >= 90,
                })
            if len(data) < 100:
                break
            page += 1
    except urllib.error.HTTPError as exc:
        if exc.code in (403, 429):
            rate_limited = True
        else:
            # Return stale cache on any HTTP error if available
            if _VERSIONS_CACHE.get("data"):
                return jsonify(_VERSIONS_CACHE["data"])
            return jsonify({"error": f"GitHub API error: {exc.code} {exc.reason}"})
    except Exception as exc:
        if _VERSIONS_CACHE.get("data"):
            return jsonify(_VERSIONS_CACHE["data"])
        return jsonify({"error": str(exc)})

    if rate_limited:
        # Return stale cache if we have it; otherwise friendly message
        if _VERSIONS_CACHE.get("data"):
            return jsonify(_VERSIONS_CACHE["data"])
        return jsonify({"error": "GitHub API rate limit exceeded — please wait a few minutes and refresh."})

    result = {"commits": commits}
    _VERSIONS_CACHE["ts"] = now
    _VERSIONS_CACHE["data"] = result
    return jsonify(result)


@admin_bp.route("/rollback", methods=["POST"])
@login_required
def run_rollback():
    """Install a specific commit SHA via rollback.ps1 / rollback.sh."""
    import platform
    if current_user.role != "admin":
        return jsonify({"error": "Access denied"}), 403

    data = request.get_json(silent=True) or {}
    commit = (data.get("commit") or "").strip()

    # Validate: only hex chars, 7-40 length — prevents any command injection
    if not re.match(r'^[0-9a-fA-F]{7,40}$', commit):
        return jsonify({"error": "Invalid commit SHA."}), 400

    _ansi = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

    if platform.system() == "Windows":
        script = os.path.join(BASE_DIR, "rollback.ps1")
        if not os.path.exists(script):
            return jsonify({"error": "rollback.ps1 not found in the application directory."}), 404
        cmd = [
            "powershell.exe",
            "-NonInteractive",
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", script,
            "-Commit", commit,
        ]
    else:
        script = os.path.join(BASE_DIR, "rollback.sh")
        if not os.path.exists(script):
            return jsonify({"error": "rollback.sh not found in the application directory."}), 404
        cmd = ["bash", script, "--commit", commit]

    try:
        result = subprocess.run(
            cmd,
            cwd=BASE_DIR,
            capture_output=True,
            text=True,
            timeout=300,
            encoding="utf-8",
            errors="replace",
        )
        stdout = _ansi.sub("", result.stdout or "")
        stderr = _ansi.sub("", result.stderr or "")

        auto_restarting = False
        if result.returncode == 0 and platform.system() != "Windows":
            import shutil as _shutil
            if _shutil.which("systemctl"):
                import threading
                def _restart_service():
                    import time as _time
                    _time.sleep(2)
                    subprocess.run(
                        ["sudo", "systemctl", "restart", "centralized"],
                        capture_output=True,
                        timeout=30,
                    )
                t = threading.Thread(target=_restart_service, daemon=True)
                t.start()
                auto_restarting = True

        # Invalidate the update-status and versions caches after any successful rollback
        if result.returncode == 0:
            _update_cache.clear()
            _VERSIONS_CACHE.clear()

        return jsonify({
            "returncode": result.returncode,
            "stdout": stdout[-3000:],
            "stderr": stderr[-1000:],
            "restart_required": result.returncode == 0,
            "auto_restarting": auto_restarting,
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Rollback timed out after 300 seconds."}), 500
    except FileNotFoundError as exc:
        return jsonify({"error": f"Interpreter not found: {exc}"}), 500
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_local_commit():
    """Return (full_sha, short_sha) of the current HEAD, or (None, None)."""
    try:
        full = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=BASE_DIR, capture_output=True, text=True, timeout=5,
        ).stdout.strip()
        short = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=BASE_DIR, capture_output=True, text=True, timeout=5,
        ).stdout.strip()
        return (full or None, short or None)
    except Exception:
        return (None, None)


_GITHUB_COMMIT_CACHE: dict = {}
_GITHUB_COMMIT_TTL   = 300   # 5 minutes — shared by update page + sidebar poll


def _get_github_latest_commit():
    """
    Fetch the latest commit on the default branch (main) from the GitHub API.
    Returns (full_sha, short_sha, commit_message_first_line).
    Result is cached for 5 minutes to stay well under the 60 req/hour limit.
    """
    now = _time.monotonic()
    if _GITHUB_COMMIT_CACHE.get("ts") and now - _GITHUB_COMMIT_CACHE["ts"] < _GITHUB_COMMIT_TTL:
        return _GITHUB_COMMIT_CACHE.get("data", (None, None, None))

    result = (None, None, None)
    try:
        req = urllib.request.Request(
            f"https://api.github.com/repos/{GITHUB_REPO}/commits/main",
            headers=_github_headers(),
        )
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read())
        sha = data.get("sha") or ""
        message = (data.get("commit", {}).get("message") or "").split("\n")[0][:80]
        result = (sha or None, sha[:7] if sha else None, message or None)
    except urllib.error.HTTPError as exc:
        # On rate-limit (403/429) keep any stale cached result rather than None
        if exc.code in (403, 429) and _GITHUB_COMMIT_CACHE.get("data"):
            return _GITHUB_COMMIT_CACHE["data"]
    except Exception:
        pass

    _GITHUB_COMMIT_CACHE["ts"]   = now
    _GITHUB_COMMIT_CACHE["data"] = result
    return result
