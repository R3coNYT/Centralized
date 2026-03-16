import json
import os
import re
import subprocess
import urllib.request

from flask import Blueprint, jsonify, redirect, render_template, request, url_for, flash
from flask_login import current_user, login_required

from extensions import db
from models import SiteSettings

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HEX_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")

SETTING_KEYS = ["accent_color", "sidebar_bg", "bg_card", "bg_surface"]

DEFAULT_SETTINGS = {
    "accent_color": "#0d6efd",
    "sidebar_bg":   "#0f1117",
    "bg_card":      "#1a1d23",
    "bg_surface":   "#13161b",
}

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

GITHUB_REPO = "R3coNYT/Centralized"

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


# ---------------------------------------------------------------------------
# Update routes
# ---------------------------------------------------------------------------

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

    return render_template(
        "admin/update.html",
        current_hash=current_hash,
        current_short=current_short,
        latest_hash=latest_hash,
        latest_short=latest_short,
        latest_message=latest_message,
        is_outdated=is_outdated,
        up_to_date=up_to_date,
    )


@admin_bp.route("/update/run", methods=["POST"])
@login_required
def run_update():
    if current_user.role != "admin":
        return jsonify({"error": "Access denied"}), 403

    script = os.path.join(BASE_DIR, "update.sh")
    if not os.path.exists(script):
        return jsonify({"error": "update.sh not found in the application directory."}), 404

    # Strip ANSI escape sequences from terminal output
    _ansi = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

    try:
        result = subprocess.run(
            ["bash", script],
            cwd=BASE_DIR,
            capture_output=True,
            text=True,
            timeout=180,
        )
        stdout = _ansi.sub("", result.stdout or "")
        stderr = _ansi.sub("", result.stderr or "")
        return jsonify({
            "returncode": result.returncode,
            "stdout": stdout[-3000:],
            "stderr": stderr[-1000:],
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Update timed out after 180 seconds."}), 500
    except FileNotFoundError:
        return jsonify({"error": "bash not found. Ensure bash is installed and available in PATH."}), 500
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


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


def _get_github_latest_commit():
    """
    Fetch the latest commit on the default branch (main) from the GitHub API.
    Returns (full_sha, short_sha, commit_message_first_line).
    """
    try:
        req = urllib.request.Request(
            f"https://api.github.com/repos/{GITHUB_REPO}/commits/main",
            headers={
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "Centralized-App/1.0",
            },
        )
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read())
        sha = data.get("sha") or ""
        message = (data.get("commit", {}).get("message") or "").split("\n")[0][:80]
        return (sha or None, sha[:7] if sha else None, message or None)
    except Exception:
        return (None, None, None)
