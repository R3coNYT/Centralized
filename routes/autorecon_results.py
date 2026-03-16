"""
Browse the local AutoRecon results directory and import selected files into an audit.
"""
import os
import platform
import uuid
import shutil

from flask import Blueprint, render_template, jsonify, request, current_app, abort
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename

from models import Audit, UploadedFile
from extensions import db, csrf
from parsers import detect_file_type, parse_file

autorecon_results_bp = Blueprint("autorecon_results", __name__, url_prefix="/autorecon-results")

ALLOWED_EXTENSIONS = {"xml", "json", "pdf"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_base_dir() -> str:
    system = platform.system()
    if system == "Windows":
        return r"C:\Tools\AutoRecon\results"
    elif system == "Darwin":
        return os.path.join(os.path.expanduser("~"), "Tools", "AutoRecon", "results")
    else:
        return "/opt/autorecon/results"


def _safe_resolve(base: str, rel: str) -> str | None:
    """
    Resolve *rel* against *base* and return the absolute path only if it
    stays inside *base* (prevents path-traversal attacks).
    Returns None if the resolved path escapes the base directory.
    """
    # Normalise the relative portion: strip leading separators / ".."
    rel = rel.lstrip("/\\")
    candidate = os.path.normpath(os.path.join(base, rel))
    base_norm = os.path.normpath(base)
    if not candidate.startswith(base_norm + os.sep) and candidate != base_norm:
        return None
    return candidate


def _entry(name: str, full_path: str, base: str) -> dict:
    rel = os.path.relpath(full_path, base).replace("\\", "/")
    is_dir = os.path.isdir(full_path)
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    try:
        size = os.path.getsize(full_path) if not is_dir else None
    except OSError:
        size = None
    return {
        "name": name,
        "type": "dir" if is_dir else "file",
        "path": rel,
        "size": size,
        "ext": ext,
        "allowed": ext in ALLOWED_EXTENSIONS if not is_dir else None,
    }


def _slugify(text: str) -> str:
    import re
    text = text.strip().lower()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s_-]+", "_", text)
    return text[:60] or "unknown"


def _audit_upload_dir(audit: Audit) -> str:
    upload_root = current_app.config["UPLOAD_FOLDER"]
    client_slug = _slugify(audit.client.name) if audit.client else "_no_client"
    audit_slug = f"{_slugify(audit.name)}_{audit.id}"
    return os.path.join(upload_root, client_slug, audit_slug)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@autorecon_results_bp.route("/")
@login_required
def index():
    audits = Audit.query.order_by(Audit.created_at.desc()).all()
    base_dir = _get_base_dir()
    base_exists = os.path.isdir(base_dir)
    return render_template(
        "autorecon_results/index.html",
        audits=audits,
        base_dir=base_dir,
        base_exists=base_exists,
    )


@autorecon_results_bp.route("/api/browse")
@login_required
def api_browse():
    """Return JSON listing of a directory inside the AutoRecon results folder."""
    base = _get_base_dir()
    rel = request.args.get("path", "").strip()

    if rel:
        target = _safe_resolve(base, rel)
        if not target:
            abort(400)
    else:
        target = os.path.normpath(base)

    if not os.path.isdir(target):
        return jsonify({"error": "Directory not found", "items": [], "current_path": rel, "parent_path": None}), 404

    try:
        names = sorted(os.listdir(target))
    except PermissionError:
        return jsonify({"error": "Permission denied", "items": [], "current_path": rel, "parent_path": None}), 403

    items = []
    for name in names:
        full = os.path.join(target, name)
        items.append(_entry(name, full, base))

    # Dirs first, then files — alphabetical within each group
    items.sort(key=lambda e: (0 if e["type"] == "dir" else 1, e["name"].lower()))

    # Compute parent path (relative to base), or None if we're at the root
    base_norm = os.path.normpath(base)
    parent_rel: str | None = None
    if os.path.normpath(target) != base_norm:
        parent_abs = os.path.dirname(target)
        if os.path.normpath(parent_abs).startswith(base_norm):
            parent_rel = os.path.relpath(parent_abs, base).replace("\\", "/")
            if parent_rel == ".":
                parent_rel = ""

    current_rel = os.path.relpath(target, base).replace("\\", "/")
    if current_rel == ".":
        current_rel = ""

    return jsonify({
        "items": items,
        "current_path": current_rel,
        "parent_path": parent_rel,
    })


@autorecon_results_bp.route("/api/import", methods=["POST"])
@login_required
def api_import():
    """
    Import selected files from the AutoRecon results directory into an audit.
    Expected JSON body:
      { "paths": ["rel/path/to/file.json", ...], "audit_id": 1, "enrich_nvd": false }
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    paths = data.get("paths", [])
    audit_id = data.get("audit_id")
    enrich_nvd = bool(data.get("enrich_nvd", False))

    if not paths:
        return jsonify({"error": "No files selected"}), 400
    if not audit_id:
        return jsonify({"error": "No audit selected"}), 400

    audit = Audit.query.get(audit_id)
    if not audit:
        return jsonify({"error": "Audit not found"}), 404

    base = _get_base_dir()
    audit_dir = _audit_upload_dir(audit)
    os.makedirs(audit_dir, exist_ok=True)

    client_slug = _slugify(audit.client.name) if audit.client else "_no_client"
    audit_slug = f"{_slugify(audit.name)}_{audit.id}"

    results = []
    for rel_path in paths:
        rel_path = str(rel_path).strip()
        abs_path = _safe_resolve(base, rel_path)
        if not abs_path or not os.path.isfile(abs_path):
            results.append({"path": rel_path, "ok": False, "error": "File not found or invalid path"})
            continue

        original_name = secure_filename(os.path.basename(abs_path))
        ext = original_name.rsplit(".", 1)[-1].lower() if "." in original_name else ""
        if ext not in ALLOWED_EXTENSIONS:
            results.append({"path": rel_path, "ok": False, "error": "Unsupported file type"})
            continue

        stored_name = f"{uuid.uuid4().hex}_{original_name}"
        stored_relative = os.path.join(client_slug, audit_slug, stored_name)
        save_path = os.path.join(audit_dir, stored_name)

        try:
            shutil.copy2(abs_path, save_path)
        except OSError as exc:
            results.append({"path": rel_path, "ok": False, "error": str(exc)})
            continue

        file_size = os.path.getsize(save_path)
        file_type = detect_file_type(save_path, original_name)

        uploaded = UploadedFile(
            audit_id=audit_id,
            original_filename=original_name,
            stored_filename=stored_relative,
            file_type=file_type,
            file_size=file_size,
            parsed=False,
        )
        db.session.add(uploaded)
        db.session.flush()

        from routes.uploads import _persist_parsed_data
        parse_result = parse_file(save_path, file_type, audit_id, db.session)
        if parse_result.get("error"):
            uploaded.parse_error = parse_result["error"]
            results.append({"path": rel_path, "ok": False, "error": parse_result["error"]})
        else:
            try:
                _persist_parsed_data(audit_id, parse_result["hosts"], enrich_nvd)
                uploaded.parsed = True
                results.append({"path": rel_path, "ok": True})
            except Exception as exc:
                db.session.rollback()
                uploaded.parse_error = str(exc)
                results.append({"path": rel_path, "ok": False, "error": f"DB error – {exc}"})

        db.session.commit()

    ok_count = sum(1 for r in results if r["ok"])
    return jsonify({"results": results, "ok_count": ok_count, "total": len(results)})
