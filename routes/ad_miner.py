"""
Routes for Active Directory / SharpHound / AD-Miner integration.

URL prefix: /clients (nested under client resources)
"""
import json
import os
import re
import shutil
import uuid
import zipfile

from flask import (
    Blueprint, abort, current_app, flash, redirect,
    render_template, request, send_from_directory, url_for,
)
from flask_login import login_required
from models import ADData, ADFinding, Client
from extensions import db

ad_miner_bp = Blueprint("ad_miner", __name__, url_prefix="/clients")


# ── Helpers ────────────────────────────────────────────────────────────────────

def _slugify(text: str) -> str:
    text = text.strip().lower()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s_-]+", "_", text)
    return text[:60] or "unknown"


def _upload_root() -> str:
    return current_app.config["UPLOAD_FOLDER"]


def _adminer_dir(client: Client) -> str:
    """Absolute path of the AD-Miner static folder for this client."""
    return os.path.join(_upload_root(), _slugify(client.name), "adminer")


def _adminer_index(client: Client) -> str:
    return os.path.join(_adminer_dir(client), "index.html")


def _zip_common_prefix(members: list) -> str:
    """
    If every zip member sharing a directory component has the same top-level
    folder name, return that prefix (e.g. 'render_20231205/').
    Otherwise return ''.
    """
    tops = {m.split("/")[0] for m in members if "/" in m}
    if len(tops) == 1:
        return tops.pop() + "/"
    return ""


# ── SharpHound upload ──────────────────────────────────────────────────────────

@ad_miner_bp.route("/<int:client_id>/ad/upload-sharphound", methods=["POST"])
@login_required
def upload_sharphound(client_id):
    client = Client.query.get_or_404(client_id)
    files = request.files.getlist("sh_files")
    if not files or all(f.filename == "" for f in files):
        flash("No files selected.", "warning")
        return redirect(url_for("clients.detail", client_id=client_id))

    tmp_dir = os.path.join(_upload_root(), _slugify(client.name), "sh_tmp")
    os.makedirs(tmp_dir, exist_ok=True)
    saved: list = []

    try:
        for f in files:
            if not f.filename:
                continue
            ext = os.path.splitext(f.filename)[1].lower()
            if ext not in (".json", ".zip"):
                continue
            dest = os.path.join(tmp_dir, f"{uuid.uuid4().hex}{ext}")
            f.save(dest)
            saved.append(dest)

        if not saved:
            flash("No valid .json or .zip SharpHound files found.", "warning")
            return redirect(url_for("clients.detail", client_id=client_id))

        from parsers.sharphound_parser import parse_sharphound_files
        parsed = parse_sharphound_files(saved)

    except Exception as exc:
        flash(f"Parse error: {exc}", "danger")
        return redirect(url_for("clients.detail", client_id=client_id))
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    # Upsert ADData
    ad = client.ad_data
    if ad is None:
        ad = ADData(client_id=client_id)
        db.session.add(ad)

    ad.domain_name             = parsed["domain_name"]
    ad.domain_count            = parsed["domain_count"]
    ad.dc_count                = parsed["dc_count"]
    ad.user_count              = parsed["user_count"]
    ad.enabled_user_count      = parsed["enabled_user_count"]
    ad.group_count             = parsed["group_count"]
    ad.computer_count          = parsed["computer_count"]
    ad.adcs_count              = parsed["adcs_count"]
    ad.domain_admin_count      = parsed["domain_admin_count"]
    ad.kerberoastable_count    = parsed["kerberoastable_count"]
    ad.asreproastable_count    = parsed["asreproastable_count"]
    ad.unconstrained_deleg_count = parsed["unconstrained_deleg_count"]
    ad.risk_rating             = parsed["risk_rating"]
    ad.risk_score              = parsed["risk_score"]
    db.session.flush()

    # Replace SharpHound findings only
    ADFinding.query.filter_by(ad_data_id=ad.id, source="sharphound").delete()
    for fd in parsed["findings"]:
        db.session.add(ADFinding(
            ad_data_id     = ad.id,
            source         = "sharphound",
            category       = fd["category"],
            title          = fd["title"],
            severity       = fd["severity"],
            description    = fd["description"],
            affected_count = fd["affected_count"],
            details        = fd["details"],
            remediation    = fd.get("remediation", "[]"),
        ))

    db.session.commit()
    flash(
        f"SharpHound data imported — {len(parsed['findings'])} finding(s) detected.",
        "success",
    )
    return redirect(url_for("clients.detail", client_id=client_id))


# ── AD Data page ───────────────────────────────────────────────────────────────

_SEV_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

@ad_miner_bp.route("/<int:client_id>/ad")
@login_required
def ad_data(client_id):
    client = Client.query.get_or_404(client_id)
    ad = client.ad_data
    if ad is None:
        flash("No AD data uploaded for this client yet.", "warning")
        return redirect(url_for("clients.detail", client_id=client_id))

    findings = sorted(
        ADFinding.query.filter_by(ad_data_id=ad.id).all(),
        key=lambda f: _SEV_ORDER.get(f.severity, 0),
        reverse=True,
    )

    # Build chart data for findings by severity
    sev_labels  = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    sev_counts  = [sum(1 for f in findings if f.severity == s) for s in sev_labels]
    sev_colors  = ["#dc3545", "#fd7e14", "#ffc107", "#0dcaf0", "#6c757d"]

    # Parse raw AD-Miner indicator values if available
    raw_values    = {}
    raw_colors    = {}
    if ad.adminer_raw_values:
        try:
            raw_values = json.loads(ad.adminer_raw_values)
        except Exception:
            raw_values = {}
    if ad.adminer_color_category:
        try:
            raw_colors = json.loads(ad.adminer_color_category)
        except Exception:
            raw_colors = {}

    # Build grouped indicator list for the "all indicators" section
    # Group: Permissions, Attack Paths, Kerberos, Credentials, Network, Misc
    _groups_order = ["Attack Paths", "Permissions", "Kerberos", "Credentials / Authentication", "Network", "Misc"]
    from parsers.adminer_data_parser import _INDICATOR_META, _COLOR_TO_SEV
    indicators_grouped = {g: [] for g in _groups_order}
    for key, color in raw_colors.items():
        sev = _COLOR_TO_SEV.get(color, "INFO")
        value = raw_values.get(key, 0)
        meta  = _INDICATOR_META.get(key)
        if meta:
            title, description, group = meta[0], meta[1], meta[2]
        else:
            title       = key.replace("_", " ").replace("-", " ").title()
            description = ""
            group       = "Misc"
        group = group if group in indicators_grouped else "Misc"
        indicators_grouped[group].append({
            "key":         key,
            "title":       title,
            "description": description,
            "value":       value,
            "color":       color,
            "severity":    sev,
        })
    # Sort each group by severity then value desc
    _sev_sort = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "INFO": 1}
    for g in indicators_grouped:
        indicators_grouped[g].sort(
            key=lambda x: (_sev_sort.get(x["severity"], 0), x["value"]),
            reverse=True,
        )

    adminer_available = os.path.isfile(_adminer_index(client))

    return render_template(
        "clients/ad_data.html",
        client             = client,
        ad                 = ad,
        findings           = findings,
        sev_labels         = json.dumps(sev_labels),
        sev_counts         = json.dumps(sev_counts),
        sev_colors         = json.dumps(sev_colors),
        adminer_available  = adminer_available,
        raw_values         = raw_values,
        raw_colors         = raw_colors,
        indicators_grouped = indicators_grouped,
        groups_order       = _groups_order,
    )


# ── AD-Miner folder upload (ZIP) ───────────────────────────────────────────────

@ad_miner_bp.route("/<int:client_id>/ad/upload-adminer", methods=["POST"])
@login_required
def upload_adminer(client_id):
    client = Client.query.get_or_404(client_id)
    f = request.files.get("adminer_zip")
    if not f or not f.filename:
        flash("No file selected.", "warning")
        return _back(client_id)

    if not f.filename.lower().endswith(".zip"):
        flash("Please upload a .zip file of the AD-Miner output folder.", "warning")
        return _back(client_id)

    dest_dir = _adminer_dir(client)
    if os.path.isdir(dest_dir):
        shutil.rmtree(dest_dir)
    os.makedirs(dest_dir, exist_ok=True)

    tmp_zip = os.path.join(dest_dir, "_upload.zip")
    f.save(tmp_zip)

    try:
        with zipfile.ZipFile(tmp_zip, "r") as zf:
            members = zf.namelist()
            prefix  = _zip_common_prefix(members)
            for member in members:
                rel = member[len(prefix):] if prefix and member.startswith(prefix) else member
                if not rel or rel.startswith("..") or rel.startswith("/"):
                    continue
                target = os.path.realpath(os.path.join(dest_dir, rel))
                # Path-traversal guard
                if not target.startswith(os.path.realpath(dest_dir)):
                    continue
                if member.endswith("/"):
                    os.makedirs(target, exist_ok=True)
                else:
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    with zf.open(member) as src, open(target, "wb") as dst:
                        dst.write(src.read())
    except Exception as exc:
        flash(f"Failed to extract ZIP: {exc}", "danger")
        return _back(client_id)
    finally:
        try:
            os.remove(tmp_zip)
        except OSError:
            pass

    if not os.path.isfile(os.path.join(dest_dir, "index.html")):
        flash("No index.html found at the root of the ZIP. Make sure you zip the AD-Miner output folder directly.", "warning")
        return _back(client_id)

    # ── Parse data_*.json from the extracted folder ────────────────────────────
    from parsers.adminer_data_parser import find_adminer_data_json, parse_adminer_data_json

    data_json_path = find_adminer_data_json(dest_dir)

    # Upsert ADData
    ad = client.ad_data
    if ad is None:
        ad = ADData(client_id=client_id)
        db.session.add(ad)

    ad.adminer_folder_path = os.path.join(_slugify(client.name), "adminer")

    if data_json_path:
        try:
            parsed = parse_adminer_data_json(data_json_path)

            ad.render_name             = parsed["render_name"]
            ad.adminer_report_date     = parsed["report_date"]
            ad.adminer_raw_values      = parsed["raw_values"]
            ad.adminer_color_category  = parsed["raw_color_category"]

            # Only overwrite stat fields if not already populated by SharpHound
            # (SharpHound data is more granular — prefer it if present)
            if not ad.domain_count:
                ad.domain_count = parsed["domain_count"]
            if not ad.dc_count:
                ad.dc_count = parsed["dc_count"]
            if not ad.domain_admin_count:
                ad.domain_admin_count = parsed["domain_admin_count"]
            if not ad.user_count:
                ad.user_count = parsed["user_count"]
            if not ad.group_count:
                ad.group_count = parsed["group_count"]
            if not ad.computer_count:
                ad.computer_count = parsed["computer_count"]
            if not ad.adcs_count:
                ad.adcs_count = parsed["adcs_count"]
            if not ad.kerberoastable_count:
                ad.kerberoastable_count = parsed["kerberoastable_count"]
            if not ad.asreproastable_count:
                ad.asreproastable_count = parsed["asreproastable_count"]
            if not ad.unconstrained_deleg_count:
                ad.unconstrained_deleg_count = parsed["unconstrained_deleg_count"]

            # Always take risk from AD-Miner (it's authoritative)
            ad.risk_rating = parsed["risk_rating"]
            ad.risk_score  = parsed["risk_score"]

            # Replace findings (AD-Miner source only — keep existing SharpHound findings)
            # Delete previous AD-Miner findings and re-insert fresh ones
            ADFinding.query.filter_by(ad_data_id=ad.id, source="adminer").delete()
            db.session.flush()
            for fd in parsed["findings"]:
                db.session.add(ADFinding(
                    ad_data_id     = ad.id,
                    source         = "adminer",
                    category       = fd["category"],
                    title          = fd["title"],
                    severity       = fd["severity"],
                    description    = fd["description"],
                    affected_count = fd["affected_count"],
                    details        = fd["details"],
                    remediation    = fd.get("remediation", "[]"),
                ))

            db.session.commit()
            flash(
                f"AD-Miner report uploaded — {len(parsed['findings'])} finding(s) extracted from data JSON.",
                "success",
            )
        except Exception as exc:
            db.session.commit()  # still save the folder path
            flash(f"AD-Miner report uploaded but data JSON parse failed: {exc}", "warning")
    else:
        db.session.commit()
        flash("AD-Miner report uploaded (no data JSON found — statistics unavailable).", "warning")

    return redirect(url_for("ad_miner.ad_data", client_id=client_id))


def _back(client_id: int):
    """Redirect to AD data page if it exists, else to client detail."""
    client = Client.query.get(client_id)
    if client and client.ad_data:
        return redirect(url_for("ad_miner.ad_data", client_id=client_id))
    return redirect(url_for("clients.detail", client_id=client_id))


# ── Serve AD-Miner static files ────────────────────────────────────────────────

@ad_miner_bp.route("/<int:client_id>/ad/adminer-report/<path:filename>")
@login_required
def serve_adminer(client_id, filename):
    client  = Client.query.get_or_404(client_id)
    base    = os.path.realpath(_adminer_dir(client))
    target  = os.path.realpath(os.path.join(base, filename))

    # Path-traversal guard
    if not target.startswith(base + os.sep) and target != base:
        abort(403)
    if not os.path.isfile(target):
        abort(404)

    return send_from_directory(base, filename)
