import json
import re
from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required
from models import Host, Port, Vulnerability, HttpPage, CVE_STATUS_VALUES, AutoReconSnapshot
from extensions import db

hosts_bp = Blueprint("hosts", __name__, url_prefix="/hosts")


def _lynis_recommendation_from_title(title: str) -> str:
    """Regenerate a recommendation string from a Lynis vuln title.
    Title format: '[TEST-ID] description'
    """
    from parsers.lynis_parser import _build_recommendation
    m = re.match(r'^\[([A-Z0-9-]+)\]\s*(.*)', title or '')
    if m:
        test_id, description = m.group(1), m.group(2)
    else:
        test_id, description = '', title or ''
    return _build_recommendation(test_id, '', description)


@hosts_bp.route("/<int:host_id>")
@login_required
def detail(host_id):
    host = Host.query.get_or_404(host_id)
    ports = Port.query.filter_by(host_id=host_id).order_by(Port.port).all()
    vulns = (
        Vulnerability.query.filter_by(host_id=host_id)
        .order_by(
            db.case(
                {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5},
                value=Vulnerability.severity,
                else_=6,
            )
        )
        .all()
    )
    pages = HttpPage.query.filter_by(host_id=host_id).all()

    # Auto-backfill missing recommendations for Lynis vulns.
    # This runs transparently so existing data is healed without any user action.
    needs_commit = False
    for v in vulns:
        if v.source == 'lynis' and not v.recommendation:
            v.recommendation = _lynis_recommendation_from_title(v.title)
            needs_commit = True
    if needs_commit:
        db.session.commit()

    extra_data = {}
    if host.extra_data:
        try:
            extra_data = json.loads(host.extra_data)
        except Exception:
            extra_data = {}

    # Latest AI snapshot (for AI report card on host page)
    latest_ai_snap = (
        AutoReconSnapshot.query
        .filter_by(host_id=host_id)
        .filter(AutoReconSnapshot.ai_report_md.isnot(None))
        .order_by(AutoReconSnapshot.version_number.desc())
        .first()
    )
    ai_report_md        = latest_ai_snap.ai_report_md        if latest_ai_snap else None
    ai_suggested_tools  = latest_ai_snap.suggested_tools_list() if latest_ai_snap else []
    ai_report_label     = latest_ai_snap.label                if latest_ai_snap else None

    return render_template(
        "hosts/detail.html",
        host=host,
        ports=ports,
        vulns=vulns,
        pages=pages,
        cve_status_values=CVE_STATUS_VALUES,
        extra_data=extra_data,
        ai_report_md=ai_report_md,
        ai_suggested_tools=ai_suggested_tools,
        ai_report_label=ai_report_label,
    )


@hosts_bp.route("/<int:host_id>/tag", methods=["POST"])
@login_required
def update_tag(host_id):
    host = Host.query.get_or_404(host_id)
    data = request.get_json(silent=True) or {}
    tag = (data.get("tag") or "").strip()[:25]
    host.tag = tag if tag else None
    db.session.commit()
    return jsonify({"ok": True, "tag": host.tag})
