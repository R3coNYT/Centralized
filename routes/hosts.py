from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required
from models import Host, Port, Vulnerability, HttpPage, CVE_STATUS_VALUES
from extensions import db

hosts_bp = Blueprint("hosts", __name__, url_prefix="/hosts")


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

    return render_template(
        "hosts/detail.html",
        host=host,
        ports=ports,
        vulns=vulns,
        pages=pages,
        cve_status_values=CVE_STATUS_VALUES,
    )


@hosts_bp.route("/<int:host_id>/tag", methods=["POST"])
@login_required
def update_tag(host_id):
    host = Host.query.get_or_404(host_id)
    data = request.get_json(silent=True) or {}
    tag = (data.get("tag") or "").strip()[:35]
    host.tag = tag if tag else None
    db.session.commit()
    return jsonify({"ok": True, "tag": host.tag})
