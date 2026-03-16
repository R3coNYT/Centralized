from flask import Blueprint, jsonify, request
from flask_login import login_required
from models import Audit, Host, Vulnerability, Port, CVE_STATUS_VALUES
from extensions import db
from sqlalchemy import func

api_bp = Blueprint("api", __name__, url_prefix="/api")


@api_bp.route("/audits/<int:audit_id>/stats")
@login_required
def audit_stats(audit_id):
    """Return JSON stats for a specific audit."""
    sev_data = (
        db.session.query(Vulnerability.severity, func.count(Vulnerability.id))
        .join(Host, Host.id == Vulnerability.host_id)
        .filter(Host.audit_id == audit_id)
        .group_by(Vulnerability.severity)
        .all()
    )
    sev_map = {row[0] or "UNKNOWN": row[1] for row in sev_data}

    port_data = (
        db.session.query(Port.service, func.count(Port.id))
        .join(Host, Host.id == Port.host_id)
        .filter(Host.audit_id == audit_id, Port.service.isnot(None))
        .group_by(Port.service)
        .order_by(func.count(Port.id).desc())
        .limit(8)
        .all()
    )

    return jsonify({
        "severities": sev_map,
        "services": {row[0]: row[1] for row in port_data},
    })


@api_bp.route("/hosts/<int:host_id>/analyze", methods=["POST"])
@login_required
def analyze_host(host_id):
    """
    Re-run port-based risk scoring and auto CVE lookup for a host.
    Useful for hosts that were imported without risk data.
    """
    host = Host.query.get_or_404(host_id)

    # Remember the original level before any changes
    original_level = host.risk_level

    # Auto CVE lookup for ports that have no linked vulns yet
    from routes.uploads import _nvd_enrich_port, _AUTO_CVE_SERVICES, _compute_host_risk
    new_cves = 0
    for port_obj in host.ports.filter_by(state="open"):
        product = port_obj.product
        service = (port_obj.service or "").lower()
        if not product and not service:
            continue
        if service in _AUTO_CVE_SERVICES or product:
            # Only search if this port has no CVEs linked yet
            existing = Vulnerability.query.filter_by(host_id=host.id, port_id=port_obj.id).count()
            if existing == 0:
                before = Vulnerability.query.filter_by(host_id=host.id).count()
                _nvd_enrich_port(host.id, port_obj.id, product or service, port_obj.version)
                after = Vulnerability.query.filter_by(host_id=host.id).count()
                new_cves += after - before

    db.session.flush()

    # Recompute risk from ports + all vulns
    score, level = _compute_host_risk(host)

    # If the host was marked POTENTIAL by an AutoRecon report and the new score
    # doesn't warrant elevation to MEDIUM/HIGH/CRITICAL, preserve POTENTIAL.
    if original_level == "POTENTIAL" and score < 60:
        from models import UploadedFile
        has_autorecon = UploadedFile.query.filter(
            UploadedFile.audit_id == host.audit_id,
            UploadedFile.file_type.in_(["autorecon_json", "pdf"]),
        ).first() is not None
        if has_autorecon:
            level = "POTENTIAL"

    host.risk_score = score
    host.risk_level = level
    db.session.commit()

    return jsonify({
        "host_id": host_id,
        "ip": host.ip,
        "risk_score": host.risk_score,
        "risk_level": host.risk_level,
        "new_cves_found": new_cves,
    })


@api_bp.route("/cve/lookup")
@login_required
def cve_lookup():
    """Lookup a single CVE from NVD."""
    cve_id = request.args.get("id", "").strip()
    if not cve_id:
        return jsonify({"error": "Missing 'id' parameter"}), 400

    from services.cve_service import lookup_cve
    data = lookup_cve(cve_id)
    if not data:
        return jsonify({"error": f"CVE {cve_id} not found or NVD unreachable"}), 404
    return jsonify(data)


@api_bp.route("/cve/search")
@login_required
def cve_search():
    """Search CVEs by keyword."""
    keyword = request.args.get("q", "").strip()
    if not keyword:
        return jsonify({"error": "Missing 'q' parameter"}), 400

    from services.cve_service import search_cves_by_keyword
    results = search_cves_by_keyword(keyword, max_results=10)
    return jsonify({"results": results, "count": len(results)})


@api_bp.route("/dashboard/stats")
@login_required
def dashboard_stats():
    from models import Client
    from datetime import datetime, timedelta
    sev_data = (
        db.session.query(Vulnerability.severity, func.count(Vulnerability.id))
        .group_by(Vulnerability.severity)
        .all()
    )
    return jsonify({
        "audits": Audit.query.count(),
        "clients": Client.query.count(),
        "hosts": Host.query.count(),
        "vulnerabilities": Vulnerability.query.count(),
        "severities": {row[0] or "UNKNOWN": row[1] for row in sev_data},
    })


@api_bp.route("/vulnerabilities/<int:vuln_id>/status", methods=["PATCH"])
@login_required
def update_vuln_status(vuln_id):
    """Update the cve_status of a single vulnerability and recompute host risk score."""
    vuln = Vulnerability.query.get_or_404(vuln_id)
    data = request.get_json(silent=True) or {}
    new_status = data.get("status", "").strip()

    if new_status not in CVE_STATUS_VALUES:
        return jsonify({"error": f"Invalid status '{new_status}'. Must be one of: {CVE_STATUS_VALUES}"}), 400

    vuln.cve_status = new_status
    db.session.flush()

    # Recompute host risk score based on active vulnerabilities only
    _recompute_host_risk(vuln.host_id)

    db.session.commit()
    return jsonify({"id": vuln_id, "status": new_status, "risk_score": vuln.host.risk_score,
                    "risk_level": vuln.host.risk_level})


def _recompute_host_risk(host_id):
    """Recalculate risk_score and risk_level using the shared port+vuln scoring."""
    from routes.uploads import _compute_host_risk
    host = Host.query.get(host_id)
    if host:
        score, level = _compute_host_risk(host)
        host.risk_score = score
        host.risk_level = level
