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
    """Recalculate risk_score and risk_level for the host excluding corrected/FP vulns."""
    from models import CVE_STATUS_EXCLUDED
    WEIGHTS = {"CRITICAL": 10, "HIGH": 6, "MEDIUM": 3, "LOW": 1, "INFO": 0}

    active_vulns = (
        Vulnerability.query
        .filter(
            Vulnerability.host_id == host_id,
            ~Vulnerability.cve_status.in_(CVE_STATUS_EXCLUDED),
        )
        .all()
    )

    score = sum(WEIGHTS.get(v.severity or "", 0) for v in active_vulns)

    if score >= 20:
        level = "CRITICAL"
    elif score >= 10:
        level = "HIGH"
    elif score >= 5:
        level = "MEDIUM"
    elif score > 0:
        level = "LOW"
    else:
        level = "INFO"

    host = Host.query.get(host_id)
    if host:
        host.risk_score = float(score)
        host.risk_level = level
