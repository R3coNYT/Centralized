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
    from routes.uploads import _nvd_enrich_port, _AUTO_CVE_SERVICES, _compute_host_risk, _clean_str, _is_blank
    new_cves = 0
    for port_obj in host.ports.filter_by(state="open"):
        # Normalize '?' / '-' placeholders left by nmap when identification failed
        product = _clean_str(port_obj.product)
        version = _clean_str(port_obj.version)
        service = (port_obj.service or "").lower()
        if not product and not service:
            continue
        search_term = product or service
        if service in _AUTO_CVE_SERVICES or product:
            # Only search if this port has no CVEs linked yet
            existing = Vulnerability.query.filter_by(host_id=host.id, port_id=port_obj.id).count()
            if existing == 0:
                before = Vulnerability.query.filter_by(host_id=host.id).count()
                _nvd_enrich_port(host.id, port_obj.id, search_term, version)
                after = Vulnerability.query.filter_by(host_id=host.id).count()
                new_cves += after - before

    db.session.flush()

    # Refresh CVSS/severity from NVD for all vulns on this host that have a
    # cve_id but are missing cvss_score or still showing UNKNOWN severity.
    from routes.uploads import _nvd_enrich_vuln
    cvss_updated = 0
    for vuln in host.vulnerabilities:
        if vuln.cve_id and (vuln.cvss_score is None or vuln.severity in ("UNKNOWN", None)):
            _nvd_enrich_vuln(vuln, vuln.cve_id)
            cvss_updated += 1

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
        "cvss_refreshed": cvss_updated,
    })


@api_bp.route("/audits/<int:audit_id>/analyze", methods=["POST"])
@login_required
def analyze_audit(audit_id):
    """
    Re-run port-based risk scoring and auto CVE lookup for ALL hosts of an audit.
    """
    audit = Audit.query.get_or_404(audit_id)
    hosts = Host.query.filter_by(audit_id=audit_id).all()

    from routes.uploads import _nvd_enrich_port, _AUTO_CVE_SERVICES, _compute_host_risk, _clean_str, _is_blank, _nvd_enrich_vuln
    from models import UploadedFile

    total_cves = 0
    total_cvss = 0

    # ── Phase 1: port-based CVE lookup (new ports without any linked CVEs) ───
    for host in hosts:
        for port_obj in host.ports.filter_by(state="open"):
            product = _clean_str(port_obj.product)
            service = (port_obj.service or "").lower()
            if not product and not service:
                continue
            search_term = product or service
            if service in _AUTO_CVE_SERVICES or product:
                existing = Vulnerability.query.filter_by(host_id=host.id, port_id=port_obj.id).count()
                if existing == 0:
                    before = Vulnerability.query.filter_by(host_id=host.id).count()
                    _nvd_enrich_port(host.id, port_obj.id, search_term, _clean_str(port_obj.version))
                    after = Vulnerability.query.filter_by(host_id=host.id).count()
                    total_cves += after - before

    db.session.flush()

    # ── Phase 2: bulk refresh of ALL UNKNOWN/missing-CVSS vulns in the audit ─
    # Query directly (avoids dynamic-relationship iteration issues across hosts)
    unknown_vulns = (
        Vulnerability.query
        .join(Host, Host.id == Vulnerability.host_id)
        .filter(
            Host.audit_id == audit_id,
            Vulnerability.cve_id.isnot(None),
            db.or_(
                Vulnerability.cvss_score.is_(None),
                Vulnerability.severity.in_(["UNKNOWN"]),
                Vulnerability.severity.is_(None),
            ),
        )
        .all()
    )

    for vuln in unknown_vulns:
        _nvd_enrich_vuln(vuln, vuln.cve_id)
        total_cvss += 1

    db.session.flush()

    # ── Phase 3: recompute risk scores for all hosts ──────────────────────────
    has_autorecon = UploadedFile.query.filter(
        UploadedFile.audit_id == audit_id,
        UploadedFile.file_type.in_(["autorecon_json", "pdf"]),
    ).first() is not None

    for host in hosts:
        original_level = host.risk_level
        score, level = _compute_host_risk(host)

        if original_level == "POTENTIAL" and score < 60 and has_autorecon:
            level = "POTENTIAL"

        host.risk_score = score
        host.risk_level = level

    db.session.commit()

    return jsonify({
        "audit_id": audit_id,
        "hosts_analyzed": len(hosts),
        "new_cves_found": total_cves,
        "cvss_refreshed": total_cvss,
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


@api_bp.route("/vulnerabilities/<int:vuln_id>/enrich", methods=["POST"])
@login_required
def enrich_vuln(vuln_id):
    """
    Fetch authoritative CVSS/severity from NVD for a single vulnerability.
    Used by the host detail page to auto-resolve UNKNOWN CVEs without a full
    host re-analysis.
    """
    vuln = Vulnerability.query.get_or_404(vuln_id)
    if not vuln.cve_id:
        return jsonify({"error": "Vulnerability has no CVE ID to look up"}), 400

    from routes.uploads import _nvd_enrich_vuln
    _nvd_enrich_vuln(vuln, vuln.cve_id)
    db.session.commit()

    return jsonify({
        "id": vuln_id,
        "severity": vuln.severity,
        "cvss_score": vuln.cvss_score,
        "description": vuln.description,
    })


def _recompute_host_risk(host_id):
    """Recalculate risk_score and risk_level using the shared port+vuln scoring."""
    from routes.uploads import _compute_host_risk
    host = Host.query.get(host_id)
    if host:
        score, level = _compute_host_risk(host)
        host.risk_score = score
        host.risk_level = level
