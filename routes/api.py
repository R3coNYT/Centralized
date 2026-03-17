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


@api_bp.route("/cve/<path:cve_id>/affected")
@login_required
def cve_affected_software(cve_id):
    """Return a grouped, human-readable list of software affected by a CVE."""
    import re as _re
    from collections import OrderedDict
    from services.cve_service import fetch_cve_configurations

    cve_id = cve_id.upper().strip()
    if not _re.match(r"^CVE-\d{4}-\d{4,7}$", cve_id):
        return jsonify({"error": "Invalid CVE ID"}), 400

    configurations = fetch_cve_configurations(cve_id)
    groups = OrderedDict()

    for node_group in configurations:
        for node in node_group.get("nodes", []):
            for cm in node.get("cpeMatch", []):
                if not cm.get("vulnerable", False):
                    continue
                cpe = cm.get("criteria", "")
                cpe_parts = cpe.split(":")
                if len(cpe_parts) < 5:
                    continue

                part_type = cpe_parts[2]          # a / o / h
                vendor    = cpe_parts[3]
                product   = cpe_parts[4]
                cpe_ver   = cpe_parts[5] if len(cpe_parts) > 5 else "*"

                si = cm.get("versionStartIncluding")
                se = cm.get("versionStartExcluding")
                ei = cm.get("versionEndIncluding")
                ee = cm.get("versionEndExcluding")

                if any([si, se, ei, ee]):
                    bounds = []
                    if si: bounds.append(f">= {si}")
                    if se: bounds.append(f"> {se}")
                    if ei: bounds.append(f"<= {ei}")
                    if ee: bounds.append(f"< {ee}")
                    version_range = " ".join(bounds)
                elif cpe_ver not in ("*", "-", ""):
                    version_range = cpe_ver
                else:
                    version_range = "*"

                key = (vendor, product)
                if key not in groups:
                    groups[key] = {
                        "type": {"a": "App", "o": "OS", "h": "HW"}.get(part_type, "?"),
                        "vendor":  vendor.replace("_", " "),
                        "product": product.replace("_", " "),
                        "versions": [],
                    }
                if version_range not in groups[key]["versions"]:
                    groups[key]["versions"].append(version_range)

    result = list(groups.values())
    return jsonify({"affected": result, "count": len(result)})


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


# ---------------------------------------------------------------------------
# Host context — analyst-provided OS / service version hints
# ---------------------------------------------------------------------------

@api_bp.route("/hosts/<int:host_id>/context", methods=["GET"])
@login_required
def get_host_context(host_id):
    """Return the saved context for a host (OS version + service versions)."""
    host = Host.query.get_or_404(host_id)
    from models import HostContext
    import json
    ctx = host.context
    services = []
    if ctx and ctx.service_versions:
        try:
            services = json.loads(ctx.service_versions)
        except Exception:
            pass
    # Also suggest services from detected ports (pre-populate modal)
    port_hints = [
        {"name": p.product or p.service or "", "version": p.version or ""}
        for p in host.ports.filter_by(state="open")
        if p.product or p.service
    ]
    return jsonify({
        "os_version": ctx.os_version if ctx else "",
        "services": services,
        "port_hints": port_hints,
        "notes": ctx.notes if ctx else "",
    })


@api_bp.route("/hosts/<int:host_id>/context", methods=["POST"])
@login_required
def set_host_context(host_id):
    """Save context and correlate it against CVEs for this host.

    Body JSON:
        os_version  : str  — e.g. "Ubuntu 22.04"
        services    : list — [{"name": "openssl", "version": "3.0.2"}, ...]
        notes       : str  — optional free-text context
        correlate   : bool — default true; if false just saves without CVE check
    """
    host = Host.query.get_or_404(host_id)
    from models import HostContext
    import json as _json

    data = request.get_json(silent=True) or {}
    os_version = (data.get("os_version") or "").strip()
    services   = data.get("services") or []
    notes      = (data.get("notes") or "").strip()
    correlate  = data.get("correlate", True)

    # Persist context
    ctx = host.context
    if not ctx:
        ctx = HostContext(host_id=host_id)
        db.session.add(ctx)
    ctx.os_version = os_version or None
    ctx.service_versions = _json.dumps(services) if services else None
    ctx.notes = notes or None
    db.session.flush()

    if not correlate:
        db.session.commit()
        return jsonify({"saved": True, "false_positives": [], "confirmed": [], "skipped": []})

    # Service lookup: name → version (only entries that have a version filled in)
    service_map: dict[str, str] = {}
    for svc in services:
        name = (svc.get("name") or "").strip().lower()
        ver  = (svc.get("version") or "").strip()
        if name and ver:
            service_map[name] = ver

    # Resolve OS string → specific CPE product hint (e.g. "Windows 11" → "windows_11")
    # Using the exact product name prevents "windows" from matching "windows_2000" etc.
    import re as _re
    _OS_PRODUCT_MAP = [
        (r"windows\s*11",                "windows_11"),
        (r"windows\s*10",                "windows_10"),
        (r"windows\s*8\.1",              "windows_8.1"),
        (r"windows\s*8\b",               "windows_8"),
        (r"windows\s*7",                 "windows_7"),
        (r"windows\s*vista",             "windows_vista"),
        (r"windows\s*xp",                "windows_xp"),
        (r"windows\s*2000",              "windows_2000"),
        (r"windows\s*nt",                "windows_nt"),
        (r"windows\s*server\s*2022",     "windows_server_2022"),
        (r"windows\s*server\s*2019",     "windows_server_2019"),
        (r"windows\s*server\s*2016",     "windows_server_2016"),
        (r"windows\s*server\s*2012\s*r2","windows_server_2012_r2"),
        (r"windows\s*server\s*2012",     "windows_server_2012"),
        (r"windows\s*server\s*2008\s*r2","windows_server_2008_r2"),
        (r"windows\s*server\s*2008",     "windows_server_2008"),
        (r"windows\s*server\s*2003",     "windows_server_2003"),
        (r"ubuntu",                      "ubuntu_linux"),
        (r"debian",                      "debian_linux"),
        (r"centos",                      "centos"),
        (r"red\s*hat|rhel",              "enterprise_linux"),
        (r"fedora",                      "fedora"),
        (r"kali",                        "kali_linux"),
        (r"rocky",                       "rocky_linux"),
        (r"alma",                        "almalinux"),
        (r"mac\s*os|macos|os\s*x",       "mac_os_x"),
        (r"freebsd",                     "freebsd"),
        (r"android",                     "android"),
        (r"alpine",                      "alpine_linux"),
    ]
    os_product_hint = None
    os_ver_for_compare = None
    if os_version:
        os_lower = os_version.lower()
        for pattern, product in _OS_PRODUCT_MAP:
            if _re.search(pattern, os_lower):
                os_product_hint = product
                m = _re.search(r"\d+(?:[.\d]+)?", os_version)
                os_ver_for_compare = m.group(0) if m else None
                break

    if not service_map and not os_product_hint:
        db.session.commit()
        return jsonify({"saved": True, "false_positives": [], "confirmed": [], "skipped": [],
                        "message": "No versioned services or recognisable OS provided — nothing to correlate."})

    from services.cve_service import (
        fetch_cve_configurations, cpe_match_for_product,
        is_version_affected, has_os_cpe_entries,
    )
    from routes.uploads import _compute_host_risk

    false_positives = []
    confirmed       = []
    skipped         = []

    # Only check CVEs that are currently active (not already corrected/fp)
    active_cve_vulns = [
        v for v in host.vulnerabilities
        if v.cve_id and v.cve_status not in ("corrected", "false_positive")
    ]

    for vuln in active_cve_vulns:
        try:
            configs = fetch_cve_configurations(vuln.cve_id)
        except Exception:
            skipped.append({"vuln_id": vuln.id, "cve_id": vuln.cve_id, "reason": "NVD fetch error"})
            continue

        if not configs:
            skipped.append({"vuln_id": vuln.id, "cve_id": vuln.cve_id, "reason": "No CPE data"})
            continue

        decided = False

        # ── Phase 1: OS-level check ───────────────────────────────────────────
        # If the CVE explicitly lists OS-type CPEs and the user's specific OS
        # product (e.g. "windows_11") is NOT among them → False Positive.
        # This correctly handles CVEs that only affect windows_xp/windows_2000
        # when the user is running Windows 11.
        if os_product_hint and has_os_cpe_entries(configs):
            os_cpe_entries = cpe_match_for_product(configs, os_product_hint)
            if not os_cpe_entries:
                # CVE names specific OS versions — ours isn't one of them
                vuln.cve_status = "false_positive"
                false_positives.append({
                    "vuln_id": vuln.id,
                    "cve_id": vuln.cve_id,
                    "product": os_product_hint,
                    "version": os_ver_for_compare or "N/A",
                    "reason": f"CVE does not affect {os_product_hint} (not listed in CPE configurations)",
                })
                decided = True
            elif os_ver_for_compare:
                # Our OS product IS listed — additionally check version bounds
                affected = is_version_affected(os_ver_for_compare, os_cpe_entries)
                if affected is False:
                    vuln.cve_status = "false_positive"
                    false_positives.append({
                        "vuln_id": vuln.id,
                        "cve_id": vuln.cve_id,
                        "product": os_product_hint,
                        "version": os_ver_for_compare,
                        "reason": f"{os_product_hint} {os_ver_for_compare} is not in the affected version range",
                    })
                    decided = True
                elif affected is True:
                    confirmed.append({
                        "vuln_id": vuln.id,
                        "cve_id": vuln.cve_id,
                        "product": os_product_hint,
                        "version": os_ver_for_compare,
                        "reason": f"{os_product_hint} {os_ver_for_compare} is within the affected version range",
                    })
                    decided = True

        if decided:
            continue

        # ── Phase 2: Service / software version check ─────────────────────────
        matched_product = None
        matched_version = None
        matched_cpe_entries = []

        for name, ver in service_map.items():
            cpe_entries = cpe_match_for_product(configs, name)
            if cpe_entries:
                matched_product = name
                matched_version = ver
                matched_cpe_entries = cpe_entries
                break

        if not matched_cpe_entries:
            skipped.append({"vuln_id": vuln.id, "cve_id": vuln.cve_id,
                            "reason": "No matching product in CVE CPE data"})
            continue

        affected = is_version_affected(matched_version, matched_cpe_entries)

        if affected is False:
            vuln.cve_status = "false_positive"
            false_positives.append({
                "vuln_id": vuln.id,
                "cve_id": vuln.cve_id,
                "product": matched_product,
                "version": matched_version,
                "reason": f"{matched_product} {matched_version} is not in the affected version range",
            })
        elif affected is True:
            confirmed.append({
                "vuln_id": vuln.id,
                "cve_id": vuln.cve_id,
                "product": matched_product,
                "version": matched_version,
                "reason": f"{matched_product} {matched_version} is within the affected version range",
            })
        else:
            skipped.append({"vuln_id": vuln.id, "cve_id": vuln.cve_id,
                            "reason": "Version range indeterminate"})

    db.session.flush()

    # Recompute risk now that some CVEs may be false positives
    score, level = _compute_host_risk(host)
    host.risk_score = score
    host.risk_level = level

    db.session.commit()

    return jsonify({
        "saved": True,
        "false_positives": false_positives,
        "confirmed": confirmed,
        "skipped": skipped,
        "risk_score": host.risk_score,
        "risk_level": host.risk_level,
    })
