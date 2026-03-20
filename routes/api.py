import csv
import io
import json as _json
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
        "os_build":   ctx.os_build   if ctx else "",
        "services": services,
        "port_hints": port_hints,
        "notes": ctx.notes if ctx else "",
    })


@api_bp.route("/hosts/<int:host_id>/context", methods=["POST"])
@login_required
def set_host_context(host_id):
    """Save context and correlate it against CVEs for this host.

    Body JSON:
        os_version  : str  — e.g. "Microsoft Windows 11 Professionnel"
        os_build    : str  — e.g. "25H2" / "22H2" / "1809"
        services    : list — [{"name": "openssl", "version": "3.0.2"}, ...]
        notes       : str  — optional free-text context
        correlate   : bool — default true; if false just saves without CVE check
    """
    host = Host.query.get_or_404(host_id)
    from models import HostContext
    import json as _json

    data = request.get_json(silent=True) or {}
    os_version = (data.get("os_version") or "").strip()
    os_build   = (data.get("os_build")   or "").strip()
    services   = data.get("services") or []
    notes      = (data.get("notes") or "").strip()
    correlate  = data.get("correlate", True)

    # Persist context
    ctx = host.context
    if not ctx:
        ctx = HostContext(host_id=host_id)
        db.session.add(ctx)
    ctx.os_version = os_version or None
    ctx.os_build   = os_build   or None
    ctx.service_versions = _json.dumps(services) if services else None
    ctx.notes = notes or None
    # Mirror analyst OS into the host's main OS field so it appears in the audit host list
    if os_version:
        normalized = _normalize_os_name(os_version)
        host.os_info = normalized + (f" {os_build}" if os_build else "")
    db.session.flush()

    if not correlate:
        db.session.commit()
        return jsonify({"saved": True, "false_positives": [], "confirmed": [], "skipped": []})

    result = _correlate_host_cves(host, os_version, services)
    db.session.commit()
    return jsonify({"saved": True, **result})


# ── Asset import (GLPI CSV / generic JSON) ───────────────────────────────────

_OS_NORMALIZE = [
    # Windows desktop
    (r"windows\s*11",                  "Windows 11"),
    (r"windows\s*10",                  "Windows 10"),
    (r"windows\s*8\.1",               "Windows 8.1"),
    (r"windows\s*8",                   "Windows 8"),
    (r"windows\s*7",                   "Windows 7"),
    # Windows Server
    (r"windows\s*server\s*2025",       "Windows Server 2025"),
    (r"windows\s*server\s*2022",       "Windows Server 2022"),
    (r"windows\s*server\s*2019",       "Windows Server 2019"),
    (r"windows\s*server\s*2016",       "Windows Server 2016"),
    (r"windows\s*server\s*2012\s*r2",  "Windows Server 2012 R2"),
    (r"windows\s*server\s*2012",       "Windows Server 2012"),
    (r"windows\s*server\s*2008\s*r2",  "Windows Server 2008 R2"),
    (r"windows\s*server\s*2008",       "Windows Server 2008"),
    # Linux
    (r"ubuntu\s*([\d.]+)",             r"Ubuntu \1"),
    (r"debian\s*([\d.]+)",             r"Debian \1"),
    (r"centos\s*([\d.]+)",             r"CentOS \1"),
    (r"rocky\s*linux\s*([\d.]+)",      r"Rocky Linux \1"),
    (r"almalinux\s*([\d.]+)",          r"AlmaLinux \1"),
    (r"red\s*hat[^\d]*(\d[\d.]*)",   r"RHEL \1"),
    (r"rhel\s*([\d.]+)",               r"RHEL \1"),
    (r"fedora\s*([\d.]+)",             r"Fedora \1"),
    (r"kali",                          "Kali Linux"),
    # macOS
    (r"macos\s*([\d.]+)",              r"macOS \1"),
    (r"mac\s*os\s*x\s*([\d.]+)",       r"macOS \1"),
]

import re as _os_re

def _normalize_os_name(raw: str) -> str:
    """Normalize a verbose OS string to a short canonical form.
    e.g. 'Microsoft Windows 11 Professionnel' -> 'Windows 11'
    """
    if not raw:
        return raw
    s = raw.strip()
    sl = s.lower()
    for pattern, replacement in _OS_NORMALIZE:
        m = _os_re.search(pattern, sl)
        if m:
            if '\\' in replacement:
                # Has back-references — substitute on the lowercased string,
                # then capitalize the first letter of each word token
                result = _os_re.sub(pattern, replacement, sl).strip()
                # Capitalize known word boundaries cleanly
                return ' '.join(w.capitalize() if w[0].isalpha() else w for w in result.split())
            return replacement
    # Fallback: return as-is
    return s


# ---------------------------------------------------------------------------
# OS → CPE product map (module-level so both set_host_context and
# _correlate_host_cves can share it without redefining it each call)
# ---------------------------------------------------------------------------

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
    (r"windows\s*server\s*2025",     "windows_server_2025"),
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


def _correlate_host_cves(host, os_version: str, services: list) -> dict:
    """Correlate a host's active CVEs against an OS/service context.

    Flushes the session and recomputes host risk but does NOT commit —
    the caller must call db.session.commit() after this returns.

    Returns a dict with keys: false_positives, confirmed, skipped,
                              risk_score, risk_level.
    """
    import re as _re
    from services.cve_service import (
        fetch_cve_configurations, cpe_match_for_product,
        is_version_affected, has_os_cpe_entries,
    )
    from routes.uploads import _compute_host_risk

    # Build service lookup: name (lower) → version
    service_map: dict[str, str] = {}
    for svc in services:
        name = (svc.get("name") or "").strip().lower()
        ver  = (svc.get("version") or "").strip()
        if name and ver:
            service_map[name] = ver

    # Resolve OS string → CPE product hint
    os_product_hint    = None
    os_ver_for_compare = None
    if os_version:
        os_lower = os_version.lower()
        for pattern, product in _OS_PRODUCT_MAP:
            if _re.search(pattern, os_lower):
                os_product_hint = product
                m = _re.search(r"\d+(?:[.\d]+)?", os_version)
                os_ver_for_compare = m.group(0) if m else None
                break

    false_positives = []
    confirmed       = []
    skipped         = []

    if not service_map and not os_product_hint:
        return {
            "false_positives": [],
            "confirmed":       [],
            "skipped":         [],
            "message":         "No versioned services or recognisable OS — nothing to correlate.",
            "risk_score":      host.risk_score,
            "risk_level":      host.risk_level,
        }

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

        decided         = False
        os_fp_candidate = False
        os_fp_product   = None
        os_fp_version   = None
        os_fp_reason    = None

        # ── Phase 1: OS-level check ──────────────────────────────────────────────
        if os_product_hint and has_os_cpe_entries(configs):
            os_cpe_entries = cpe_match_for_product(configs, os_product_hint)
            if not os_cpe_entries:
                os_fp_candidate = True
                os_fp_product   = os_product_hint
                os_fp_version   = os_ver_for_compare or "N/A"
                os_fp_reason    = (
                    f"CVE does not affect {os_product_hint} "
                    f"(not listed in CPE configurations)"
                )
            elif os_ver_for_compare:
                affected = is_version_affected(os_ver_for_compare, os_cpe_entries)
                if affected is False:
                    os_fp_candidate = True
                    os_fp_product   = os_product_hint
                    os_fp_version   = os_ver_for_compare
                    os_fp_reason    = (
                        f"{os_product_hint} {os_ver_for_compare} "
                        f"is not in the affected version range"
                    )
                elif affected is True:
                    vuln.cve_status = "active"
                    confirmed.append({
                        "vuln_id": vuln.id,
                        "cve_id":  vuln.cve_id,
                        "product": os_product_hint,
                        "version": os_ver_for_compare,
                        "reason":  f"{os_product_hint} {os_ver_for_compare} is within the affected version range",
                    })
                    decided = True

        if decided:
            continue

        # ── Phase 2: Service / software version check ──────────────────────────
        matched_product     = None
        matched_version     = None
        matched_cpe_entries = []

        for name, ver in service_map.items():
            cpe_entries = cpe_match_for_product(configs, name)
            if cpe_entries:
                matched_product     = name
                matched_version     = ver
                matched_cpe_entries = cpe_entries
                break

        if not matched_cpe_entries:
            if os_fp_candidate:
                vuln.cve_status = "false_positive"
                false_positives.append({
                    "vuln_id": vuln.id,
                    "cve_id":  vuln.cve_id,
                    "product": os_fp_product,
                    "version": os_fp_version,
                    "reason":  os_fp_reason,
                })
            else:
                skipped.append({"vuln_id": vuln.id, "cve_id": vuln.cve_id,
                                "reason": "No matching product in CVE CPE data"})
            continue

        affected = is_version_affected(matched_version, matched_cpe_entries)

        if affected is False:
            vuln.cve_status = "false_positive"
            false_positives.append({
                "vuln_id": vuln.id,
                "cve_id":  vuln.cve_id,
                "product": matched_product,
                "version": matched_version,
                "reason":  f"{matched_product} {matched_version} is not in the affected version range",
            })
        elif affected is True:
            vuln.cve_status = "active"
            confirmed.append({
                "vuln_id": vuln.id,
                "cve_id":  vuln.cve_id,
                "product": matched_product,
                "version": matched_version,
                "reason":  f"{matched_product} {matched_version} is within the affected version range",
            })
        else:
            skipped.append({"vuln_id": vuln.id, "cve_id": vuln.cve_id,
                            "reason": "Version range indeterminate"})

    db.session.flush()

    score, level = _compute_host_risk(host)
    host.risk_score = score
    host.risk_level = level

    return {
        "false_positives": false_positives,
        "confirmed":       confirmed,
        "skipped":         skipped,
        "risk_score":      host.risk_score,
        "risk_level":      host.risk_level,
    }


def _parse_glpi_csv(file_bytes):
    """Parse a GLPI CSV export (semicolon-delimited, UTF-8 with or without BOM)."""
    for enc in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            content = file_bytes.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:
        return []

    reader = csv.DictReader(io.StringIO(content), delimiter=";")
    assets = []
    for row in reader:
        # Strip BOM / whitespace from keys produced by some GLPI versions
        clean = {k.strip("\ufeff").strip(): v for k, v in row.items() if k}
        name     = clean.get("Nom", "").strip()
        os_name  = (
            clean.get("Système d'exploitation - Nom")
            or clean.get("Syst\u00e8me d'exploitation - Nom")
            or ""
        ).strip()
        os_build = (
            clean.get("Système d'exploitation - Version")
            or clean.get("Syst\u00e8me d'exploitation - Version")
            or ""
        ).strip()
        manufacturer = clean.get("Fabricant", "").strip()
        model        = clean.get("Modèle", clean.get("Mod\u00e8le", "")).strip()
        if name:
            assets.append({
                "name":         name,
                "os":           _normalize_os_name(os_name),
                "os_build":     os_build,
                "manufacturer": manufacturer,
                "model":        model,
            })
    return assets


def _parse_assets_json(file_bytes):
    """Parse a generic JSON asset list (array of objects)."""
    try:
        data = _json.loads(file_bytes.decode("utf-8"))
    except Exception:
        return []
    if not isinstance(data, list):
        return []
    assets = []
    for item in data:
        name = (
            item.get("name") or item.get("Nom") or item.get("hostname") or ""
        ).strip()
        os_name = (
            item.get("os") or item.get("os_info")
            or item.get("Système d'exploitation - Nom") or ""
        ).strip()
        if name:
            assets.append({
                "name":         name,
                "os":           os_name,
                "os_build":     (item.get("os_build") or item.get("Système d'exploitation - Version") or "").strip(),
                "manufacturer": item.get("manufacturer", ""),
                "model":        item.get("model", ""),
            })
    return assets


@api_bp.route("/audits/<int:audit_id>/import-assets", methods=["POST"])
@login_required
def import_assets(audit_id):
    """
    Match an uploaded GLPI CSV (or generic JSON) against the audit's hosts and
    update hostname / os_info where a match is found.

    Query param  dry_run=true  (default) → preview only, no DB write.
    Query param  dry_run=false           → apply changes.
    """
    audit = Audit.query.get_or_404(audit_id)

    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        return jsonify({"error": "No file provided."}), 400

    ext = uploaded.filename.rsplit(".", 1)[-1].lower() if "." in uploaded.filename else ""
    if ext not in ("csv", "json"):
        return jsonify({"error": "Unsupported format. Upload a .csv or .json file."}), 400

    file_bytes = uploaded.read()

    if ext == "csv":
        assets = _parse_glpi_csv(file_bytes)
    else:
        assets = _parse_assets_json(file_bytes)

    if not assets:
        return jsonify({"error": "No assets found in the file. Check the format."}), 400

    dry_run = request.form.get("dry_run", "true").lower() != "false"

    # Build lookup: short name (lowercase) → asset dict
    asset_map = {a["name"].lower(): a for a in assets}

    hosts = Host.query.filter_by(audit_id=audit_id).all()
    results = []
    matched_count = 0
    updated_count = 0
    hosts_to_correlate = []   # (host, os_version) for post-apply CVE correlation

    for host in hosts:
        hn = (host.hostname or "").strip()
        # Try short name first (strip domain suffix), then full hostname
        short = hn.split(".")[0].lower() if hn else ""
        matched = asset_map.get(short) or (asset_map.get(hn.lower()) if hn else None)

        if matched:
            matched_count += 1
            new_hostname = matched["name"]
            new_os       = matched["os"]
            if not dry_run:
                if new_hostname:
                    host.hostname = new_hostname
                if new_os:
                    build = matched.get("os_build", "") or ""
                    host.os_info = new_os + (f" {build}" if build else "")
                    # Also persist into HostContext so the Host Context panel reflects it
                    from models import HostContext
                    ctx = host.context
                    if not ctx:
                        ctx = HostContext(host_id=host.id)
                        db.session.add(ctx)
                    ctx.os_version = new_os or None
                    ctx.os_build   = build  or None
                    hosts_to_correlate.append((host, new_os))
                updated_count += 1
        else:
            new_hostname = ""
            new_os       = ""

        results.append({
            "host_id":          host.id,
            "ip":               host.ip,
            "current_hostname": host.hostname or "",
            "current_os":       host.os_info  or "",
            "new_hostname":     new_hostname,
            "new_os":           new_os,
            "new_os_build":     matched.get("os_build", "") if matched else "",
            "manufacturer":     matched.get("manufacturer", "") if matched else "",
            "model":            matched.get("model", "")        if matched else "",
            "status":           "match" if matched else "no_match",
        })

    if not dry_run:
        db.session.commit()
        # Run CVE correlation for each updated host, reusing their existing
        # stored services so Phase 2 (app-level version check) also fires.
        import json as _cjson
        for _h, _os_ver in hosts_to_correlate:
            try:
                stored_services = []
                if _h.context and _h.context.service_versions:
                    try:
                        stored_services = _cjson.loads(_h.context.service_versions) or []
                    except Exception:
                        pass
                _correlate_host_cves(_h, _os_ver, stored_services)
            except Exception:
                pass
        if hosts_to_correlate:
            db.session.commit()

    return jsonify({
        "dry_run":     dry_run,
        "total_hosts": len(hosts),
        "matched":     matched_count,
        "updated":     updated_count,
        "results":     results,
    })
