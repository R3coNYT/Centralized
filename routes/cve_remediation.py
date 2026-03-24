import re
from collections import defaultdict
from flask import Blueprint, render_template, jsonify, request, current_app
from flask_login import login_required
from models import Vulnerability, Host, Audit, Client, Port
from extensions import db

cve_remediation_bp = Blueprint("cve_remediation", __name__, url_prefix="/cve-remediation")

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# Human-facing URL template per driver (same as in cve_service, duplicated here for Jinja)
_DRIVER_URL_TEMPLATES: dict[str, str] = {
    "nvd":        "https://nvd.nist.gov/vuln/detail/{id}",
    "circl":      "https://vulnerability.circl.lu/vuln/{id}",
    "mitre":      "https://cve.org/CVERecord?id={id}",
    "osv":        "https://osv.dev/vulnerability/{id}",
    "euvd":       "https://euvd.enisa.europa.eu/vuln/{id}",
    "cvedetails": "https://www.cvedetails.com/cve/{id}/",
    "tenable":    "https://www.tenable.com/cve/{id}",
    "wiz":        "https://www.wiz.io/vulnerability-database/{id}",
    "vuldb":      "https://vuldb.com/?cve.id={id}",
    "cvefind":    "https://www.cvefind.com/cve/{id}",
}

_DRIVER_LABELS: dict[str, str] = {
    "nvd":        "NVD — National Vulnerability Database",
    "circl":      "CIRCL CVE Search",
    "mitre":      "MITRE CVE Program",
    "epss":       "FIRST EPSS",
    "osv":        "OSV",
    "euvd":       "ENISA EUVD",
    "cvedetails": "CVE Details",
    "tenable":    "Tenable Research",
    "wiz":        "Wiz",
    "vuldb":      "VulDB",
    "cvefind":    "CVEFind",
}


def _get_source_links() -> list[dict]:
    """Return [{label, url_template, driver}] for all enabled CveSources with human-facing URLs."""
    try:
        from models import CveSource
        sources = CveSource.query.filter(
            CveSource.enabled == True,
        ).order_by(CveSource.is_builtin.desc(), CveSource.id).all()
        result = []
        for src in sources:
            driver = src.driver or "generic"
            tmpl = _DRIVER_URL_TEMPLATES.get(driver, "")
            if not tmpl or driver == "epss":
                continue
            label = _DRIVER_LABELS.get(driver, src.label or driver)
            result.append({"label": label, "url_template": tmpl, "driver": driver})
        return result
    except Exception:
        return [{"label": "NVD — National Vulnerability Database",
                 "url_template": "https://nvd.nist.gov/vuln/detail/{id}",
                 "driver": "nvd"}]


# ─── helpers ───────────────────────────────────────────────────────────────────

def _sev_key(sev):
    return _SEV_ORDER.get((sev or "").upper(), 5)


# ─── list page ─────────────────────────────────────────────────────────────────

@cve_remediation_bp.route("/")
@login_required
def index():
    """
    List every unique CVE/vulnerability found across all audits,
    with the exhaustive list of affected hosts (host - audit - client).
    """
    rows = (
        db.session.query(Vulnerability, Host, Audit, Client)
        .join(Host,  Host.id  == Vulnerability.host_id)
        .join(Audit, Audit.id == Host.audit_id)
        .outerjoin(Client, Client.id == Audit.client_id)
        .filter(
            db.or_(
                db.and_(Vulnerability.cve_id.isnot(None), Vulnerability.cve_id != ""),
                db.and_(Vulnerability.title.isnot(None),  Vulnerability.title  != ""),
            )
        )
        .order_by(Vulnerability.cve_id, Vulnerability.cvss_score.desc().nullslast())
        .all()
    )

    # Group by canonical key (cve_id when available, else title)
    cve_map: dict = {}

    for vuln, host, audit, client in rows:
        key = vuln.cve_id.upper() if vuln.cve_id else f"TITLE::{vuln.title}"

        if key not in cve_map:
            cve_map[key] = {
                "key":        key,
                "is_cve_id":  bool(vuln.cve_id),
                "cve_id":     vuln.cve_id or None,
                "title":      vuln.title or vuln.cve_id or "—",
                "severity":   vuln.severity or "UNKNOWN",
                "cvss_score": vuln.cvss_score,
                "description": vuln.description or "",
                "recommendation": vuln.recommendation or "",
                "hosts":      {},
            }
        entry = cve_map[key]

        # Keep highest CVSS as the representative
        if vuln.cvss_score and (not entry["cvss_score"] or vuln.cvss_score > entry["cvss_score"]):
            entry["cvss_score"] = vuln.cvss_score
            entry["severity"]   = vuln.severity or entry["severity"]
            entry["description"] = vuln.description or entry["description"]
            entry["recommendation"] = vuln.recommendation or entry["recommendation"]

        # Deduplicate hosts by (host_id, audit_id)
        hkey = (host.id, audit.id)
        if hkey not in entry["hosts"]:
            entry["hosts"][hkey] = {
                "ip":          host.ip,
                "hostname":    host.hostname or host.ip,
                "host_id":     host.id,
                "audit_id":    audit.id,
                "audit_name":  audit.name,
                "client_name": client.name if client else "—",
            }

    # Flatten hosts dicts to lists
    cve_list = []
    for entry in cve_map.values():
        entry["hosts"] = list(entry["hosts"].values())
        entry["host_count"] = len(entry["hosts"])
        cve_list.append(entry)

    # Sort by severity → CVSS desc
    cve_list.sort(key=lambda x: (_sev_key(x["severity"]), -(x["cvss_score"] or 0)))

    # Stats
    sev_counts = defaultdict(int)
    for e in cve_list:
        sev_counts[e["severity"]] += 1

    return render_template(
        "cve_remediation/index.html",
        cve_list=cve_list,
        sev_counts=dict(sev_counts),
        total_affected=sum(e["host_count"] for e in cve_list),
        cve_sources=_get_source_links(),
    )


# ─── AJAX detail endpoint ───────────────────────────────────────────────────────

@cve_remediation_bp.route("/detail")
@login_required
def detail():
    """
    Returns JSON for one CVE: NVD data (description, remediation, refs)
    + list of affected hosts from the DB.
    """
    raw_key = request.args.get("key", "").strip()
    if not raw_key:
        return jsonify({"error": "Missing 'key' parameter"}), 400

    # Determine whether key is a real CVE-ID or a title-based key
    is_cve_id = raw_key.upper().startswith("CVE-") and _CVE_RE.match(raw_key)
    cve_id_upper = raw_key.upper() if is_cve_id else None

    # Fetch DB records for this key
    q = db.session.query(Vulnerability, Host, Audit, Client)\
        .join(Host,  Host.id  == Vulnerability.host_id)\
        .join(Audit, Audit.id == Host.audit_id)\
        .outerjoin(Client, Client.id == Audit.client_id)

    if is_cve_id:
        q = q.filter(db.func.upper(Vulnerability.cve_id) == cve_id_upper)
    else:
        # Title-based key is stored as "TITLE::<title>"
        actual_title = raw_key[len("TITLE::"):] if raw_key.startswith("TITLE::") else raw_key
        q = q.filter(Vulnerability.title == actual_title)

    rows = q.order_by(Vulnerability.cvss_score.desc().nullslast()).all()

    if not rows:
        return jsonify({"error": "No data found for this CVE"}), 404

    # Pick representative vuln (highest CVSS)
    vuln_rep = rows[0][0]

    # Build result dict from DB first
    result = {
        "cve_id":          vuln_rep.cve_id or None,
        "title":           vuln_rep.title or vuln_rep.cve_id or raw_key,
        "severity":        vuln_rep.severity or "UNKNOWN",
        "cvss_score":      vuln_rep.cvss_score,
        "cvss_vector":     vuln_rep.cvss_vector,
        "description":     vuln_rep.description or "",
        "recommendation":  vuln_rep.recommendation or "",
        "references":      vuln_rep.references or "[]",
        # NVD-only fields (filled below if available)
        "patch_refs":           [],
        "patch_available":      False,
        "weaknesses":           [],
        "exploited_in_wild":    False,
        "cisa_remediation":     None,
        "published":            None,
        "last_modified":        None,
        "vuln_status":          None,
    }

    # Enrich with live NVD data when key is a real CVE-ID
    if is_cve_id:
        try:
            from services.cve_service import lookup_cve
            nvd = lookup_cve(cve_id_upper)
            if nvd:
                result.update({
                    "description":        nvd.get("description")    or result["description"],
                    "severity":           nvd.get("severity")       or result["severity"],
                    "cvss_score":         nvd.get("cvss_score")     or result["cvss_score"],
                    "cvss_vector":        nvd.get("cvss_vector")    or result["cvss_vector"],
                    "references":         nvd.get("references", "[]"),
                    "references_meta":    nvd.get("references_meta", {}),
                    "source_links":       nvd.get("source_links", []),
                    "patch_refs":         nvd.get("patch_refs", []),
                    "patch_available":    nvd.get("patch_available", False),
                    "weaknesses":         nvd.get("weaknesses", []),
                    "exploited_in_wild":  nvd.get("exploited_in_wild", False),
                    "cisa_remediation":   nvd.get("cisa_remediation"),
                    "published":          nvd.get("published"),
                    "last_modified":      nvd.get("last_modified"),
                    "vuln_status":        nvd.get("vuln_status"),
                    "configurations":     nvd.get("configurations", []),
                    "affected_packages":  nvd.get("affected_packages", []),
                    "epss_score":         nvd.get("epss_score"),
                    "epss_percentile":    nvd.get("epss_percentile"),
                })
        except Exception:
            pass  # Fallback to DB data silently

    # Collect unique affected hosts
    hosts_seen = {}
    for vuln, host, audit, client in rows:
        hkey = (host.id, audit.id)
        if hkey not in hosts_seen:
            hosts_seen[hkey] = {
                "ip":          host.ip,
                "hostname":    host.hostname or host.ip,
                "host_id":     host.id,
                "audit_id":    audit.id,
                "audit_name":  audit.name,
                "client_name": client.name if client else "—",
                "cve_status":  vuln.cve_status or "active",
            }

    result["hosts"] = list(hosts_seen.values())

    # Collect product/version from Port records for richer remediation commands
    affected_products: list[dict] = []
    products_seen: set[tuple] = set()
    for vuln, host, audit, client in rows:
        if vuln.port_id:
            port = db.session.get(Port, vuln.port_id)
            if port and (port.product or port.cpe):
                pk = (port.product, port.version)
                if pk not in products_seen:
                    products_seen.add(pk)
                    affected_products.append({
                        "product": port.product,
                        "version": port.version,
                        "cpe":     port.cpe,
                        "service": port.service,
                        "port":    port.port,
                        "os_info": host.os_info,
                    })

    # Build step-by-step remediation guide (with DB cache)
    try:
        import json as _json
        import hashlib
        from datetime import datetime, timedelta
        from services.cve_service import build_remediation_steps
        from models import CveRemediationCache

        # Hash of the inputs so we detect when CVE data or host context changes
        _h_input = _json.dumps([
            result.get("configurations", []),
            result.get("affected_packages", []),
            result.get("weaknesses", []),
            result.get("cvss_vector"),
            result.get("exploited_in_wild"),
            sorted(str(p) for p in (affected_products or [])),
        ], sort_keys=True, default=str)
        input_hash = hashlib.sha256(_h_input.encode()).hexdigest()

        cached_steps = None
        if is_cve_id:
            _row = CveRemediationCache.query.filter_by(cve_id=cve_id_upper).first()
            if (_row
                    and _row.expires_at > datetime.utcnow()
                    and _row.input_hash == input_hash):
                cached_steps = _row.steps_list()

        if cached_steps is not None:
            result["remediation_steps"] = cached_steps
        else:
            steps = build_remediation_steps(result, affected_products=affected_products or None)
            result["remediation_steps"] = steps
            if is_cve_id:
                ttl = int(current_app.config.get("CVE_CACHE_TTL_DAYS", 7))
                exp = datetime.utcnow() + timedelta(days=ttl)
                _row = CveRemediationCache.query.filter_by(cve_id=cve_id_upper).first()
                if _row is None:
                    _row = CveRemediationCache(cve_id=cve_id_upper)
                    db.session.add(_row)
                _row.steps      = _json.dumps(steps)
                _row.input_hash = input_hash
                _row.cached_at  = datetime.utcnow()
                _row.expires_at = exp
                try:
                    db.session.commit()
                except Exception:
                    db.session.rollback()
    except Exception:
        result["remediation_steps"] = []

    return jsonify(result)
