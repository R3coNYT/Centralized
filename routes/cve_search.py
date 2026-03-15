import re
from flask import Blueprint, render_template, request
from flask_login import login_required
from models import Audit, Host, Port
from extensions import db

cve_bp = Blueprint("cve", __name__, url_prefix="/cve-search")

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)


@cve_bp.route("/")
@login_required
def search_page():
    q = request.args.get("q", "").strip()
    audit_id = request.args.get("audit_id", type=int)

    # All audits for the selector
    audits = Audit.query.order_by(Audit.created_at.desc()).all()

    # Unique product+version pairs in DB for datalist suggestions
    db_services_raw = (
        db.session.query(Port.product, Port.version)
        .filter(Port.product.isnot(None), Port.product != "")
        .distinct()
        .limit(80)
        .all()
    )
    db_services = sorted({
        f"{p} {v}".strip() if v else p
        for p, v in db_services_raw
    })

    results         = []
    searched_for    = ""
    services_searched = []
    error           = None
    audit_obj       = None

    if q:
        from services.cve_service import lookup_cve, search_cves_by_keyword
        try:
            if _CVE_RE.match(q):
                # Direct CVE-ID lookup — much more precise
                cve = lookup_cve(q.upper())
                results = [cve] if cve else []
            else:
                results = search_cves_by_keyword(q, max_results=20)
            searched_for = q
        except Exception as exc:
            error = f"NVD request failed: {exc}"

    elif audit_id:
        audit_obj = Audit.query.get_or_404(audit_id)
        # Unique product+version from this audit's ports
        ports = (
            db.session.query(Port.product, Port.version)
            .join(Host, Host.id == Port.host_id)
            .filter(
                Host.audit_id == audit_id,
                Port.product.isnot(None),
                Port.product != "",
            )
            .distinct()
            .limit(10)
            .all()
        )
        if not ports:
            error = (
                "No services with known product names found in this audit. "
                "Try uploading a Nmap XML scan with version detection (-sV)."
            )
        else:
            from services.cve_service import search_cves_by_keyword
            seen: set[str] = set()
            for product, version in ports:
                kw = f"{product} {version}".strip() if version else product
                services_searched.append(kw)
                try:
                    for cve in search_cves_by_keyword(kw, max_results=5):
                        if cve["cve_id"] not in seen:
                            seen.add(cve["cve_id"])
                            results.append(cve)
                except Exception:
                    pass
        searched_for = f"Audit: {audit_obj.name}" if audit_obj else ""

    # Sort by CVSS score descending
    results.sort(key=lambda x: x.get("cvss_score") or 0, reverse=True)

    # Severity distribution for chart
    sev_count: dict[str, int] = {}
    patch_count = sum(1 for r in results if r.get("patch_available"))
    for r in results:
        s = r.get("severity", "UNKNOWN")
        sev_count[s] = sev_count.get(s, 0) + 1

    return render_template(
        "cve_search/index.html",
        audits=audits,
        audit_obj=audit_obj,
        db_services=db_services,
        results=results,
        searched_for=searched_for,
        services_searched=services_searched,
        sev_count=sev_count,
        patch_count=patch_count,
        q=q,
        audit_id=audit_id,
        error=error,
    )
