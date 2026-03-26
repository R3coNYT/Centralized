import os
import re
import uuid
import shutil
import ipaddress
from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app, send_file, abort
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from models import Audit, Host, Port, Vulnerability, HttpPage, UploadedFile
from extensions import db
from parsers import detect_file_type, parse_file, FILE_TYPE_LYNIS_LOG, FILE_TYPE_LYNIS_REPORT

uploads_bp = Blueprint("uploads", __name__, url_prefix="/uploads")

ALLOWED_EXTENSIONS = {"xml", "json", "pdf", "log", "dat"}


def _allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def _slugify(text: str) -> str:
    """Turn arbitrary text into a safe directory name."""
    text = text.strip().lower()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s_-]+", "_", text)
    return text[:60] or "unknown"


def _audit_upload_dir(audit: Audit) -> str:
    """Return the absolute directory where files for this audit are stored."""
    upload_root = current_app.config["UPLOAD_FOLDER"]
    client_slug = _slugify(audit.client.name) if audit.client else "_no_client"
    audit_slug = f"{_slugify(audit.name)}_{audit.id}"
    return os.path.join(upload_root, client_slug, audit_slug)


def _upload_path(uf: UploadedFile) -> str:
    """Absolute path to an uploaded file on disk."""
    return os.path.join(current_app.config["UPLOAD_FOLDER"], uf.stored_filename)


@uploads_bp.route("/<int:audit_id>", methods=["GET", "POST"])
@login_required
def upload(audit_id):
    audit = Audit.query.get_or_404(audit_id)

    if request.method == "POST":
        files = request.files.getlist("files")
        if not files or all(f.filename == "" for f in files):
            flash("No files selected.", "warning")
            return redirect(request.url)

        enrich_nvd = bool(request.form.get("enrich_nvd"))
        target_ip  = request.form.get("target_ip", "").strip()
        saved_count = 0
        errors = []

        audit_dir = _audit_upload_dir(audit)
        os.makedirs(audit_dir, exist_ok=True)

        for file in files:
            if file.filename == "":
                continue
            if not _allowed_file(file.filename):
                errors.append(f"{file.filename}: unsupported extension (only xml, json, pdf, log, dat).")
                continue

            original_name = secure_filename(file.filename)
            stored_name_file = f"{uuid.uuid4().hex}_{original_name}"

            # Build relative sub-path (stored in DB) and absolute path (for disk I/O)
            client_slug = _slugify(audit.client.name) if audit.client else "_no_client"
            audit_slug = f"{_slugify(audit.name)}_{audit.id}"
            stored_relative = os.path.join(client_slug, audit_slug, stored_name_file)
            save_path = os.path.join(audit_dir, stored_name_file)

            file.save(save_path)
            file_size = os.path.getsize(save_path)

            file_type = detect_file_type(save_path, original_name)

            # Lynis files require a target IP provided by the user
            if file_type in (FILE_TYPE_LYNIS_LOG, FILE_TYPE_LYNIS_REPORT) and not target_ip:
                errors.append(
                    f"{original_name}: a Target IP / Hostname is required for Lynis files."
                )
                os.remove(save_path)
                continue

            uploaded = UploadedFile(
                audit_id=audit_id,
                original_filename=original_name,
                stored_filename=stored_relative,
                file_type=file_type,
                file_size=file_size,
                parsed=False,
                target_ip=target_ip if file_type in (FILE_TYPE_LYNIS_LOG, FILE_TYPE_LYNIS_REPORT) else None,
            )
            db.session.add(uploaded)
            try:
                db.session.flush()
            except Exception as exc:
                db.session.rollback()
                if os.path.exists(save_path):
                    os.remove(save_path)
                errors.append(f"{original_name}: DB error saving record – {exc}")
                continue

            extra = {"target_ip": target_ip} if target_ip else None
            result = parse_file(save_path, file_type, audit_id, db.session, extra=extra)

            if result.get("error"):
                uploaded.parse_error = result["error"]
                errors.append(f"{original_name}: {result['error']}")
            else:
                try:
                    _persist_parsed_data(audit_id, result["hosts"], enrich_nvd)
                    uploaded.parsed = True
                    saved_count += 1
                except Exception as exc:
                    db.session.rollback()
                    uploaded.parse_error = str(exc)
                    errors.append(f"{original_name}: DB error – {exc}")

            db.session.commit()

        if saved_count:
            flash(f"{saved_count} file(s) uploaded and parsed successfully.", "success")
        for err in errors:
            flash(err, "danger")

        return redirect(url_for("audits.detail", audit_id=audit_id))

    uploaded_files = audit.uploaded_files.order_by("created_at").all()
    return render_template("uploads/index.html", audit=audit, uploaded_files=uploaded_files)


@uploads_bp.route("/<int:audit_id>/view/<int:file_id>")
@login_required
def view_file(audit_id, file_id):
    uf = UploadedFile.query.get_or_404(file_id)
    if uf.audit_id != audit_id:
        abort(403)
    path = _upload_path(uf)
    if not os.path.exists(path):
        abort(404)
    ext = uf.original_filename.rsplit(".", 1)[-1].lower() if "." in uf.original_filename else ""
    mime_map = {
        "pdf":  "application/pdf",
        "xml":  "text/xml",
        "json": "application/json",
    }
    mime = mime_map.get(ext, "application/octet-stream")
    return send_file(path, mimetype=mime, download_name=uf.original_filename, as_attachment=False)


@uploads_bp.route("/<int:audit_id>/delete/<int:file_id>", methods=["POST"])
@login_required
def delete_file(audit_id, file_id):
    uf = UploadedFile.query.get_or_404(file_id)
    path = _upload_path(uf)
    if os.path.exists(path):
        os.remove(path)
    # Remove the audit sub-directory if it is now empty
    _cleanup_empty_dirs(os.path.dirname(path))
    db.session.delete(uf)
    db.session.commit()
    flash("File deleted.", "success")
    return redirect(url_for("audits.detail", audit_id=audit_id))


@uploads_bp.route("/<int:audit_id>/reprocess", methods=["POST"])
@login_required
def reprocess_files(audit_id):
    """Re-run all uploaded files for an audit through the parser and persist
    layer.  This enriches existing ports/hosts with data from files that were
    imported in a different order, filling in any missing product/version/CVE
    information without duplicating existing records."""
    audit = Audit.query.get_or_404(audit_id)
    uf_list = audit.uploaded_files.order_by("created_at").all()

    if not uf_list:
        flash("No files to reprocess.", "warning")
        return redirect(url_for("audits.detail", audit_id=audit_id))

    enriched = 0
    errors = []
    for uf in uf_list:
        path = _upload_path(uf)
        if not os.path.exists(path):
            errors.append(f"{uf.original_filename}: file not found on disk.")
            continue
        # Lynis files need a target_ip — use the one stored on the UploadedFile
        # record (saved at upload time), which ties each file to the correct host.
        extra = None
        if uf.file_type in (FILE_TYPE_LYNIS_LOG, FILE_TYPE_LYNIS_REPORT):
            stored_ip = (uf.target_ip or "").strip()
            if not stored_ip:
                # Fallback for legacy records: find the host that owns Lynis vulns
                # matching this file's basename (hostname embedded in Lynis output).
                # If still ambiguous, skip rather than corrupt another host.
                lynis_hosts = (
                    db.session.query(Host)
                    .join(Vulnerability, Vulnerability.host_id == Host.id)
                    .filter(Host.audit_id == audit_id, Vulnerability.source == "lynis")
                    .distinct()
                    .all()
                )
                if len(lynis_hosts) == 1:
                    stored_ip = lynis_hosts[0].ip
                elif len(lynis_hosts) == 0:
                    stored_ip = (Host.query.filter_by(audit_id=audit_id).first() or Host()).ip or ""
                else:
                    errors.append(
                        f"{uf.original_filename}: cannot reprocess — multiple Lynis hosts found "
                        f"and no target IP stored. Re-upload the file with the correct IP."
                    )
                    continue
            if not stored_ip:
                errors.append(f"{uf.original_filename}: cannot reprocess — no host IP found.")
                continue
            extra = {"target_ip": stored_ip}

        result = parse_file(path, uf.file_type, audit_id, db.session, extra=extra)
        if result.get("error"):
            errors.append(f"{uf.original_filename}: {result['error']}")
            continue
        try:
            _persist_parsed_data(audit_id, result["hosts"], enrich_nvd=False)
            enriched += 1
        except Exception as exc:
            db.session.rollback()
            errors.append(f"{uf.original_filename}: DB error – {exc}")

    db.session.commit()

    if enriched:
        flash(f"Reprocessed {enriched} file(s) — ports and CVEs updated.", "success")
    for err in errors:
        flash(err, "danger")

    return redirect(url_for("audits.detail", audit_id=audit_id))


def _cleanup_empty_dirs(directory: str):
    """Remove directory if empty, then walk up and do the same for the parent."""
    upload_root = None
    try:
        from flask import current_app
        upload_root = current_app.config["UPLOAD_FOLDER"]
    except RuntimeError:
        return
    # Never remove the upload root itself
    while directory and directory != upload_root:
        try:
            if os.path.isdir(directory) and not os.listdir(directory):
                os.rmdir(directory)
                directory = os.path.dirname(directory)
            else:
                break
        except OSError:
            break


# ---------------------------------------------------------------------------
# Internal: persist parsed data into DB
# ---------------------------------------------------------------------------

# Ports that should always trigger CVE lookup regardless of enrich_nvd flag
# (they carry known products that commonly have CVEs)
_AUTO_CVE_SERVICES = {
    "ssh", "ftp", "telnet", "smtp", "http", "https", "smb", "rdp",
    "mysql", "mssql", "postgresql", "oracle", "redis", "mongodb",
    "vnc", "imap", "pop3", "ldap", "snmp", "nfs", "ms-wbt-server",
}

# Sensitive ports that raise the base risk score (mirroring AutoRecon logic)
_SENSITIVE_PORTS = {21, 22, 23, 25, 53, 110, 143, 389, 443, 445, 512, 513,
                    514, 873, 1433, 1521, 2049, 2375, 3306, 3389, 5432,
                    5984, 6379, 8080, 8443, 9200, 27017}

_SEV_WEIGHT = {"CRITICAL": 10, "HIGH": 6, "MEDIUM": 3, "LOW": 1, "INFO": 0, "UNKNOWN": 0}

# Values that nmap emits when identification failed — treat as absent
_BLANK_VALUES = {"?", "-", ""}


def _clean_str(val) -> str | None:
    """Normalize nmap placeholder values ('?', '-') to None."""
    if val is None:
        return None
    s = str(val).strip()
    return None if s in _BLANK_VALUES else s


def _is_blank(val) -> bool:
    """Return True if val is absent or an nmap placeholder."""
    return not val or str(val).strip() in _BLANK_VALUES


def _compute_host_risk(host: Host) -> tuple[float, str]:
    """
    Compute risk score from open ports and active vulnerabilities.
    Returns (score, level).  Mirrors AutoRecon's compute_risk_score logic,
    including the POTENTIAL level for unversioned-but-known products.
    """
    from models import CVE_STATUS_EXCLUDED
    score = 0.0

    # 1. Port analysis
    open_port_nums = {p.port for p in host.ports if p.state == "open"}
    sensitive_hit = open_port_nums.intersection(_SENSITIVE_PORTS)
    if sensitive_hit:
        score += 25

    # POTENTIAL flag: product is identified but version is unknown (or '?')
    # This mirrors AutoRecon's potential_flag logic.
    version_unknown = any(
        not _is_blank(p.product) and _is_blank(p.version)
        for p in host.ports if p.state == "open"
    )

    # 2. CVE / vuln severity (only active statuses)
    active_vulns = [
        v for v in host.vulnerabilities
        if v.cve_status not in CVE_STATUS_EXCLUDED
    ]
    critical = sum(1 for v in active_vulns if v.severity == "CRITICAL")
    high     = sum(1 for v in active_vulns if v.severity == "HIGH")

    if critical:
        score += 30
    elif high:
        score += 15

    # Additional weight from vuln count
    score += sum(_SEV_WEIGHT.get(v.severity, 0) for v in active_vulns)

    # WAF slightly reduces risk
    if host.waf:
        score = max(0.0, score - 5)

    score = min(100.0, score)

    # Classification — mirrors AutoRecon exactly:
    # POTENTIAL takes priority when score < 60 and a product version is unknown
    if score >= 60:
        level = "CRITICAL" if critical else "HIGH"
    elif version_unknown:
        level = "POTENTIAL"
    elif score >= 25:
        level = "MEDIUM"
    elif score > 0:
        level = "LOW"
    else:
        level = "INFO"

    return score, level


def _is_plausible_host_ip(ip: str) -> bool:
    """Return False for IPs that are clearly not scannable hosts (loopback, multicast, unspecified, network/broadcast)."""
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback or addr.is_multicast or addr.is_unspecified or addr.is_reserved:
            return False
        # Reject network addresses (last octet 0) and broadcast addresses (last octet 255)
        last_octet = int(str(addr).rsplit(".", 1)[-1])
        if last_octet == 0 or last_octet == 255:
            return False
        return True
    except ValueError:
        return False


def _persist_parsed_data(audit_id: int, parsed_hosts: list, enrich_nvd: bool):
    """Merge parsed host data into the database for the given audit."""
    for host_data in parsed_hosts:
        ip = str(host_data.get("ip", "")).strip()
        if not ip or not _is_plausible_host_ip(ip):
            continue

        # Find or create host
        host = Host.query.filter_by(audit_id=audit_id, ip=ip).first()
        if not host:
            host = Host(audit_id=audit_id, ip=ip)
            db.session.add(host)
            db.session.flush()

        # Update host fields if new data is available
        if host_data.get("hostname") and not host.hostname:
            host.hostname = host_data["hostname"]
        if host_data.get("os_info"):
            host.os_info = host_data["os_info"]
        if host_data.get("mac_address"):
            host.mac_address = host_data["mac_address"]
        if host_data.get("mac_vendor"):
            host.mac_vendor = host_data["mac_vendor"]
        if host_data.get("risk_score") is not None:
            host.risk_score = host_data["risk_score"]
        if host_data.get("risk_level"):
            host.risk_level = host_data["risk_level"]
        if host_data.get("cms"):
            host.cms = host_data["cms"]
        if host_data.get("waf"):
            host.waf = host_data["waf"]

        db.session.flush()

        # Ports
        existing_ports = {(p.port, p.protocol): p for p in host.ports}
        new_ports_for_cve: list[Port] = []
        for pdata in host_data.get("ports", []):
            key = (pdata.get("port"), pdata.get("protocol", "tcp"))
            if key[0] is None:
                continue
            if key not in existing_ports:
                port_obj = Port(
                    host_id=host.id,
                    port=key[0],
                    protocol=key[1],
                    service=_clean_str(pdata.get("service")),
                    product=_clean_str(pdata.get("product")),
                    version=_clean_str(pdata.get("version")),
                    extra_info=_clean_str(pdata.get("extra_info")),
                    state=pdata.get("state", "open"),
                    cpe=_clean_str(pdata.get("cpe")),
                )
                db.session.add(port_obj)
                db.session.flush()
                existing_ports[key] = port_obj
                new_ports_for_cve.append(port_obj)
            else:
                # Port already exists — enrich it with any missing details from
                # this file (e.g. nmap product/version added after httpx, or vice
                # versa).  Only overwrite a field when the existing value is blank
                # and the new value carries real data.
                port_obj = existing_ports[key]
                enriched = False
                product_enriched = False
                for attr, raw in (
                    ("service",    pdata.get("service")),
                    ("product",    pdata.get("product")),
                    ("version",    pdata.get("version")),
                    ("extra_info", pdata.get("extra_info")),
                    ("cpe",        pdata.get("cpe")),
                ):
                    new_val = _clean_str(raw)
                    if new_val and _is_blank(getattr(port_obj, attr)):
                        setattr(port_obj, attr, new_val)
                        enriched = True
                        if attr in ("product", "version"):
                            product_enriched = True
                if pdata.get("state") and port_obj.state in (None, ""):
                    port_obj.state = pdata["state"]
                    enriched = True
                # Re-trigger CVE lookup if we just learned the product/version
                # (this is the main reason import order produced different results)
                if product_enriched:
                    new_ports_for_cve.append(port_obj)
                if enriched:
                    db.session.flush()

        db.session.flush()

        # HTTP pages
        for page in host_data.get("http_pages", []):
            if not page.get("url"):
                continue
            existing_page = HttpPage.query.filter_by(host_id=host.id, url=page["url"]).first()
            if not existing_page:
                db.session.add(HttpPage(
                    host_id=host.id,
                    url=page["url"],
                    status_code=page.get("status_code"),
                    title=page.get("title"),
                    content_type=page.get("content_type"),
                    content_length=page.get("content_length"),
                    technology=page.get("technology"),
                    redirect_location=page.get("redirect_location"),
                ))

        # Vulnerabilities from the parser
        for vdata in host_data.get("vulnerabilities", []):
            cve_id = vdata.get("cve_id")
            title = vdata.get("title", "")
            dup = None
            if cve_id:
                dup = Vulnerability.query.filter_by(host_id=host.id, cve_id=cve_id).first()
            if not dup and title:
                dup = Vulnerability.query.filter_by(host_id=host.id, title=title).first()
            if dup:
                # Backfill recommendation if the existing record is missing it
                new_rec = vdata.get("recommendation")
                if not dup.recommendation and new_rec:
                    dup.recommendation = new_rec
                continue

            vuln = Vulnerability(
                host_id=host.id,
                cve_id=cve_id,
                title=title or cve_id or "Unknown",
                severity=(vdata.get("severity") or "UNKNOWN").upper(),
                cvss_score=vdata.get("cvss_score"),
                cvss_vector=vdata.get("cvss_vector"),
                description=vdata.get("description"),
                references=vdata.get("references"),
                source=vdata.get("source", "unknown"),
                template_id=vdata.get("template_id"),
                evidence=vdata.get("evidence"),
                recommendation=vdata.get("recommendation"),
            )
            db.session.add(vuln)

            # Always fetch authoritative CVSS/severity from NVD for known CVE IDs.
            # This is independent of enrich_nvd (which controls keyword-based searches).
            if cve_id:
                _nvd_enrich_vuln(vuln, cve_id)

        db.session.flush()

        # ── Auto CVE lookup from port data ────────────────────────────────────
        # For every new (or newly-enriched) port that has a product/service
        # name, search all configured CVE sources (NVD + any enabled extras).
        # This always runs: the enrich_nvd checkbox is no longer required to
        # trigger product-based searches.  When only the service keyword is
        # known (product is None), the search is limited to the well-known
        # high-risk service set so we avoid noisy lookups for generic names.
        # '?' / '-' have already been normalised to None above.
        for port_obj in new_ports_for_cve:
            product = port_obj.product           # None when nmap returned '?'
            service = (port_obj.service or "").lower()
            # Nothing useful to search with
            if not product and not service:
                continue
            # When only service is known (product is None / unknown), search by
            # service name only if it's in the well-known auto-lookup set.
            search_term = product or service
            if product or service in _AUTO_CVE_SERVICES:
                version = port_obj.version        # None when nmap returned '?'
                _nvd_enrich_port(host.id, port_obj.id, search_term, version)

        db.session.flush()

        # ── Risk score: compute from ports+vulns if not already provided ──────
        needs_risk = not host_data.get("risk_score") and not host_data.get("risk_level")
        if needs_risk:
            score, level = _compute_host_risk(host)
            host.risk_score = score
            host.risk_level = level

        db.session.flush()



def _nvd_enrich_port(host_id: int, port_id: int, product: str, version: str | None):
    """Search all configured CVE sources for CVEs related to a port's product/version.

    Queries NVD plus any enabled additional sources (e.g. CIRCL) that support
    product keyword search.  Results are deduplicated by CVE ID.
    """
    from services.cve_service import search_cves_for_service
    try:
        cves = search_cves_for_service(product, version)
        for cve_data in cves:
            cve_id = cve_data.get("cve_id")
            if not cve_id:
                continue
            exists = Vulnerability.query.filter_by(host_id=host_id, cve_id=cve_id).first()
            if not exists:
                db.session.add(Vulnerability(
                    host_id=host_id,
                    port_id=port_id,
                    cve_id=cve_id,
                    title=cve_id,
                    severity=cve_data.get("severity", "UNKNOWN"),
                    cvss_score=cve_data.get("cvss_score"),
                    cvss_vector=cve_data.get("cvss_vector"),
                    description=cve_data.get("description"),
                    references=cve_data.get("references"),
                    source=cve_data.get("source", "nvd"),
                ))
    except Exception:
        pass  # CVE lookup is best-effort


def _nvd_enrich_vuln(vuln, cve_id: str):
    """Fetch authoritative CVE data from NVD and update the vulnerability object.

    Always overwrites CVSS score/vector/severity with NVD values (they are the
    authoritative source).  Only fills description/references when absent.
    """
    from services.cve_service import lookup_cve
    try:
        data = lookup_cve(cve_id)
        if data:
            # Always take NVD's authoritative severity and CVSS
            if data.get("severity") and data["severity"] != "UNKNOWN":
                vuln.severity = data["severity"]
            if data.get("cvss_score") is not None:
                vuln.cvss_score = data["cvss_score"]
            if data.get("cvss_vector"):
                vuln.cvss_vector = data["cvss_vector"]
            # Only fill description / references when the vuln doesn't have them yet
            if data.get("description") and not vuln.description:
                vuln.description = data["description"]
            if data.get("references"):
                vuln.references = data["references"]
    except Exception:
        pass
