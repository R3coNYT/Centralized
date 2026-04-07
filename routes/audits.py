import os
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from models import Audit, Client, Host, Vulnerability, Finding, Port
from extensions import db
from datetime import datetime
from services.notifications import fire_notification, broadcast_live_event

audits_bp = Blueprint("audits", __name__, url_prefix="/audits")


@audits_bp.route("/")
@login_required
def list_audits():
    status_filter = request.args.get("status", "")
    q = Audit.query.order_by(Audit.created_at.desc())
    if status_filter:
        q = q.filter(Audit.status == status_filter)
    audits = q.all()
    return render_template("audits/list.html", audits=audits, status_filter=status_filter)


@audits_bp.route("/new", methods=["GET", "POST"])
@login_required
def new_audit():
    clients = Client.query.order_by(Client.name).all()

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        if not name:
            flash("Audit name is required.", "danger")
            return render_template("audits/new.html", clients=clients)

        client_id = request.form.get("client_id") or None
        target = request.form.get("target", "").strip()
        scope = request.form.get("scope", "").strip()
        notes = request.form.get("notes", "").strip()
        status = request.form.get("status", "in_progress")
        start_date = _parse_date(request.form.get("start_date"))
        end_date = _parse_date(request.form.get("end_date"))

        audit = Audit(
            name=name,
            client_id=int(client_id) if client_id else None,
            created_by_id=current_user.id,
            target=target,
            scope=scope,
            notes=notes,
            status=status,
            start_date=start_date,
            end_date=end_date,
        )
        db.session.add(audit)
        db.session.flush()  # get ID before firing notifications
        if audit.client_id:
            fire_notification(
                "client", audit.client_id, "new_audit",
                f"New audit: {audit.name}",
                f"Target: {audit.target}" if audit.target else "A new audit has been created.",
                f"/audits/{audit.id}",
            )
        db.session.commit()
        broadcast_live_event("new_audit", {
            "audit_id": audit.id,
            "audit_name": audit.name,
            "client_id": audit.client_id,
            "status": audit.status,
            "url": f"/audits/{audit.id}",
        })
        flash(f"Audit '{name}' created.", "success")
        return redirect(url_for("audits.detail", audit_id=audit.id))

    return render_template("audits/new.html", clients=clients)


@audits_bp.route("/<int:audit_id>")
@login_required
def detail(audit_id):
    audit = Audit.query.get_or_404(audit_id)
    hosts = Host.query.filter_by(audit_id=audit_id).all()

    # Vulnerability stats per severity
    from sqlalchemy import func
    sev_data = (
        db.session.query(Vulnerability.severity, func.count(Vulnerability.id))
        .join(Host, Host.id == Vulnerability.host_id)
        .filter(Host.audit_id == audit_id)
        .group_by(Vulnerability.severity)
        .all()
    )
    sev_map = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "UNKNOWN": 0}
    for sev, cnt in sev_data:
        key = (sev or "UNKNOWN").upper()
        sev_map[key] = sev_map.get(key, 0) + cnt

    # Host risk level distribution (AutoRecon risk score, independent of CVE severity)
    risk_data = (
        db.session.query(Host.risk_level, func.count(Host.id))
        .filter(Host.audit_id == audit_id, Host.risk_level.isnot(None))
        .group_by(Host.risk_level)
        .all()
    )
    risk_map = {row[0].upper(): row[1] for row in risk_data if row[0]}

    # Port distribution
    port_svc = (
        db.session.query(Port.service, func.count(Port.id))
        .join(Host, Host.id == Port.host_id)
        .filter(Host.audit_id == audit_id, Port.service.isnot(None))
        .group_by(Port.service)
        .order_by(func.count(Port.id).desc())
        .limit(10)
        .all()
    )

    findings = Finding.query.filter_by(audit_id=audit_id).order_by(Finding.created_at.desc()).all()
    uploaded_files = audit.uploaded_files.order_by("created_at").all()

    # Vulns with unknown/missing severity that need background enrichment on page load
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
        .with_entities(Vulnerability.id, Vulnerability.cve_id)
        .all()
    )

    return render_template(
        "audits/detail.html",
        audit=audit,
        hosts=hosts,
        sev_map=sev_map,
        risk_map=risk_map,
        port_svc=port_svc,
        findings=findings,
        uploaded_files=uploaded_files,
        unknown_vulns=unknown_vulns,
    )


@audits_bp.route("/<int:audit_id>/edit", methods=["GET", "POST"])
@login_required
def edit_audit(audit_id):
    audit = Audit.query.get_or_404(audit_id)
    clients = Client.query.order_by(Client.name).all()

    if request.method == "POST":
        old_status = audit.status
        audit.name = request.form.get("name", audit.name).strip()
        audit.target = request.form.get("target", "").strip()
        audit.scope = request.form.get("scope", "").strip()
        audit.notes = request.form.get("notes", "").strip()
        new_status = request.form.get("status", audit.status)
        audit.status = new_status
        client_id = request.form.get("client_id")
        audit.client_id = int(client_id) if client_id else None
        audit.start_date = _parse_date(request.form.get("start_date"))
        audit.end_date = _parse_date(request.form.get("end_date"))
        if old_status != new_status:
            fire_notification(
                "audit", audit.id, "status_change",
                f"Audit status changed: {audit.name}",
                f"Status: {old_status} → {new_status}",
                f"/audits/{audit.id}",
            )
            if new_status == "completed":
                fire_notification(
                    "audit", audit.id, "audit_completed",
                    f"Audit completed: {audit.name}",
                    f"The audit has been marked as completed.",
                    f"/audits/{audit.id}",
                )
                if audit.client_id:
                    fire_notification(
                        "client", audit.client_id, "audit_completed",
                        f"Audit completed: {audit.name}",
                        f"An audit for this client has been marked as completed.",
                        f"/audits/{audit.id}",
                    )
        db.session.commit()
        broadcast_live_event("audit_update", {
            "audit_id": audit.id,
            "audit_name": audit.name,
            "status": audit.status,
            "old_status": old_status,
            "client_id": audit.client_id,
            "url": f"/audits/{audit.id}",
        })
        flash("Audit updated.", "success")
        return redirect(url_for("audits.detail", audit_id=audit.id))

    return render_template("audits/edit.html", audit=audit, clients=clients)


@audits_bp.route("/<int:audit_id>/delete", methods=["POST"])
@login_required
def delete_audit(audit_id):
    import shutil
    from routes.uploads import _audit_upload_dir
    audit = Audit.query.get_or_404(audit_id)
    name = audit.name
    # Remove the audit's upload directory from disk before DB cascade
    try:
        audit_dir = _audit_upload_dir(audit)
        if os.path.isdir(audit_dir):
            shutil.rmtree(audit_dir)
        # Remove parent client dir if now empty
        client_dir = os.path.dirname(audit_dir)
        if os.path.isdir(client_dir) and not os.listdir(client_dir):
            os.rmdir(client_dir)
    except Exception:
        pass
    db.session.delete(audit)
    db.session.commit()
    flash(f"Audit '{name}' deleted.", "success")
    return redirect(url_for("audits.list_audits"))


@audits_bp.route("/<int:audit_id>/findings/add", methods=["POST"])
@login_required
def add_finding(audit_id):
    audit = Audit.query.get_or_404(audit_id)
    title = request.form.get("title", "").strip()
    if not title:
        flash("Finding title is required.", "danger")
        return redirect(url_for("audits.detail", audit_id=audit_id))

    host_id = request.form.get("host_id")
    finding = Finding(
        audit_id=audit_id,
        host_id=int(host_id) if host_id else None,
        title=title,
        severity=request.form.get("severity", "MEDIUM"),
        description=request.form.get("description", ""),
        evidence=request.form.get("evidence", ""),
        recommendation=request.form.get("recommendation", ""),
        status=request.form.get("status", "open"),
    )
    db.session.add(finding)
    db.session.commit()
    flash("Finding added.", "success")
    return redirect(url_for("audits.detail", audit_id=audit_id))


@audits_bp.route("/<int:audit_id>/findings/<int:finding_id>/delete", methods=["POST"])
@login_required
def delete_finding(audit_id, finding_id):
    finding = Finding.query.get_or_404(finding_id)
    db.session.delete(finding)
    db.session.commit()
    flash("Finding deleted.", "success")
    return redirect(url_for("audits.detail", audit_id=audit_id))


def _parse_date(value):
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d")
    except (ValueError, TypeError):
        return None
