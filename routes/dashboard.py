from flask import Blueprint, render_template
from flask_login import login_required
from sqlalchemy import func
from models import Audit, Host, Vulnerability, Client, UploadedFile
from extensions import db
from datetime import datetime, timedelta

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
@login_required
def index():
    # Summary cards
    total_audits = Audit.query.count()
    total_clients = Client.query.count()
    total_hosts = Host.query.count()
    total_vulns = Vulnerability.query.count()

    # Vulnerabilities by severity
    sev_data = (
        db.session.query(Vulnerability.severity, func.count(Vulnerability.id))
        .group_by(Vulnerability.severity)
        .all()
    )
    sev_map = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "UNKNOWN": 0}
    for sev, cnt in sev_data:
        key = (sev or "UNKNOWN").upper()
        sev_map[key] = sev_map.get(key, 0) + cnt

    # Top services (ports)
    from models import Port
    svc_data = (
        db.session.query(Port.service, func.count(Port.id))
        .filter(Port.service.isnot(None))
        .group_by(Port.service)
        .order_by(func.count(Port.id).desc())
        .limit(8)
        .all()
    )

    # Audits per month (last 12 months)
    twelve_months_ago = datetime.utcnow() - timedelta(days=365)
    monthly_data = (
        db.session.query(
            func.strftime("%Y-%m", Audit.created_at).label("month"),
            func.count(Audit.id),
        )
        .filter(Audit.created_at >= twelve_months_ago)
        .group_by("month")
        .order_by("month")
        .all()
    )

    # Recent audits
    recent_audits = Audit.query.order_by(Audit.created_at.desc()).limit(5).all()

    # Recent vulnerabilities (critical/high)
    recent_vulns = (
        Vulnerability.query
        .filter(Vulnerability.severity.in_(["CRITICAL", "HIGH"]))
        .order_by(Vulnerability.created_at.desc())
        .limit(8)
        .all()
    )

    return render_template(
        "dashboard.html",
        total_audits=total_audits,
        total_clients=total_clients,
        total_hosts=total_hosts,
        total_vulns=total_vulns,
        sev_map=sev_map,
        svc_data=svc_data,
        monthly_data=monthly_data,
        recent_audits=recent_audits,
        recent_vulns=recent_vulns,
    )
