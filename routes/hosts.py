from flask import Blueprint, render_template
from flask_login import login_required
from models import Host, Port, Vulnerability, HttpPage
from extensions import db

hosts_bp = Blueprint("hosts", __name__, url_prefix="/hosts")


@hosts_bp.route("/<int:host_id>")
@login_required
def detail(host_id):
    host = Host.query.get_or_404(host_id)
    ports = Port.query.filter_by(host_id=host_id).order_by(Port.port).all()
    vulns = (
        Vulnerability.query.filter_by(host_id=host_id)
        .order_by(
            db.case(
                {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5},
                value=Vulnerability.severity,
                else_=6,
            )
        )
        .all()
    )
    pages = HttpPage.query.filter_by(host_id=host_id).all()

    return render_template(
        "hosts/detail.html",
        host=host,
        ports=ports,
        vulns=vulns,
        pages=pages,
    )
