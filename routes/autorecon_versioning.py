"""
AutoRecon Versioning — browse, compare, and diff AutoRecon scan snapshots.

Routes:
  GET  /autorecon-versioning/host/<int:host_id>          – per-host timeline
  GET  /autorecon-versioning/audit/<int:audit_id>         – per-audit timeline
  GET  /autorecon-versioning/client/<int:client_id>       – per-client timeline
  GET  /autorecon-versioning/api/diff?from=<id>&to=<id>  – JSON diff
  GET  /autorecon-versioning/api/snapshot/<int:snap_id>   – JSON snapshot detail
"""
import json

from flask import Blueprint, render_template, jsonify, request, abort
from flask_login import login_required

from extensions import db
from models import AutoReconSnapshot, Host, Audit, Client
from services.autorecon_snapshot_service import compute_diff

autorecon_versioning_bp = Blueprint(
    "autorecon_versioning", __name__, url_prefix="/autorecon-versioning"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _snapshots_for_host(host_id: int) -> list[AutoReconSnapshot]:
    return (
        AutoReconSnapshot.query
        .filter_by(host_id=host_id)
        .order_by(AutoReconSnapshot.version_number)
        .all()
    )


def _snapshot_to_dict(snap: AutoReconSnapshot, with_diff: dict | None = None) -> dict:
    """Serialise a snapshot to a JSON-safe dict for the templates."""
    d = {
        "id":            snap.id,
        "version_number": snap.version_number,
        "label":         snap.label or f"v{snap.version_number}",
        "scan_type":     snap.scan_type,
        "scanned_at":    snap.scanned_at.strftime("%Y-%m-%d %H:%M") if snap.scanned_at else "—",
        "risk_score":    snap.risk_score,
        "risk_level":    snap.risk_level or "UNKNOWN",
        "vuln_count":    snap.vuln_count,
        "critical_count": snap.critical_count,
        "high_count":    snap.high_count,
        "medium_count":  snap.medium_count,
        "low_count":     snap.low_count,
        "info_count":    snap.info_count,
        "has_ai_report": bool(snap.ai_report_md),
        "diff":          with_diff,
    }
    return d


# ---------------------------------------------------------------------------
# Host-level versioning
# ---------------------------------------------------------------------------

@autorecon_versioning_bp.route("/host/<int:host_id>")
@login_required
def host_versioning(host_id: int):
    host = Host.query.get_or_404(host_id)
    audit = host.audit
    snapshots = _snapshots_for_host(host_id)

    # Build version timeline with diffs
    timeline = []
    for i, snap in enumerate(snapshots):
        diff = None
        if i > 0:
            diff = compute_diff(snapshots[i - 1], snap)
        timeline.append(_snapshot_to_dict(snap, diff))

    return render_template(
        "autorecon_versioning/host.html",
        host=host,
        audit=audit,
        timeline=timeline,
        snapshots=snapshots,
    )


# ---------------------------------------------------------------------------
# Audit-level versioning
# ---------------------------------------------------------------------------

@autorecon_versioning_bp.route("/audit/<int:audit_id>")
@login_required
def audit_versioning(audit_id: int):
    audit = Audit.query.get_or_404(audit_id)

    # Gather all hosts with at least one snapshot
    snapped_host_ids = (
        db.session.query(AutoReconSnapshot.host_id)
        .filter_by(audit_id=audit_id)
        .distinct()
        .all()
    )
    snapped_host_ids = [r[0] for r in snapped_host_ids]
    hosts = Host.query.filter(Host.id.in_(snapped_host_ids)).order_by(Host.ip).all()

    hosts_data = []
    for host in hosts:
        snaps = _snapshots_for_host(host.id)
        timeline = []
        for i, snap in enumerate(snaps):
            diff = compute_diff(snaps[i - 1], snap) if i > 0 else None
            timeline.append(_snapshot_to_dict(snap, diff))
        hosts_data.append({
            "host":     host,
            "timeline": timeline,
        })

    return render_template(
        "autorecon_versioning/audit.html",
        audit=audit,
        hosts_data=hosts_data,
    )


# ---------------------------------------------------------------------------
# Client-level versioning
# ---------------------------------------------------------------------------

@autorecon_versioning_bp.route("/client/<int:client_id>")
@login_required
def client_versioning(client_id: int):
    client = Client.query.get_or_404(client_id)
    audits = client.audits.order_by(Audit.created_at.desc()).all()

    audits_data = []
    for audit in audits:
        snapped_host_ids = (
            db.session.query(AutoReconSnapshot.host_id)
            .filter_by(audit_id=audit.id)
            .distinct()
            .all()
        )
        snapped_host_ids = [r[0] for r in snapped_host_ids]
        if not snapped_host_ids:
            continue
        hosts = Host.query.filter(Host.id.in_(snapped_host_ids)).order_by(Host.ip).all()
        hosts_data = []
        for host in hosts:
            snaps = _snapshots_for_host(host.id)
            timeline = []
            for i, snap in enumerate(snaps):
                diff = compute_diff(snaps[i - 1], snap) if i > 0 else None
                timeline.append(_snapshot_to_dict(snap, diff))
            hosts_data.append({"host": host, "timeline": timeline})
        audits_data.append({"audit": audit, "hosts_data": hosts_data})

    return render_template(
        "autorecon_versioning/client.html",
        client=client,
        audits_data=audits_data,
    )


# ---------------------------------------------------------------------------
# API — JSON diff between two snapshots
# ---------------------------------------------------------------------------

@autorecon_versioning_bp.route("/api/diff")
@login_required
def api_diff():
    from_id = request.args.get("from", type=int)
    to_id   = request.args.get("to",   type=int)
    if not from_id or not to_id:
        return jsonify({"error": "from and to params required"}), 400

    snap_from = AutoReconSnapshot.query.get_or_404(from_id)
    snap_to   = AutoReconSnapshot.query.get_or_404(to_id)
    diff = compute_diff(snap_from, snap_to)
    return jsonify(diff)


# ---------------------------------------------------------------------------
# API — full snapshot detail (for modal/drawer)
# ---------------------------------------------------------------------------

@autorecon_versioning_bp.route("/api/snapshot/<int:snap_id>")
@login_required
def api_snapshot(snap_id: int):
    snap = AutoReconSnapshot.query.get_or_404(snap_id)
    d = _snapshot_to_dict(snap)
    d["vulns"]          = snap.snapshot_vulns_list()
    d["ports"]          = snap.snapshot_ports_list()
    d["suggested_tools"] = snap.suggested_tools_list()
    d["ai_report_md"]   = snap.ai_report_md or ""
    return jsonify(d)
