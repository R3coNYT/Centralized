"""
AutoRecon versioning / snapshot service.

After an AutoRecon file (JSON, AI JSON, or backup ZIP) is imported and its
data has been persisted via ``_persist_parsed_data``, call
``create_snapshots_for_upload`` to record a point-in-time snapshot of each
affected host.  Subsequent uploads for the same hosts will produce new
version numbers, enabling diff-based change tracking.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from extensions import db
from models import AutoReconSnapshot, Host, Vulnerability, Port


# ── Constants ──────────────────────────────────────────────────────────────

_AUTORECON_SCAN_TYPES = frozenset([
    "autorecon_json",
    "autorecon_zip",
    "autorecon_ai_json",
])


# ── Public API ─────────────────────────────────────────────────────────────

def create_snapshots_for_upload(
    *,
    audit_id: int,
    host_ips: list[str],
    uploaded_file_id: int | None,
    file_type: str,
    ai_scan_data: dict | None = None,
) -> list[AutoReconSnapshot]:
    """
    Create (or update) AutoReconSnapshot records for all hosts affected by
    a single AutoRecon import.

    :param audit_id:          The audit the file was imported into.
    :param host_ips:          IPs of hosts produced/updated by the parser.
    :param uploaded_file_id:  UploadedFile.id for backlink (may be None).
    :param file_type:         One of FILE_TYPE_AUTORECON_* constants.
    :param ai_scan_data:      Dict with keys ``ai_report_md``,
                              ``suggested_tools``, ``iterations`` (AI only).
    :returns: List of created AutoReconSnapshot objects.
    """
    if file_type not in _AUTORECON_SCAN_TYPES:
        return []

    scan_type = "ai" if file_type == "autorecon_ai_json" else (
        "ai" if (ai_scan_data and ai_scan_data.get("ai_report_md")) else "normal"
    )
    ai_data = ai_scan_data or {}
    created: list[AutoReconSnapshot] = []

    for ip in host_ips:
        if not ip:
            continue
        host: Host | None = Host.query.filter_by(audit_id=audit_id, ip=ip).first()
        if not host:
            continue

        # --- Build snapshot of current host state ---
        vulns = list(host.vulnerabilities)
        ports = list(host.ports)

        snapshot_vulns = json.dumps([
            {
                "cve_id":      v.cve_id,
                "title":       v.title or "",
                "severity":    v.severity or "UNKNOWN",
                "source":      v.source or "unknown",
                "description": (v.description or "")[:300],
                "cve_status":  v.cve_status or "active",
            }
            for v in vulns
        ], ensure_ascii=False)

        snapshot_ports = json.dumps([
            {
                "port":     p.port,
                "protocol": p.protocol or "tcp",
                "service":  p.service or "",
                "product":  p.product or "",
                "version":  p.version or "",
                "state":    p.state or "open",
            }
            for p in ports
        ], ensure_ascii=False)

        # Severity counts
        counts = _count_by_severity(vulns)
        total = sum(counts.values())

        # Version number = existing snapshots for this host + 1
        prev_count = AutoReconSnapshot.query.filter_by(
            audit_id=audit_id, host_id=host.id
        ).count()
        version_number = prev_count + 1

        ts_label = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
        scan_label = f"Scan v{version_number} – {ts_label}"
        if scan_type == "ai":
            scan_label = f"AI Scan v{version_number} – {ts_label}"

        snap = AutoReconSnapshot(
            audit_id=audit_id,
            host_id=host.id,
            uploaded_file_id=uploaded_file_id,
            scan_type=scan_type,
            version_number=version_number,
            label=scan_label,
            scanned_at=_utcnow(),
            risk_score=host.risk_score,
            risk_level=host.risk_level,
            vuln_count=total,
            critical_count=counts["CRITICAL"],
            high_count=counts["HIGH"],
            medium_count=counts["MEDIUM"],
            low_count=counts["LOW"],
            info_count=counts["INFO"],
            snapshot_vulns=snapshot_vulns,
            snapshot_ports=snapshot_ports,
            ai_report_md=ai_data.get("ai_report_md"),
            suggested_tools=json.dumps(ai_data.get("suggested_tools") or [], ensure_ascii=False),
        )
        db.session.add(snap)
        created.append(snap)

    return created


# ── Diff computation (no DB writes) ────────────────────────────────────────

def compute_diff(snap_from: AutoReconSnapshot, snap_to: AutoReconSnapshot) -> dict:
    """
    Compute the diff between two consecutive snapshots.

    Returns::

        {
            "new_vulns":    [...],   # appeared in snap_to, not in snap_from
            "fixed_vulns":  [...],   # present in snap_from, gone in snap_to
            "changed_vulns":[...],   # same cve_id/title, different severity
            "new_ports":    [...],   # appeared in snap_to
            "closed_ports": [...],   # gone in snap_to
            "risk_delta":   float,   # snap_to.risk_score - snap_from.risk_score
        }
    """
    v_from = {_vuln_key(v): v for v in snap_from.snapshot_vulns_list()}
    v_to   = {_vuln_key(v): v for v in snap_to.snapshot_vulns_list()}

    new_vulns     = [v for k, v in v_to.items()   if k not in v_from]
    fixed_vulns   = [v for k, v in v_from.items() if k not in v_to]
    changed_vulns = [
        {"from": v_from[k], "to": v}
        for k, v in v_to.items()
        if k in v_from and v_from[k]["severity"] != v["severity"]
    ]

    p_from = {_port_key(p): p for p in snap_from.snapshot_ports_list()}
    p_to   = {_port_key(p): p for p in snap_to.snapshot_ports_list()}

    new_ports    = [p for k, p in p_to.items()   if k not in p_from]
    closed_ports = [p for k, p in p_from.items() if k not in p_to]

    rs_from = snap_from.risk_score or 0.0
    rs_to   = snap_to.risk_score   or 0.0

    return {
        "new_vulns":     new_vulns,
        "fixed_vulns":   fixed_vulns,
        "changed_vulns": changed_vulns,
        "new_ports":     new_ports,
        "closed_ports":  closed_ports,
        "risk_delta":    round(rs_to - rs_from, 2),
    }


# ── Helpers ────────────────────────────────────────────────────────────────

def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _vuln_key(v: dict) -> str:
    """Canonical key for deduplication: prefer CVE ID, fall back to title."""
    return (v.get("cve_id") or "").upper() or v.get("title", "").lower()[:100]


def _port_key(p: dict) -> str:
    return f"{p.get('port')}/{p.get('protocol', 'tcp')}"


def _count_by_severity(vulns) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for v in vulns:
        sev = (getattr(v, "severity", None) or "INFO").upper()
        if sev in counts:
            counts[sev] += 1
    return counts
