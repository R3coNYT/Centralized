"""
Parse Nuclei JSON output.
Supports both JSONL (one JSON object per line) and a JSON array.
"""
import json
import re

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
    "informational": "INFO",
    "unknown": "UNKNOWN",
}


def _norm_severity(raw):
    if not raw:
        return "UNKNOWN"
    return SEVERITY_MAP.get(str(raw).lower(), "UNKNOWN")


def _load_nuclei(file_path: str) -> list:
    """Load nuclei output: JSON array or JSONL."""
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read().strip()

    # Try JSON array first
    try:
        data = json.loads(content)
        if isinstance(data, list):
            return data
    except json.JSONDecodeError:
        pass

    # Try JSONL
    results = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return results


def parse_nuclei_json(file_path: str) -> dict:
    entries = _load_nuclei(file_path)
    hosts_map: dict[str, dict] = {}

    for entry in entries:
        if not isinstance(entry, dict):
            continue

        matched_at = entry.get("matched-at") or entry.get("matched_at") or ""
        host = entry.get("host") or entry.get("ip") or ""

        # Derive IP from matched_at or host field
        ip = host
        # Strip scheme and path
        ip_clean = re.sub(r"https?://", "", ip).split(":")[0].split("/")[0]
        if ip_clean:
            ip = ip_clean

        if not ip:
            ip = "unknown"

        if ip not in hosts_map:
            hosts_map[ip] = {
                "ip": ip,
                "hostname": None,
                "mac_address": None,
                "mac_vendor": None,
                "os_info": None,
                "ports": [],
                "vulnerabilities": [],
                "http_pages": [],
            }

        info = entry.get("info", {}) or {}
        sev = _norm_severity(info.get("severity") or entry.get("severity"))

        # Extract CVE ID
        cve_id = None
        classification = info.get("classification", {}) or {}
        cve_ids = classification.get("cve-id", [])
        if isinstance(cve_ids, list) and cve_ids:
            cve_id = cve_ids[0].upper()
        elif isinstance(cve_ids, str) and cve_ids:
            cve_id = cve_ids.upper()
        else:
            found = CVE_RE.findall(entry.get("template-id", "") + " " + info.get("name", ""))
            if found:
                cve_id = found[0].upper()

        refs = info.get("reference", [])
        if isinstance(refs, str):
            refs = [refs]

        hosts_map[ip]["vulnerabilities"].append({
            "cve_id": cve_id,
            "title": info.get("name") or entry.get("template-id") or "Nuclei Finding",
            "severity": sev,
            "description": info.get("description") or matched_at,
            "references": json.dumps(refs) if refs else None,
            "template_id": entry.get("template-id") or entry.get("templateID"),
            "evidence": matched_at or entry.get("curl-command"),
            "source": "nuclei",
        })

    return {"hosts": list(hosts_map.values()), "error": None}
