"""
Parse AutoRecon full JSON report (report.json).
Schema (simplified):
{
    "input_target": "IP_or_domain",
    "is_ip": bool,
    "reverse_dns": "...",
    "generated_at": "ISO datetime",
    "subdomains": {
        "<host>": {
            "scheme": "https",
            "resolved_ips": [...],
            "tls": {...},
            "cms": [...],
            "waf": [...],
            "pages": [...],
            "login_forms": [...],
            "cves": [...],
            "risk": {"score": N, "level": "...", ...},
            "httpx": [...],
            "nuclei": [...],
            "masscan": {...}
        }
    }
}
"""
import ipaddress
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


def parse_autorecon_json(file_path: str) -> dict:
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    hosts = []
    input_target = data.get("input_target", "")
    reverse_dns = data.get("reverse_dns")

    # Exclude network/broadcast addresses derived from a CIDR input_target
    excluded_ips: set = set()
    try:
        net = ipaddress.ip_network(input_target, strict=False)
        if net.prefixlen < 32:
            excluded_ips.add(str(net.network_address))
            excluded_ips.add(str(net.broadcast_address))
    except ValueError:
        pass

    for host_key, host_data in data.get("subdomains", {}).items():
        if host_key in excluded_ips:
            continue
        resolved_ips = host_data.get("resolved_ips", [])
        ip = resolved_ips[0] if resolved_ips else (input_target if data.get("is_ip") else None)
        if not ip:
            ip = host_key
        # Also skip if the resolved IP itself is a network/broadcast address
        if ip in excluded_ips:
            continue

        risk = host_data.get("risk", {}) or {}
        cms_list = host_data.get("cms", []) or []
        waf_list = host_data.get("waf", []) or []

        # Build ports from masscan data
        ports = []
        masscan = host_data.get("masscan", {}) or {}
        for port_str, port_info in masscan.items():
            try:
                portnum = int(port_str)
            except (ValueError, TypeError):
                continue
            if isinstance(port_info, dict):
                ports.append({
                    "port": portnum,
                    "protocol": port_info.get("proto", "tcp"),
                    "service": port_info.get("service"),
                    "product": port_info.get("product"),
                    "version": port_info.get("version"),
                    "extra_info": None,
                    "state": "open",
                    "cpe": None,
                })

        # CVEs section from AutoRecon report
        vulns = []
        for cve_entry in host_data.get("cves", []) or []:
            if isinstance(cve_entry, dict):
                cve_id = cve_entry.get("cve_id") or cve_entry.get("id") or cve_entry.get("cve")
                vulns.append({
                    "cve_id": cve_id,
                    "title": cve_entry.get("title") or cve_id or "Unknown CVE",
                    "severity": _norm_severity(cve_entry.get("severity") or cve_entry.get("baseSeverity")),
                    "cvss_score": cve_entry.get("cvss_score") or cve_entry.get("score"),
                    "description": cve_entry.get("description"),
                    "source": "autorecon",
                })
            elif isinstance(cve_entry, str) and CVE_RE.match(cve_entry):
                vulns.append({
                    "cve_id": cve_entry,
                    "title": cve_entry,
                    "severity": "UNKNOWN",
                    "source": "autorecon",
                })

        # Nuclei findings
        for nuc in host_data.get("nuclei", []) or []:
            if not isinstance(nuc, dict):
                continue
            info = nuc.get("info", {}) or {}
            sev = _norm_severity(info.get("severity") or nuc.get("severity"))
            cve_id = None
            class_tags = info.get("classification", {}) or {}
            cve_ids = class_tags.get("cve-id", [])
            if isinstance(cve_ids, list) and cve_ids:
                cve_id = cve_ids[0]
            elif isinstance(cve_ids, str):
                cve_id = cve_ids

            vulns.append({
                "cve_id": cve_id,
                "title": info.get("name") or nuc.get("template-id", "Nuclei Finding"),
                "severity": sev,
                "description": info.get("description") or nuc.get("matched-at"),
                "template_id": nuc.get("template-id") or nuc.get("templateID"),
                "evidence": nuc.get("matched-at") or nuc.get("curl-command"),
                "source": "nuclei",
            })

        # HTTP pages from httpx probe results embedded in AutoRecon
        http_pages = []
        for probe in host_data.get("httpx", []) or []:
            if isinstance(probe, dict):
                http_pages.append({
                    "url": probe.get("url") or probe.get("input"),
                    "status_code": probe.get("status_code"),
                    "title": probe.get("title"),
                    "content_type": probe.get("content_type"),
                    "content_length": probe.get("content_length"),
                    "technology": _join_tech(probe.get("tech") or probe.get("technologies")),
                    "redirect_location": probe.get("location"),
                })

        # Also extract pages from crawled pages list
        for page in host_data.get("pages", []) or []:
            if isinstance(page, dict):
                http_pages.append({
                    "url": page.get("url"),
                    "status_code": page.get("status_code") or page.get("status"),
                    "title": page.get("title"),
                    "content_type": page.get("content_type"),
                    "content_length": page.get("content_length"),
                    "technology": None,
                    "redirect_location": None,
                })

        hosts.append({
            "ip": ip,
            "hostname": host_key if host_key != ip else reverse_dns,
            "mac_address": None,
            "mac_vendor": None,
            "os_info": None,
            "risk_score": risk.get("score") or 0.0,
            "risk_level": str(risk.get("level", "")).upper() or None,
            "cms": ", ".join(cms_list) if cms_list else None,
            "waf": ", ".join(waf_list) if waf_list else None,
            "ports": ports,
            "vulnerabilities": vulns,
            "http_pages": http_pages,
        })

    return {"hosts": hosts, "error": None}


def _join_tech(tech):
    if not tech:
        return None
    if isinstance(tech, list):
        return ", ".join(str(t) for t in tech)
    return str(tech)
