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
            "xss_findings": [...],
            "sqli_findings": [...],
            "jwt_findings": [...],
            "dom_xss": [...],
            "shodan": {"<ip>": {...}},
            "cloud_buckets": [...],
            "theharvester": {"emails": [...], "subdomains": [...], "ips": [...]},
            "param_discovery": [...],
            "dir_bruteforce": [...],
            "security_headers": {"missing": [...], "leaky": [...]},
            "cookies": [...],
            "cors_findings": [...],
            "http_methods": [...],
            "open_redirects": [...],
            "js_secrets": [...],
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
    top_level_reverse_dns = data.get("reverse_dns")

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

        # Hostname: prefer per-host ip_enrichment[0].reverse_dns, fall back to top-level
        ip_enrichment = host_data.get("ip_enrichment", []) or []
        host_reverse_dns = None
        for enrichment in ip_enrichment:
            if isinstance(enrichment, dict) and enrichment.get("reverse_dns"):
                host_reverse_dns = enrichment["reverse_dns"]
                break
        if not host_reverse_dns:
            host_reverse_dns = top_level_reverse_dns

        risk = host_data.get("risk", {}) or {}
        cms_list = host_data.get("cms", []) or []
        waf_list = host_data.get("waf", []) or []

        # Build ports from nmap_structured (primary) and masscan (fallback)
        ports = []
        seen_ports = set()

        nmap_structured = host_data.get("nmap_structured") or {}
        for port_info in nmap_structured.get("open_ports", []) or []:
            if not isinstance(port_info, dict):
                continue
            portnum = port_info.get("port")
            try:
                portnum = int(portnum)
            except (ValueError, TypeError):
                continue
            key = (portnum, port_info.get("proto", "tcp"))
            if key in seen_ports:
                continue
            seen_ports.add(key)
            ports.append({
                "port": portnum,
                "protocol": port_info.get("proto", "tcp"),
                "service": port_info.get("service"),
                "product": port_info.get("product"),
                "version": port_info.get("version") or port_info.get("version_raw"),
                "extra_info": port_info.get("extrainfo"),
                "state": "open",
                "cpe": port_info.get("cpe"),
            })

        masscan = host_data.get("masscan", {}) or {}
        for port_str, port_info in masscan.items():
            try:
                portnum = int(port_str)
            except (ValueError, TypeError):
                continue
            if isinstance(port_info, dict):
                key = (portnum, port_info.get("proto", "tcp"))
                if key in seen_ports:
                    continue
                seen_ports.add(key)
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

        # ── New security findings → Vulnerability records ────────────────────

        # Reflected XSS
        for xss in host_data.get("xss_findings", []) or []:
            if not isinstance(xss, dict):
                continue
            param = xss.get("parameter", "?")
            vulns.append({
                "cve_id": None,
                "title": f"Reflected XSS – parameter: {param}",
                "severity": "HIGH",
                "description": (
                    f"Reflected XSS on {xss.get('url', '')} "
                    f"parameter '{param}'. Payload: {xss.get('payload', '')}"
                ),
                "evidence": xss.get("evidence"),
                "source": "xss_scan",
            })

        # SQL Injection (sqlmap)
        for sqli in host_data.get("sqli_findings", []) or []:
            if not isinstance(sqli, dict):
                continue
            param = sqli.get("parameter", "?")
            vulns.append({
                "cve_id": None,
                "title": f"SQL Injection – parameter: {param}",
                "severity": "CRITICAL",
                "description": (
                    f"SQL injection on {sqli.get('url', '')} parameter '{param}' "
                    f"({sqli.get('technique', '')}). DBMS: {sqli.get('db_type') or 'unknown'}."
                ),
                "evidence": sqli.get("evidence"),
                "source": "sqli_scan",
            })

        # JWT vulnerabilities (HIGH / CRITICAL only)
        for jwt in host_data.get("jwt_findings", []) or []:
            if not isinstance(jwt, dict):
                continue
            sev = str(jwt.get("severity", "")).upper()
            if sev in ("HIGH", "CRITICAL"):
                issues = jwt.get("issues", [])
                issues_str = ", ".join(issues) if isinstance(issues, list) else str(issues)
                vulns.append({
                    "cve_id": None,
                    "title": f"JWT Vulnerability – {issues_str[:80] or 'insecure JWT'}",
                    "severity": sev,
                    "description": (
                        f"JWT token analysis: {issues_str}. "
                        f"Algorithm: {jwt.get('algorithm', 'unknown')}"
                    ),
                    "evidence": (jwt.get("token", "")[:60] + "…") if jwt.get("token") else None,
                    "source": "jwt_analysis",
                })

        # DOM XSS (confirmed only)
        for dx in host_data.get("dom_xss", []) or []:
            if not isinstance(dx, dict) or not dx.get("confirmed"):
                continue
            vulns.append({
                "cve_id": None,
                "title": f"DOM XSS – {dx.get('sink', 'unknown sink')}",
                "severity": "HIGH",
                "description": (
                    f"DOM-based XSS confirmed on {dx.get('url', '')}. "
                    f"Sink: {dx.get('sink', '')}. Payload: {dx.get('payload', '')}"
                ),
                "evidence": dx.get("url"),
                "source": "dom_xss",
            })

        # Public cloud storage buckets
        for bucket in host_data.get("cloud_buckets", []) or []:
            if not isinstance(bucket, dict) or not bucket.get("public"):
                continue
            vulns.append({
                "cve_id": None,
                "title": f"Public Cloud Bucket – {bucket.get('name', '?')} ({bucket.get('provider', '?')})",
                "severity": "HIGH",
                "description": f"Publicly accessible cloud storage bucket: {bucket.get('url', '')}",
                "evidence": bucket.get("url"),
                "source": "cloud_buckets",
            })

        # Shodan CVEs
        shodan = host_data.get("shodan", {}) or {}
        for ip_key, sd in shodan.items():
            if not isinstance(sd, dict) or sd.get("error"):
                continue
            for cve_id in (sd.get("vulns") or []):
                if isinstance(cve_id, str) and CVE_RE.match(cve_id):
                    vulns.append({
                        "cve_id": cve_id,
                        "title": cve_id,
                        "severity": "HIGH",
                        "description": f"CVE reported by Shodan for {ip_key}",
                        "source": "shodan",
                    })

        # Missing security headers
        sec_hdrs = host_data.get("security_headers", {}) or {}
        for hdr in sec_hdrs.get("missing", []) or []:
            if not isinstance(hdr, dict):
                continue
            vulns.append({
                "cve_id": None,
                "title": f"Missing Security Header – {hdr.get('header', '?')}",
                "severity": _norm_severity(hdr.get("severity", "MEDIUM")),
                "description": f"HTTP security header '{hdr.get('header')}' is missing.",
                "source": "security_headers",
            })

        # Insecure cookies
        for ck in host_data.get("cookies", []) or []:
            if not isinstance(ck, dict):
                continue
            flags = ", ".join(ck.get("missing_flags", []) or [])
            if flags:
                vulns.append({
                    "cve_id": None,
                    "title": f"Insecure Cookie – {ck.get('name', '?')}",
                    "severity": _norm_severity(ck.get("severity", "LOW")),
                    "description": f"Cookie '{ck.get('name')}' is missing security flags: {flags}.",
                    "source": "cookies",
                })

        # CORS misconfigurations
        for cors in host_data.get("cors_findings", []) or []:
            if not isinstance(cors, dict):
                continue
            vulns.append({
                "cve_id": None,
                "title": f"CORS Misconfiguration – {cors.get('url', '')[:60]}",
                "severity": _norm_severity(cors.get("severity", "MEDIUM")),
                "description": (
                    f"CORS allows origin: {cors.get('reflected_origin', '')}. "
                    f"Credentials: {cors.get('credentials_allowed', False)}"
                ),
                "evidence": cors.get("url"),
                "source": "cors",
            })

        # Open redirects
        for rd in host_data.get("open_redirects", []) or []:
            if not isinstance(rd, dict):
                continue
            vulns.append({
                "cve_id": None,
                "title": f"Open Redirect – {rd.get('parameter', '?')}",
                "severity": _norm_severity(rd.get("severity", "MEDIUM")),
                "description": (
                    f"Open redirect on {rd.get('url', '')} "
                    f"via parameter '{rd.get('parameter', '')}'"
                ),
                "evidence": rd.get("url"),
                "source": "open_redirect",
            })

        # JavaScript secrets / sensitive data
        for sec in host_data.get("js_secrets", []) or []:
            if not isinstance(sec, dict):
                continue
            vulns.append({
                "cve_id": None,
                "title": f"JS Secret – {sec.get('type', 'Unknown')}",
                "severity": "HIGH",
                "description": (
                    f"Sensitive data found in JavaScript: {sec.get('type', '')} "
                    f"in {sec.get('source', '')}"
                ),
                "evidence": str(sec.get("match", ""))[:100],
                "source": "js_secrets",
            })

        # Dangerous HTTP methods
        for hm in host_data.get("http_methods", []) or []:
            if not isinstance(hm, dict):
                continue
            vulns.append({
                "cve_id": None,
                "title": f"Dangerous HTTP Method – {hm.get('method', '?')}",
                "severity": _norm_severity(hm.get("severity", "MEDIUM")),
                "description": (
                    f"Dangerous HTTP method '{hm.get('method')}' "
                    f"enabled on {hm.get('url', '')}"
                ),
                "source": "http_methods",
            })

        # ── Informational enrichment data → extra_data JSON blob ─────────────
        extra_data: dict = {}

        if shodan:
            extra_data["shodan"] = shodan

        harvest = host_data.get("theharvester", {}) or {}
        if harvest and not harvest.get("error") and any(
            harvest.get(k) for k in ("emails", "subdomains", "ips", "hosts")
        ):
            extra_data["theharvester"] = harvest

        login_forms = host_data.get("login_forms", []) or []
        if login_forms:
            extra_data["login_forms"] = login_forms

        dir_bust = host_data.get("dir_bruteforce", []) or []
        if dir_bust:
            extra_data["dir_bruteforce"] = dir_bust

        params = host_data.get("param_discovery", []) or []
        if params:
            extra_data["param_discovery"] = params

        # TLS data
        tls = host_data.get("tls") or {}
        if tls:
            extra_data["tls"] = tls

        # Network info from first valid ip_enrichment entry
        for enrichment in ip_enrichment:
            if not isinstance(enrichment, dict):
                continue
            rdap = enrichment.get("rdap") or {}
            if rdap and not rdap.get("error"):
                if rdap.get("startAddress") and rdap.get("endAddress"):
                    extra_data["network_range"] = f"{rdap['startAddress']} – {rdap['endAddress']}"
                if rdap.get("name"):
                    extra_data["network_name"] = rdap["name"]
            break

        hosts.append({
            "ip": ip,
            "hostname": host_key if host_key != ip else host_reverse_dns,
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
            "extra_data": extra_data if extra_data else None,
        })

    return {"hosts": hosts, "error": None}


def _join_tech(tech):
    if not tech:
        return None
    if isinstance(tech, list):
        return ", ".join(str(t) for t in tech)
    return str(tech)
