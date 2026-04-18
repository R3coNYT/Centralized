"""
Parse AutoRecon AI-scan output files.

The AI scan produces an ``ai_scan/`` subdirectory containing:
  - conversation.json   – full JSON conversation log (commands + AI analysis)
  - ai_report.md        – final Markdown report written by the AI
  - ai_report.pdf       – PDF version (not parsed here)
  - step_NNN.txt        – individual command outputs
  - suggested_tools.json – tools the AI flagged as missing

This parser extracts:
  - target IP (from caller-supplied extra["target"] or from conversation)
  - final AI report (markdown)
  - suggested tools list
  - a synthetic vulnerability list built from the AI's analysis text
    (we tag these as source="ai_analysis" so they are clearly labelled)

The returned structure is identical to what other parsers return:
  {
      "hosts": [<host_dict>, ...],
      "error": None | str,
      "ai_scan_data": {
          "ai_report_md": str,
          "suggested_tools": [{"name": ..., "reason": ...}, ...],
          "iterations": int,
      }
  }
"""
import json
import re
import os

# ── Regex patterns used to extract structured findings from free-text ──────
_CVE_RE       = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_SEVERITY_MAP = {
    "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
    "low": "LOW", "info": "INFO", "informational": "INFO",
}

# Heuristic patterns that indicate a vulnerability mention in the AI report
_VULN_PATTERNS = [
    # "CVE-2021-12345 (Critical)" or "CVE-2021-12345: description"
    re.compile(
        r"(CVE-\d{4}-\d{4,7})[^\n]*?(critical|high|medium|low|info)?",
        re.IGNORECASE,
    ),
    # "** Finding: … **" markdown bold headings
    re.compile(r"\*\*\s*(?:Finding|Vulnerability|Issue|Risk|Weakness)[:\s]+([^\*\n]+)\*\*", re.IGNORECASE),
    # Markdown section headings: "### CVE-…", "### Finding N: …",
    # "### [HIGH] - Title", "### Vulnerability: …", "### N. Title (High)"
    re.compile(
        r"^#{2,4}\s+("
        r"(?:CVE-\d{4}-\d{4,7}[^\n]*)"
        r"|(?:(?:Finding|Vulnerability|Issue|Risk|Weakness)\s*[\d#]*\s*[:\-\u2013]+\s*[^\n]{3,})"
        r"|(?:\[?(?:CRITICAL|HIGH|MEDIUM|LOW|INFO)\]?\s*[-:\u2013]\s*[^\n]{3,})"
        r"|(?:\d+[\.):]\s+[^\n]{5,80}\s*(?:[-\u2013(]\s*(?:critical|high|medium|low|info)[)\s]*)?$)"
        r")",
        re.MULTILINE | re.IGNORECASE,
    ),
]

# ── Rich port / host / finding extraction ─────────────────────────────────

# "- `22/tcp` — OpenSSH 10.0p2 Debian 7"  or plain "- 22/tcp — SSH"
_PORT_LINE_RE = re.compile(
    r"^\s*[-*\u2022]\s+`?(\d{1,5})/(tcp|udp)`?\s*[—–\-]{1,3}\s*(.+)",
    re.IGNORECASE | re.MULTILINE,
)

# "**Resolved name:** device-64.home"  /  "Resolved name: device-64.home"
# Note: in markdown **Label:** the colon is INSIDE the bold, closing ** comes after it.
_RESOLVED_NAME_RE = re.compile(
    r"Resolved\s+name\s*:+\s*\*{0,2}\s*`?([a-zA-Z0-9][a-zA-Z0-9._-]{1,})`?",
    re.IGNORECASE,
)
_HOSTNAME_LABEL_RE = re.compile(
    r"\b(?:hostname|fqdn|rdns|ptr)\b\s*:+\s*\*{0,2}\s*`?([a-zA-Z0-9][a-zA-Z0-9._-]{2,})`?",
    re.IGNORECASE,
)

# Finding section headings (markdown or plain text)
_FINDING_SECTION_RE = re.compile(
    r"^#{0,4}\s*Finding\s+\d+[:.)\s]+(.+?)$",
    re.MULTILINE,
)
# Sub-block patterns inside a finding section.
# Pattern handles both plain "Label: value" and markdown "**Label:** value"
# (in markdown the colon is inside the bold, closing ** appears AFTER it).
_SEV_IN_SECTION_RE    = re.compile(r"Severity\s*:+\s*\*{0,2}\s*(Critical|High|Medium|Low|Info(?:rmational)?)", re.IGNORECASE)
_SVC_IN_SECTION_RE    = re.compile(r"Service\s*:+\s*\*{0,2}\s*(.+?)(?:\n|$)", re.IGNORECASE)
_EVI_IN_SECTION_RE    = re.compile(
    r"Evidence\s*:+\s*\*{0,2}\s*([\s\S]+?)(?=\nService\s*:|\nSeverity\s*:|\nInterpretation\s*:|\nRecommendations?\s*:|$)",
    re.IGNORECASE,
)
_INTERP_IN_SECTION_RE = re.compile(
    r"Interpretation\s*:+\s*\*{0,2}\s*([\s\S]+?)(?=\nSeverity\s*:|\nRecommendations?\s*:|$)",
    re.IGNORECASE,
)
_REC_IN_SECTION_RE    = re.compile(
    r"Recommendations?\s*:+\s*\*{0,2}\s*([\s\S]+?)(?=\n#{1,4}\s|$)",
    re.IGNORECASE,
)

# "Additional Tools Not Installed" section
_TOOLS_SECTION_RE = re.compile(
    r"(?:Additional\s+Tools?\s+(?:Not\s+Installed|Recommended|That\s+Would\s+Help)|Tools?\s+(?:Not\s+Installed|Recommended))[^\n]*\n([\s\S]+?)(?=\n#{1,4}\s|\Z)",
    re.IGNORECASE,
)

# Port → default service name
_PORT_SVC_MAP: dict = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    3306: "mysql", 3389: "ms-wbt-server", 4000: "https",
    5432: "postgresql", 5900: "vnc", 6379: "redis",
    8006: "https", 8080: "http-proxy", 9200: "elasticsearch",
    10050: "zabbix-agent", 27017: "mongodb",
}

# Product keyword → service name
_PRODUCT_SVC_MAP: dict = {
    "openssh": "ssh", "apache": "http", "nginx": "http",
    "express": "https", "node": "https", "nodejs": "https",
    "proxmox": "https", "pve": "https",
    "zabbix": "zabbix-agent", "mysql": "mysql",
    "postgresql": "postgresql", "postgres": "postgresql",
    "redis": "redis", "mongodb": "mongodb",
    "iis": "http", "tomcat": "http",
    "vsftpd": "ftp", "proftpd": "ftp",
    "postfix": "smtp", "exim": "smtp",
    "dovecot": "imap", "ssl": "https", "tls": "https",
}


def _parse_port_service(desc: str, port: int) -> tuple:
    """Parse a service-description string into (service, product, version)."""
    raw = re.sub(r"`", "", desc).strip()

    # tcpwrapped — try inline hint "/ likely X"
    if re.match(r"tcpwrapped", raw, re.IGNORECASE):
        likely = re.search(r"/?(?:likely|probably)\s+(.+)", raw, re.IGNORECASE)
        if likely:
            hint = likely.group(1).strip()
            kw = hint.lower().split()[0]
            return (_PRODUCT_SVC_MAP.get(kw, kw), hint[:100], None)
        return (_PORT_SVC_MAP.get(port), None, None)

    # Service name from product keyword
    service = _PORT_SVC_MAP.get(port)
    for kw, svc in _PRODUCT_SVC_MAP.items():
        if kw in raw.lower():
            service = svc
            break

    # Version: first standalone version token (e.g. "10.0p2", "10.0p2 Debian 7")
    ver_m = re.search(
        r"\b(\d+\.\d+(?:\.\d+)?(?:[a-z]\d+)?(?:p\d+)?(?:\s+(?:Debian|Ubuntu|RHEL|CentOS)\s+\d+)?)\b",
        raw, re.IGNORECASE,
    )
    version = ver_m.group(1).strip() if ver_m else None

    # Product: full description, cleaned of trailing noise and version suffix
    product = re.sub(
        r"\s*(?:application|interface|service|server|agent|daemon|running)\s*$",
        "", raw, flags=re.IGNORECASE,
    ).strip()
    if version and product.endswith(version):
        product = product[: -len(version)].strip()
    product = product[:120] or None

    return (service, product, version)


def _extract_ports_from_report(text: str) -> list:
    """Extract open-port records from a markdown or plain-text security report."""
    ports: list = []
    seen: set = set()
    for m in _PORT_LINE_RE.finditer(text):
        port_num = int(m.group(1))
        proto    = m.group(2).lower()
        desc     = m.group(3).strip()
        key = (port_num, proto)
        if key in seen or port_num > 65535:
            continue
        seen.add(key)
        service, product, version = _parse_port_service(desc, port_num)
        ports.append({
            "port":       port_num,
            "protocol":   proto,
            "service":    service,
            "product":    product,
            "version":    version,
            "extra_info": None,
            "state":      "open",
            "cpe":        None,
        })
    return ports


def _extract_hostname_from_report(text: str) -> "str | None":
    """Extract resolved hostname from the report text."""
    m = _RESOLVED_NAME_RE.search(text)
    if m:
        return m.group(1).strip()
    m = _HOSTNAME_LABEL_RE.search(text)
    if m:
        val = m.group(1).strip()
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", val):
            return val
    return None


def _extract_os_from_report(text: str) -> "str | None":
    """Extract OS information from the report text."""
    # "Host is Linux-based" / "host appears to be a Linux-based system"
    m = re.search(
        r"host\s+(?:is|appears?\s+to\s+be)\s+(?:a\s+)?([A-Za-z][A-Za-z0-9\s\-\.]{2,50}?)"
        r"(?:\s+based|\s+system|\s*[.\n])",
        text, re.IGNORECASE,
    )
    if m:
        val = m.group(1).strip()
        if 3 < len(val) < 80:
            return val
    # "Operating System: ..." / "OS: ..."
    m = re.search(r"\b(?:operating\s+system|os)\s*:+\s*([^\n]{3,80})", text, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    # Standalone OS name in a bullet
    m = re.search(
        r"-\s+(?:Host\s+is\s+)?((?:Linux|Debian|Ubuntu|Windows\s+Server|CentOS|RHEL|FreeBSD)[^\n]{0,50})",
        text, re.IGNORECASE,
    )
    if m:
        return m.group(1).strip()
    return None


def _extract_structured_findings(text: str) -> list:
    """
    Parse 'Finding N: Title' sections from a security report (markdown or plain text).
    Each section becomes a rich vulnerability dict with severity, evidence, and recommendations.
    """
    findings: list = []
    seen_keys: set = set()
    matches = list(_FINDING_SECTION_RE.finditer(text))
    if not matches:
        return findings
    for i, m in enumerate(matches):
        title = m.group(1).strip()
        section_start = m.end()
        section_end   = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        section       = text[section_start:section_end]

        sev_m    = _SEV_IN_SECTION_RE.search(section)
        severity = _SEVERITY_MAP.get((sev_m.group(1) if sev_m else "").lower(), "UNKNOWN")

        svc_m        = _SVC_IN_SECTION_RE.search(section)
        service_desc = svc_m.group(1).strip() if svc_m else ""

        evi_m   = _EVI_IN_SECTION_RE.search(section)
        evidence = evi_m.group(1).strip()[:800] if evi_m else ""

        interp_m      = _INTERP_IN_SECTION_RE.search(section)
        interpretation = interp_m.group(1).strip()[:800] if interp_m else ""

        rec_m           = _REC_IN_SECTION_RE.search(section)
        recommendations = rec_m.group(1).strip()[:800] if rec_m else ""

        desc_parts = []
        if service_desc:
            desc_parts.append(f"Service: {service_desc}")
        if interpretation:
            desc_parts.append(interpretation)
        elif evidence:
            desc_parts.append(evidence[:400])
        description = "\n\n".join(desc_parts)[:800]

        key = re.sub(r"\W+", "", title.lower())[:80]
        if key in seen_keys:
            continue
        seen_keys.add(key)

        findings.append({
            "cve_id":         None,
            "title":          title[:200],
            "severity":       severity,
            "description":    description or None,
            "evidence":       evidence[:600] if evidence else None,
            "recommendation": recommendations[:600] if recommendations else None,
            "source":         "ai_analysis",
        })
    return findings


def _extract_suggested_tools_from_report(text: str) -> list:
    """Extract suggested tool list from the 'Additional Tools Not Installed' section."""
    section_m = _TOOLS_SECTION_RE.search(text)
    if not section_m:
        return []
    section = section_m.group(1)
    tools: list = []
    seen: set   = set()
    # Each tool appears as a name line followed by a description line (numbered list)
    tool_block_re = re.compile(
        r"(?:^\d+\.\s+|\n\d+\.\s+|\n-\s+|\n\*\s+)?\*{0,2}([a-zA-Z0-9_\-]{2,30})\*{0,2}\s*\n+\s*([^\n]{10,200})",
        re.MULTILINE,
    )
    for tm in tool_block_re.finditer(section):
        name   = tm.group(1).strip()
        reason = tm.group(2).strip()
        if name.lower() in ("useful", "provides", "helpful", "valuable", "this", "the", "and"):
            continue
        if name.lower() not in seen:
            seen.add(name.lower())
            tools.append({"name": name, "reason": reason})
    if not tools:
        # Fallback: bold/code tool names
        for name_m in re.finditer(r"(?:\*\*|``)([a-zA-Z0-9_\-]{2,30})(?:\*\*|``)", section):
            name = name_m.group(1)
            if name.lower() not in seen:
                seen.add(name.lower())
                tools.append({"name": name, "reason": ""})
    return tools


def _extract_suggestions_from_turns(turns: list) -> list:
    """Collect deduplicated suggested_tools from all conversation turns."""
    seen: set = set()
    out = []
    for turn in turns:
        for tool in turn.get("suggested_tools") or []:
            name = (tool.get("name") or "").strip()
            if name and name not in seen:
                seen.add(name)
                out.append({"name": name, "reason": tool.get("reason", "")})
    return out


def _extract_final_report(turns: list) -> str:
    """Return the final_report string from the last complete turn."""
    for turn in reversed(turns):
        if turn.get("status") == "complete" and turn.get("final_report"):
            return turn["final_report"]
        # Fallback: last turn with any analysis
        if turn.get("final_report"):
            return turn["final_report"]
    # If no explicit final_report, return the last analysis block
    for turn in reversed(turns):
        if turn.get("analysis"):
            return turn["analysis"]
    return ""


def _extract_target_from_turns(turns: list) -> str:
    """Try to guess the scan target from the first user message."""
    for turn in turns:
        analysis = turn.get("analysis") or turn.get("command_explanation") or ""
        m = re.search(r"(?:target|host|ip)[:\s]+(\d{1,3}(?:\.\d{1,3}){3}(?:/\d+)?)", analysis, re.IGNORECASE)
        if m:
            return m.group(1).strip()
        # Also check in command
        cmd = turn.get("command") or ""
        m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3}(?:/\d+)?)", cmd)
        if m:
            return m.group(1).strip()
    return ""


def _severity_from_context(text: str) -> str:
    """Guess severity from surrounding text."""
    ltext = text.lower()
    for kw, sev in _SEVERITY_MAP.items():
        if kw in ltext:
            return sev
    return "UNKNOWN"


def _extract_vulns_from_report(report_md: str, target: str) -> list:
    """
    Build a rich list of vulnerability dicts from the AI's markdown report.

    Priority:
      1. Structured 'Finding N:' sections (title + severity + evidence + recommendations)
      2. Remaining CVE IDs not already inside a captured finding
      3. Fallback bold/heading patterns when no structured findings exist
    """
    if not report_md:
        return []

    vulns: list      = []
    seen_titles: set = set()

    # 1. Structured findings (primary extraction path)
    structured = _extract_structured_findings(report_md)
    for f in structured:
        vulns.append(f)
        seen_titles.add(re.sub(r"\W+", "", (f["title"] or "").lower())[:80])

    # 2. CVE IDs not already inside a structured finding
    seen_cves: set = set()
    for line in report_md.splitlines():
        for cve_id in _CVE_RE.findall(line):
            cve_upper = cve_id.upper()
            if cve_upper in seen_cves:
                continue
            seen_cves.add(cve_upper)
            sev = _severity_from_context(line)
            vulns.append({
                "cve_id":      cve_upper,
                "title":       cve_upper,
                "severity":    sev,
                "description": line.strip()[:400],
                "source":      "ai_analysis",
            })

    # 3. Fallback bold/heading findings (only when no structured sections found)
    if not structured:
        for pat in (_VULN_PATTERNS[1], _VULN_PATTERNS[2]):
            for m in pat.finditer(report_md):
                title = m.group(1).strip()
                if _CVE_RE.search(title):
                    continue
                key = re.sub(r"\W+", "", title.lower())[:80]
                if key in seen_titles:
                    continue
                seen_titles.add(key)
                context = report_md[max(0, m.start() - 200): m.end() + 200]
                sev = _severity_from_context(context)
                vulns.append({
                    "cve_id":      None,
                    "title":       title[:200],
                    "severity":    sev,
                    "description": context.strip()[:400],
                    "source":      "ai_analysis",
                })

    return vulns


def parse_autorecon_ai_conversation(conversation_path: str, target: str = "") -> dict:
    """
    Parse an ai_scan/conversation.json file.

    :param conversation_path: absolute path to conversation.json
    :param target: known scan target (IP/domain) — used to build the host record
    :returns: {hosts, error, ai_scan_data}
    """
    try:
        with open(conversation_path, "r", encoding="utf-8") as f:
            turns = json.load(f)
    except Exception as exc:
        return {"hosts": [], "error": f"Cannot read conversation.json: {exc}", "ai_scan_data": {}}

    if not isinstance(turns, list):
        return {"hosts": [], "error": "conversation.json: expected a JSON array", "ai_scan_data": {}}

    suggested_tools = _extract_suggestions_from_turns(turns)
    final_report    = _extract_final_report(turns)
    iterations      = len(turns)

    # Try to infer target if not provided
    if not target:
        target = _extract_target_from_turns(turns)

    vulns    = _extract_vulns_from_report(final_report, target)
    ports    = _extract_ports_from_report(final_report)
    hostname = _extract_hostname_from_report(final_report)
    os_info  = _extract_os_from_report(final_report)

    hosts: list = []
    if target:
        hosts.append({
            "ip":              target,
            "hostname":        hostname,
            "os_info":         os_info,
            "vulnerabilities": vulns,
            "ports":           ports,
            "http_pages":      [],
            "extra_data":      {},
        })

    ai_scan_data = {
        "ai_report_md":    final_report,
        "suggested_tools": suggested_tools,
        "iterations":      iterations,
    }
    return {"hosts": hosts, "error": None, "ai_scan_data": ai_scan_data}


def parse_autorecon_ai_directory(ai_dir: str, target: str = "") -> dict:
    """
    Parse a full ai_scan/ directory.

    :param ai_dir: path to the ai_scan/ directory
    :param target: known scan target
    :returns: {hosts, error, ai_scan_data}
    """
    conv_path   = os.path.join(ai_dir, "conversation.json")
    report_path = os.path.join(ai_dir, "ai_report.md")
    tools_path  = os.path.join(ai_dir, "suggested_tools.json")

    result: dict = {"hosts": [], "error": None, "ai_scan_data": {}}

    # --- conversation.json ---
    if os.path.isfile(conv_path):
        result = parse_autorecon_ai_conversation(conv_path, target)
    else:
        result["ai_scan_data"] = {}

    # --- ai_report.md (authoritative report — extract all rich data) ---
    if os.path.isfile(report_path):
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                md = f.read()
            result["ai_scan_data"]["ai_report_md"] = md

            # If target still unknown, try to find it in the report
            if not target:
                tm = re.search(
                    r"(?:Target|Host|IP)[:\s*`]+`?(\d{1,3}(?:\.\d{1,3}){3})`?",
                    md, re.IGNORECASE,
                )
                if tm:
                    target = tm.group(1)

            report_ports    = _extract_ports_from_report(md)
            report_hostname = _extract_hostname_from_report(md)
            report_os       = _extract_os_from_report(md)
            report_vulns    = _extract_vulns_from_report(md, target)

            existing_host = next(
                (h for h in result["hosts"] if h.get("ip") == target), None
            ) if target else None

            if existing_host is None and target:
                existing_host = {
                    "ip":              target,
                    "hostname":        report_hostname,
                    "os_info":         report_os,
                    "vulnerabilities": [],
                    "ports":           [],
                    "http_pages":      [],
                    "extra_data":      {},
                }
                result["hosts"].append(existing_host)

            if existing_host:
                # Fill hostname / OS only when missing
                if not existing_host.get("hostname") and report_hostname:
                    existing_host["hostname"] = report_hostname
                if not existing_host.get("os_info") and report_os:
                    existing_host["os_info"] = report_os
                # Merge ports (avoid duplicates)
                existing_port_keys = {
                    (p["port"], p["protocol"]) for p in existing_host.get("ports", [])
                }
                for p in report_ports:
                    key = (p["port"], p["protocol"])
                    if key not in existing_port_keys:
                        existing_host.setdefault("ports", []).append(p)
                        existing_port_keys.add(key)
                # Merge vulnerabilities
                seen_titles = {v["title"] for v in existing_host.get("vulnerabilities", [])}
                for v in report_vulns:
                    if v["title"] not in seen_titles:
                        existing_host["vulnerabilities"].append(v)
                        seen_titles.add(v["title"])
        except Exception:
            pass

    # --- suggested_tools.json (or fall back to extracting from the report text) ---
    if os.path.isfile(tools_path):
        try:
            with open(tools_path, "r", encoding="utf-8") as f:
                tools = json.load(f)
            if isinstance(tools, list):
                result["ai_scan_data"]["suggested_tools"] = tools
        except Exception:
            pass
    elif not result["ai_scan_data"].get("suggested_tools"):
        md = result["ai_scan_data"].get("ai_report_md", "")
        if md:
            tools_from_report = _extract_suggested_tools_from_report(md)
            if tools_from_report:
                result["ai_scan_data"]["suggested_tools"] = tools_from_report

    return result
