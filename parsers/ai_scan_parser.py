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

# ── Regex helpers ──────────────────────────────────────────────────────────
_CVE_RE       = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_SEVERITY_MAP = {
    "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
    "low": "LOW", "info": "INFO", "informational": "INFO",
    # French
    "critique": "CRITICAL",
    "élevée": "HIGH", "élevé": "HIGH", "elevee": "HIGH", "elevé": "HIGH",
    "haute": "HIGH", "haut": "HIGH",
    "moyenne à élevée": "HIGH", "haute à élevée": "HIGH",
    "moyenne": "MEDIUM", "moyen": "MEDIUM",
    "faible": "LOW", "basse": "LOW", "bas": "LOW",
}

# ── Port extraction ────────────────────────────────────────────────────────
# "- `22/tcp` — OpenSSH 10.0p2 Debian 7"  or  "- 22/tcp — SSH"
_PORT_LINE_RE = re.compile(
    r"^\s*[-*\u2022]\s+`?(\d{1,5})/(tcp|udp)`?\s*[—–\-]{1,3}\s*(.+)",
    re.IGNORECASE | re.MULTILINE,
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

# ── Hostname / OS ──────────────────────────────────────────────────────────
_RESOLVED_NAME_RE = re.compile(
    r"Resolved\s+name\s*:+\s*\*{0,2}\s*`?([a-zA-Z0-9][a-zA-Z0-9._-]{1,})`?",
    re.IGNORECASE,
)
_HOSTNAME_LABEL_RE = re.compile(
    r"\b(?:hostname|fqdn|rdns|ptr)\b\s*:+\s*\*{0,2}\s*`?([a-zA-Z0-9][a-zA-Z0-9._-]{2,})`?",
    re.IGNORECASE,
)

# ── Tools section detection ────────────────────────────────────────────────
# Any top-level heading that talks about missing / recommended / suggested tools
_TOOLS_HEADING_RE = re.compile(
    r"^#{1,4}\s+(?:(?:Additional\s+)?Tools?\s+(?:Not\s+Installed|Recommended|Suggested|That\s+Would\s+Help)"
    r"|Outils?\s+[^\n]*)[^\n]*$",
    re.IGNORECASE | re.MULTILINE,
)

# ── Finding detection ──────────────────────────────────────────────────────
# 1. AutoRecon-AI primary format: ### [SEVERITY] - Title
#    e.g.  ### [CRITICAL] - Insecure credential storage
_SEV_HEADING_RE = re.compile(
    r"^#{1,4}\s+\[?(CRITICAL|HIGH|MEDIUM|LOW|INFO(?:RMATIONAL)?)\]?\s*[-–:]\s*(.+?)$",
    re.MULTILINE | re.IGNORECASE,
)

# 2. "Finding N: Title" (with or without leading #)
_FINDING_N_RE = re.compile(
    r"^#{0,4}\s*(?:Finding|Vuln(?:erability)?|Issue)\s+\d+\s*[:.)\s]\s*(.+?)$",
    re.MULTILINE | re.IGNORECASE,
)

# 3. Bold heading  **Finding: title**  or  **[HIGH] title**
_BOLD_FINDING_RE = re.compile(
    r"\*\*\s*(?:\[(?:CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s*[-–:]?\s*)?(.+?)\*\*",
    re.IGNORECASE,
)

# Sub-field labels inside a finding block
_SEV_LABEL_RE  = re.compile(
    r"\*{0,2}(?:Severit(?:y|é)|Gravit[eé])\*{0,2}\s*:+\s*\*{0,2}\s*([^\n\*]{1,50})",
    re.IGNORECASE,
)
_EVI_LABEL_RE  = re.compile(r"\*{0,2}(?:Evidence|Évidence)\*{0,2}\s*:+\s*\*{0,2}\s*([\s\S]+?)(?=\n\*{0,2}(?:Service|Severity|Gravit|Interpretation|Recommendation|$))", re.IGNORECASE)
_INTERP_RE     = re.compile(r"\*{0,2}Interpretation\*{0,2}\s*:+\s*\*{0,2}\s*([\s\S]+?)(?=\n\*{0,2}(?:Severity|Gravit|Recommendation|Finding|$))", re.IGNORECASE)
_REC_RE        = re.compile(r"\*{0,2}Recommendations?\*{0,2}\s*:+\s*\*{0,2}\s*([\s\S]+?)(?=\n#{1,4}\s|\Z)", re.IGNORECASE)

# ── French-format: Constat N — Title ────────────────────────────────────────
_CONSTAT_RE      = re.compile(
    r"^#{1,4}\s+Constat\s+\d+\s*[\u2014\u2013\-]\s*(.+?)$",
    re.MULTILINE | re.IGNORECASE,
)
_CONSTAT_HOST_RE = re.compile(
    r"\*{0,2}[Hh][oô]te?\*{0,2}\s*:+\s*`(\d{1,3}(?:\.\d{1,3}){3})`",
)
_IMPACT_RE = re.compile(
    r"\*{0,2}Impact\*{0,2}\s*:+\s*\*{0,2}\s*([^\n]+)",
    re.IGNORECASE,
)
_FRENCH_REC_RE = re.compile(
    r"\*{0,2}Recommandations?\*{0,2}\s*:+\s*\*{0,2}\s*([\s\S]+?)(?=\n#{1,4}\s|\Z)",
    re.IGNORECASE,
)

# ── False-positive guards ──────────────────────────────────────────────────
# Lines/headings that look like vulnerability headings but are NOT vuln titles
_PORT_HEADING_RE = re.compile(
    r"^\s*(?:\d+\.\s+)?(?:Port\s+)?\d{1,5}/(tcp|udp)\b",
    re.IGNORECASE,
)
_TOOL_HEADING_RE = re.compile(
    r"^`[a-zA-Z0-9_\-]+`\s*$",           # bare `` `toolname` ``
)
_SECTION_NOISE_RE = re.compile(
    r"^(?:Executive\s+Summary|Detailed\s+Findings?|Open\s+Ports?|Network\s+Services?|"
    r"Recommendations?|Conclusion|Appendix|Summary|Overview|Introduction|"
    r"Host\s+Information|Scan\s+Results?|Services?\s+(?:Detected|Found)|"
    r"Additional\s+Tools?|Tools?\s+(?:Not\s+Installed|Recommended))",
    re.IGNORECASE,
)


def _is_noise_title(title: str) -> bool:
    """Return True if the title is a section header, port line, or tool name — not a real vuln."""
    t = title.strip()
    if _SECTION_NOISE_RE.match(t):
        return True
    if _PORT_HEADING_RE.match(t):
        return True
    if _TOOL_HEADING_RE.match(t):
        return True
    # Numbered port entries: "1. Port 22/tcp — SSH" or "2. Port 4000/tcp"
    if re.match(r"^\d+\.\s+(?:Port\s+)?\d{1,5}/(tcp|udp)", t, re.IGNORECASE):
        return True
    # Pure tool names with backticks: "1. `zabbix_get`", "2. `ssh-audit`"
    if re.match(r"^\d+\.\s+`[a-zA-Z0-9_\-]+`\s*$", t):
        return True
    # Very short (< 8 chars) or very long (> 200 chars) — skip
    if len(t) < 8 or len(t) > 200:
        return True
    return False


def _normalise_key(title: str) -> str:
    """Normalise a title for deduplication.

    Strips port numbers, port/tcp/udp references, and punctuation so that
    near-duplicate titles like "SSH exposed on port 22" and "SSH exposed on
    22/tcp" both collapse to the same key.
    """
    t = title.lower()
    # Remove port references: "port 22", "22/tcp", "22/udp", "on port 22"
    t = re.sub(r"\bport\s+\d+\b", "", t)
    t = re.sub(r"\b\d{1,5}/(tcp|udp)\b", "", t)
    t = re.sub(r"\bon\s+\d+\b", "", t)
    return re.sub(r"\W+", "", t)[:80]


def _sev_from_label(text: str) -> str:
    m = _SEV_LABEL_RE.search(text)
    if m:
        raw = m.group(1).strip().lower()
        # Try direct map
        direct = _SEVERITY_MAP.get(raw)
        if direct:
            return direct
        # Try substring match (handles "Moyenne \u00e0 \u00e9lev\u00e9e" etc.)
        for kw, sev in sorted(_SEVERITY_MAP.items(), key=lambda x: -len(x[0])):
            if kw in raw:
                return sev
    return "UNKNOWN"


def _sev_from_context(text: str) -> str:
    ltext = text.lower()
    for kw, sev in sorted(_SEVERITY_MAP.items(), key=lambda x: -len(x[0])):
        if kw in ltext:
            return sev
    return "UNKNOWN"


# ── Tools-section boundary detection ──────────────────────────────────────

def _tools_section_spans(text: str) -> list:
    """Return list of (start, end) byte spans that belong to tool-listing sections."""
    seen_starts: set = set()
    candidates = []
    for m in _TOOLS_HEADING_RE.finditer(text):
        if m.start() not in seen_starts:
            seen_starts.add(m.start())
            candidates.append(m)
    spans = []
    for m in candidates:
        level = len(re.match(r"^(#{1,4})", m.group()).group(1))
        rest  = text[m.end():]
        end_m = re.search(r"^#{1," + str(level) + r"}\s", rest, re.MULTILINE)
        end   = m.end() + (end_m.start() if end_m else len(rest))
        spans.append((m.start(), end))
    return spans


def _in_tools_section(pos: int, spans: list) -> bool:
    return any(s <= pos < e for s, e in spans)


# ── Primary extraction: [SEVERITY] headings ───────────────────────────────

def _extract_severity_headed_findings(text: str, tools_spans: list) -> list:
    """
    Extract findings from ``### [HIGH] - Title`` style headings.
    This is the primary format produced by the AutoRecon AI engine.
    """
    findings = []
    seen: set = set()
    matches = list(_SEV_HEADING_RE.finditer(text))
    for i, m in enumerate(matches):
        if _in_tools_section(m.start(), tools_spans):
            continue
        raw_sev = m.group(1).upper()
        severity = _SEVERITY_MAP.get(raw_sev.lower(), "UNKNOWN")
        title = m.group(2).strip()
        if _is_noise_title(title):
            continue

        # Section body = text until the next same-or-higher level heading
        level = len(re.match(r"^(#{1,4})", m.group()).group(1))
        section_start = m.end()
        # Find next heading of same or higher level
        rest = text[section_start:]
        next_heading = re.search(r"^#{1," + str(level) + r"}\s", rest, re.MULTILINE)
        section_body = rest[:next_heading.start()] if next_heading else rest

        # Try to extract sub-fields from section body
        evi_m    = _EVI_LABEL_RE.search(section_body)
        evidence = evi_m.group(1).strip()[:600] if evi_m else ""
        interp_m = _INTERP_RE.search(section_body)
        interp   = interp_m.group(1).strip()[:600] if interp_m else ""
        rec_m    = _REC_RE.search(section_body)
        rec      = rec_m.group(1).strip()[:600] if rec_m else ""

        # Override severity from inline label if present
        inline_sev = _sev_from_label(section_body)
        if inline_sev != "UNKNOWN":
            severity = inline_sev

        description = (interp or evidence or "")[:600] or None

        key = _normalise_key(title)
        if key in seen:
            continue
        seen.add(key)
        findings.append({
            "cve_id":         None,
            "title":          title[:200],
            "severity":       severity,
            "description":    description,
            "evidence":       evidence[:600] if evidence else None,
            "recommendation": rec or None,
            "source":         "ai_analysis",
        })
    return findings


# ── Secondary extraction: "Finding N: Title" sections ─────────────────────

def _extract_finding_n_sections(text: str, tools_spans: list) -> list:
    findings = []
    seen: set = set()
    matches = list(_FINDING_N_RE.finditer(text))
    for i, m in enumerate(matches):
        if _in_tools_section(m.start(), tools_spans):
            continue
        title = m.group(1).strip()
        if _is_noise_title(title):
            continue
        section_start = m.end()
        section_end   = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        section       = text[section_start:section_end]

        severity    = _sev_from_label(section)
        if severity == "UNKNOWN":
            severity = _sev_from_context(m.group())

        evi_m    = _EVI_LABEL_RE.search(section)
        evidence = evi_m.group(1).strip()[:600] if evi_m else ""
        interp_m = _INTERP_RE.search(section)
        interp   = interp_m.group(1).strip()[:600] if interp_m else ""
        rec_m    = _REC_RE.search(section)
        rec      = rec_m.group(1).strip()[:600] if rec_m else ""
        description = (interp or evidence or "")[:600] or None

        key = _normalise_key(title)
        if key in seen:
            continue
        seen.add(key)
        findings.append({
            "cve_id":         None,
            "title":          title[:200],
            "severity":       severity,
            "description":    description,
            "evidence":       evidence[:600] if evidence else None,
            "recommendation": rec or None,
            "source":         "ai_analysis",
        })
    return findings


# ── CVE extraction (standalone, not inside a known finding) ───────────────

def _extract_cve_lines(text: str, seen_titles: set) -> list:
    """Extract CVE IDs from lines — skip ones already captured as findings."""
    vulns = []
    seen_cves: set = set()
    for line in text.splitlines():
        for cve_id in _CVE_RE.findall(line):
            cve_upper = cve_id.upper()
            if cve_upper in seen_cves or cve_upper in seen_titles:
                continue
            seen_cves.add(cve_upper)
            seen_titles.add(cve_upper)
            # Build a clean description: just the raw line, stripped of any
            # "n CVE-… | CVSS: … (POTENTIAL…)" noise injected by the NVD enricher
            clean_line = re.sub(
                r"\bn\s+CVE-\d{4}-\d{4,7}\s*\|[^\n]*", "", line
            ).strip()
            vulns.append({
                "cve_id":      cve_upper,
                "title":       cve_upper,
                "severity":    _sev_from_context(line),
                "description": clean_line[:400] if clean_line else None,
                "source":      "ai_analysis",
            })
    return vulns


# ── Public extraction entry point ─────────────────────────────────────────

def _extract_vulns_from_report(report_md: str, target: str) -> list:
    """
    Extract vulnerabilities from the AI final report markdown.

    Strategy (in priority order):
      1. ``### [SEVERITY] - Title`` headings  (AutoRecon AI primary format)
      2. ``Finding N: Title`` / ``Vulnerability N: Title`` sections
      3. Standalone CVE IDs not already captured
    Tools sections are skipped entirely so tool names never appear as vulns.
    Noise headings (ports, section titles) are filtered out.
    Duplicate titles (case-insensitive, normalised) are deduplicated.
    """
    if not report_md:
        return []

    tools_spans = _tools_section_spans(report_md)

    # Pass 1 — [SEVERITY] headings
    sev_findings = _extract_severity_headed_findings(report_md, tools_spans)

    # Pass 2 — Finding N sections (complementary, not overlapping)
    seen_keys = {_normalise_key(f["title"]) for f in sev_findings}
    n_findings = [
        f for f in _extract_finding_n_sections(report_md, tools_spans)
        if _normalise_key(f["title"]) not in seen_keys
    ]
    for f in n_findings:
        seen_keys.add(_normalise_key(f["title"]))

    all_findings = sev_findings + n_findings

    # Pass 3 — Standalone CVEs
    seen_titles = {_normalise_key(f["title"]) for f in all_findings}
    seen_titles.update({_normalise_key(f["cve_id"]) for f in all_findings if f.get("cve_id")})
    cve_vulns = _extract_cve_lines(report_md, seen_titles)

    return all_findings + cve_vulns


def _extract_constat_sections(text: str) -> list:
    """
    Extract ``### Constat N \u2014 Title`` findings from French-format AI reports.
    Returns findings with an extra ``host_ip`` key (may be None).
    """
    findings = []
    seen: set = set()
    matches = list(_CONSTAT_RE.finditer(text))
    for i, m in enumerate(matches):
        title = m.group(1).strip()
        if _is_noise_title(title):
            continue
        section_start = m.end()
        section_end   = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        section       = text[section_start:section_end]

        host_m  = _CONSTAT_HOST_RE.search(section)
        host_ip = host_m.group(1) if host_m else None

        severity = _sev_from_label(section)
        if severity == "UNKNOWN":
            severity = _sev_from_context(section)

        impact_m    = _IMPACT_RE.search(section)
        description = impact_m.group(1).strip()[:600] if impact_m else None

        rec_m = _FRENCH_REC_RE.search(section) or _REC_RE.search(section)
        rec   = rec_m.group(1).strip()[:600] if rec_m else None

        key = _normalise_key(title)
        if key in seen:
            continue
        seen.add(key)
        findings.append({
            "cve_id":         None,
            "title":          title[:200],
            "severity":       severity,
            "description":    description,
            "evidence":       None,
            "recommendation": rec,
            "source":         "ai_analysis",
            "host_ip":        host_ip,  # caller pops this
        })
    return findings

def _parse_port_service(desc: str, port: int) -> tuple:
    raw = re.sub(r"`", "", desc).strip()
    if re.match(r"tcpwrapped", raw, re.IGNORECASE):
        likely = re.search(r"/?(?:likely|probably)\s+(.+)", raw, re.IGNORECASE)
        if likely:
            hint = likely.group(1).strip()
            kw = hint.lower().split()[0]
            return (_PRODUCT_SVC_MAP.get(kw, kw), hint[:100], None)
        return (_PORT_SVC_MAP.get(port), None, None)
    service = _PORT_SVC_MAP.get(port)
    for kw, svc in _PRODUCT_SVC_MAP.items():
        if kw in raw.lower():
            service = svc
            break
    ver_m = re.search(
        r"\b(\d+\.\d+(?:\.\d+)?(?:[a-z]\d+)?(?:p\d+)?(?:\s+(?:Debian|Ubuntu|RHEL|CentOS)\s+\d+)?)\b",
        raw, re.IGNORECASE,
    )
    version = ver_m.group(1).strip() if ver_m else None
    product = re.sub(
        r"\s*(?:application|interface|service|server|agent|daemon|running)\s*$",
        "", raw, flags=re.IGNORECASE,
    ).strip()
    if version and product.endswith(version):
        product = product[: -len(version)].strip()
    product = product[:120] or None
    return (service, product, version)


def _extract_ports_from_report(text: str) -> list:
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
            "port": port_num, "protocol": proto, "service": service,
            "product": product, "version": version,
            "extra_info": None, "state": "open", "cpe": None,
        })
    return ports


def _extract_hostname_from_report(text: str) -> "str | None":
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
    m = re.search(
        r"host\s+(?:is|appears?\s+to\s+be)\s+(?:a\s+)?([A-Za-z][A-Za-z0-9\s\-\.]{2,50}?)"
        r"(?:\s+based|\s+system|\s*[.\n])",
        text, re.IGNORECASE,
    )
    if m:
        val = m.group(1).strip()
        if 3 < len(val) < 80:
            return val
    m = re.search(r"\b(?:operating\s+system|os)\s*:+\s*([^\n]{3,80})", text, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    m = re.search(
        r"-\s+(?:Host\s+is\s+)?((?:Linux|Debian|Ubuntu|Windows\s+Server|CentOS|RHEL|FreeBSD)[^\n]{0,50})",
        text, re.IGNORECASE,
    )
    if m:
        return m.group(1).strip()
    return None


def _extract_suggested_tools_from_report(text: str) -> list:
    """Extract suggested-tools list from the report's tool section."""
    spans = _tools_section_spans(text)
    if not spans:
        return []
    tools: list = []
    seen: set   = set()
    for start, end in spans:
        section = text[start:end]
        # Pattern A: ### `toolname`\nReason paragraph (French AI report style)
        for m in re.finditer(
            r"^#{1,4}\s+`([a-zA-Z0-9_\-]+)`[^\n]*\n[ \t]*([^\n#][^\n]{0,300})",
            section, re.MULTILINE,
        ):
            name   = m.group(1).strip()
            reason = m.group(2).strip()[:200]
            if not name or name.lower() in seen:
                continue
            seen.add(name.lower())
            tools.append({"name": name, "reason": reason})
        # Numbered items: "### 1. `toolname`\nReason: ..." or "1. **toolname** — reason"
        for m in re.finditer(
            r"(?:^#{1,4}\s+\d+\.\s+`?(\S+?)`?\s*\n([\s\S]+?)(?=^#{1,4}\s+\d+\.|\Z))"
            r"|(?:^\d+\.\s+\*{0,2}`?([a-zA-Z0-9_\-]+)`?\*{0,2}[^\n]*\n\s*([^\n]{10,200}))",
            section, re.MULTILINE,
        ):
            name   = (m.group(1) or m.group(3) or "").strip().strip("`")
            reason = (m.group(2) or m.group(4) or "").strip().split("\n")[0][:200]
            if not name or name.lower() in seen:
                continue
            seen.add(name.lower())
            tools.append({"name": name, "reason": reason})
    if not tools:
        # Fallback: backtick-quoted names inside tool sections
        for start, end in spans:
            for m in re.finditer(r"`([a-zA-Z0-9_\-]{2,30})`", text[start:end]):
                name = m.group(1)
                if name.lower() not in seen:
                    seen.add(name.lower())
                    tools.append({"name": name, "reason": ""})
    return tools


# ── Conversation helpers ───────────────────────────────────────────────────

def _extract_suggestions_from_turns(turns: list) -> list:
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
    for turn in reversed(turns):
        if turn.get("status") == "complete" and turn.get("final_report"):
            return turn["final_report"]
        if turn.get("final_report"):
            return turn["final_report"]
    for turn in reversed(turns):
        if turn.get("analysis"):
            return turn["analysis"]
    return ""


def _extract_target_from_turns(turns: list) -> str:
    for turn in turns:
        analysis = turn.get("analysis") or turn.get("command_explanation") or ""
        m = re.search(r"(?:target|host|ip)[:\s]+(\d{1,3}(?:\.\d{1,3}){3}(?:/\d+)?)", analysis, re.IGNORECASE)
        if m:
            return m.group(1).strip()
        cmd = turn.get("command") or ""
        m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3}(?:/\d+)?)", cmd)
        if m:
            return m.group(1).strip()
    return ""


# ── Public parse functions (interface unchanged) ───────────────────────────

def parse_autorecon_ai_conversation(conversation_path: str, target: str = "") -> dict:
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

    if not target:
        target = _extract_target_from_turns(turns)

    vulns    = _extract_vulns_from_report(final_report, target)
    ports    = _extract_ports_from_report(final_report)
    hostname = _extract_hostname_from_report(final_report)
    os_info  = _extract_os_from_report(final_report)

    hosts: list = []
    if target:
        hosts.append({
            "ip": target, "hostname": hostname, "os_info": os_info,
            "vulnerabilities": vulns, "ports": ports,
            "http_pages": [], "extra_data": {},
        })

    return {
        "hosts": hosts,
        "error": None,
        "ai_scan_data": {
            "ai_report_md":    final_report,
            "suggested_tools": suggested_tools,
            "iterations":      iterations,
        },
    }


def parse_autorecon_ai_directory(ai_dir: str, target: str = "") -> dict:
    conv_path   = os.path.join(ai_dir, "conversation.json")
    report_path = os.path.join(ai_dir, "ai_report.md")
    tools_path  = os.path.join(ai_dir, "suggested_tools.json")

    result: dict = {"hosts": [], "error": None, "ai_scan_data": {}}

    if os.path.isfile(conv_path):
        result = parse_autorecon_ai_conversation(conv_path, target)
    else:
        result["ai_scan_data"] = {}

    if os.path.isfile(report_path):
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                md = f.read()
            result["ai_scan_data"]["ai_report_md"] = md

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
                    "ip": target, "hostname": report_hostname, "os_info": report_os,
                    "vulnerabilities": [], "ports": [], "http_pages": [], "extra_data": {},
                }
                result["hosts"].append(existing_host)

            if existing_host:
                if not existing_host.get("hostname") and report_hostname:
                    existing_host["hostname"] = report_hostname
                if not existing_host.get("os_info") and report_os:
                    existing_host["os_info"] = report_os
                existing_port_keys = {(p["port"], p["protocol"]) for p in existing_host.get("ports", [])}
                for p in report_ports:
                    key = (p["port"], p["protocol"])
                    if key not in existing_port_keys:
                        existing_host.setdefault("ports", []).append(p)
                        existing_port_keys.add(key)
                # Replace conversation-derived vulns with richer report-derived ones
                # when report_vulns is non-empty (ai_report.md is authoritative)
                if report_vulns:
                    existing_host["vulnerabilities"] = report_vulns
                else:
                    seen_titles = {v["title"] for v in existing_host.get("vulnerabilities", [])}
                    for v in report_vulns:
                        if v["title"] not in seen_titles:
                            existing_host["vulnerabilities"].append(v)
                            seen_titles.add(v["title"])
        except Exception:
            pass

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


# ── Standalone file parsers (individual file upload without ZIP) ────────────

def parse_autorecon_ai_report_md(md_path: str, target: str = "") -> dict:
    """Parse a standalone ai_report.md file.
    Handles both single-host reports and multi-host/CIDR reports with
    per-host ``## H\u00f4te `IP` \u2014 `hostname``` sections.
    """
    try:
        with open(md_path, "r", encoding="utf-8") as f:
            md = f.read()
    except Exception as exc:
        return {"hosts": [], "error": f"Cannot read ai_report.md: {exc}", "ai_scan_data": {}}

    tools = _extract_suggested_tools_from_report(md)

    # ── Detect per-host sections: ## H\u00f4te `IP` [— `hostname`]
    host_section_re = re.compile(
        r"^#{1,3}\s+[Hh][o\u00f4]te?\s+`(\d{1,3}(?:\.\d{1,3}){3})`"
        r"(?:\s*[\u2014\u2013\-]+\s*`([^`]+)`)?[^\n]*$",
        re.MULTILINE,
    )
    host_matches = list(host_section_re.finditer(md))

    if host_matches:
        # ── Multi-host report ──
        host_by_ip: dict = {}
        hosts: list = []

        for i, m in enumerate(host_matches):
            ip       = m.group(1)
            hostname = m.group(2) if m.group(2) else None
            sec_end  = host_matches[i + 1].start() if i + 1 < len(host_matches) else len(md)
            section  = md[m.start():sec_end]

            ports   = _extract_ports_from_report(section)
            os_info = _extract_os_from_report(section)
            if not hostname:
                hostname = _extract_hostname_from_report(section)

            host = {
                "ip": ip, "hostname": hostname, "os_info": os_info,
                "vulnerabilities": [], "ports": ports,
                "http_pages": [], "extra_data": {},
            }
            hosts.append(host)
            host_by_ip[ip] = host

        # Distribute Constat findings to their respective host
        for constat in _extract_constat_sections(md):
            h_ip = constat.pop("host_ip", None)
            if h_ip and h_ip in host_by_ip:
                host_by_ip[h_ip]["vulnerabilities"].append(constat)
            else:
                for h in hosts:
                    h["vulnerabilities"].append(dict(constat))

        # Fallback: if no constats found, try generic extraction on each section
        if not any(h["vulnerabilities"] for h in hosts):
            for i, m in enumerate(host_matches):
                ip      = m.group(1)
                sec_end = host_matches[i + 1].start() if i + 1 < len(host_matches) else len(md)
                section = md[m.start():sec_end]
                vulns   = _extract_vulns_from_report(section, ip)
                host_by_ip[ip]["vulnerabilities"] = vulns

    else:
        # ── Single-host report ──
        if not target:
            tm = re.search(
                r"(?:Target|Host|IP|Cible)[:\s*`]+`?(\d{1,3}(?:\.\d{1,3}){3}(?:/\d+)?)`?",
                md, re.IGNORECASE,
            )
            if tm:
                target = tm.group(1).strip()

        vulns    = _extract_vulns_from_report(md, target)
        ports    = _extract_ports_from_report(md)
        hostname = _extract_hostname_from_report(md)
        os_info  = _extract_os_from_report(md)

        hosts = []
        if target:
            hosts.append({
                "ip": target, "hostname": hostname, "os_info": os_info,
                "vulnerabilities": vulns, "ports": ports,
                "http_pages": [], "extra_data": {},
            })

    return {
        "hosts": hosts,
        "error": None,
        "ai_scan_data": {
            "ai_report_md":    md,
            "suggested_tools": tools,
            "iterations":      0,
        },
    }


def parse_autorecon_ai_tools(tools_path: str) -> dict:
    """Parse a standalone suggested_tools.json file."""
    try:
        with open(tools_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except Exception as exc:
        return {"hosts": [], "error": f"Cannot read suggested_tools.json: {exc}", "ai_scan_data": {}}

    normalized: list = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                normalized.append({
                    "name":   item.get("name") or item.get("tool", ""),
                    "reason": item.get("reason") or item.get("description", ""),
                })
            elif isinstance(item, str):
                normalized.append({"name": item, "reason": ""})

    return {
        "hosts": [],
        "error": None,
        "ai_scan_data": {
            "ai_report_md":    "",
            "suggested_tools": normalized,
            "iterations":      0,
        },
    }

