"""
Parse Lynis audit output files.

Supports two formats:
  - lynis.log      : human-readable verbose log (produced by --log-file)
  - lynis-report.dat : machine-readable key=value report

Both formats require a ``target_ip`` argument because Lynis runs locally on the
audited machine and includes no network address in its output.

Returns the standard {"hosts": [...], "error": None|str} structure expected by
_persist_parsed_data.
"""
import re
import json

# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

# Lynis warning/suggestion keywords → severity
_WARN_RE   = re.compile(r"\bWARNING\b|\bCRITICAL\b|\bDANGER\b",   re.IGNORECASE)
_SUGG_RE   = re.compile(r"\bSUGGESTION\b|\bINFO\b|\bNotice\b",    re.IGNORECASE)
_CVE_RE    = re.compile(r"CVE-\d{4}-\d{4,7}",                      re.IGNORECASE)


def _severity_from_text(text: str) -> str:
    if _WARN_RE.search(text):
        return "HIGH"
    if _SUGG_RE.search(text):
        return "INFO"
    return "MEDIUM"


# ---------------------------------------------------------------------------
# Lynis test-ID → human-readable category
# ---------------------------------------------------------------------------
_CATEGORY_MAP: dict[str, str] = {
    "AUTH": "Authentication",
    "BOOT": "Boot",
    "CONT": "Containers",
    "CRYP": "Cryptography",
    "FILE": "File Systems",
    "FIRE": "Firewall",
    "HRDN": "System Hardening",
    "HTTP": "Web Server",
    "INTR": "Intrusion Detection",
    "KRNL": "Kernel",
    "LDAP": "LDAP",
    "LOGG": "Logging",
    "MAIL": "Mail",
    "MALF": "Malware Detection",
    "NAME": "DNS",
    "NETW": "Network",
    "NTP":  "NTP",
    "OS":   "Operating System",
    "PAM":  "PAM",
    "PHP":  "PHP",
    "PKGS": "Package Management",
    "PRNT": "Printers",
    "PROC": "Processes / Kernel",
    "SCHD": "Scheduled Tasks",
    "SHLL": "Shells",
    "SNMP": "SNMP",
    "SQL":  "Databases",
    "SSH":  "SSH",
    "STRG": "Storage",
    "TOOL": "System Tools",
    "UPDT": "Updates",
    "USB":  "USB",
    "USER": "Users",
}


def _category(test_id: str) -> str:
    prefix = test_id[:4].upper()
    return _CATEGORY_MAP.get(prefix, "System Audit")


def _build_recommendation(test_id: str, solution: str, description: str = "", details: str = "") -> str:
    """Always return a non-empty recommendation string.
    Uses the explicit Lynis solution when available, otherwise builds a guide
    from the test category and links to the CISOfy online controls database.
    """
    parts = []
    if solution:
        parts.append(solution)
    else:
        cat = _category(test_id)
        if description:
            parts.append(f"Review and address: {description}")
        if details:
            parts.append(f"Details: {details}")
        if not parts:
            parts.append(f"Investigate the {cat} configuration.")
    if test_id:
        parts.append(f"\nLynis reference: https://cisofy.com/lynis/controls/{test_id}/")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# lynis-report.dat parser
# ---------------------------------------------------------------------------

def parse_lynis_report(file_path: str, target_ip: str) -> dict:
    """Parse a lynis-report.dat (key=value) file."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
    except OSError as exc:
        return {"hosts": [], "error": str(exc)}

    # ── Parse key=value pairs (handle list entries: key[]=value) ────────────
    data: dict[str, list[str]] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip()
        data.setdefault(key, []).append(val)

    def first(k: str, default: str = "") -> str:
        return data.get(k, [default])[0]

    def values(k: str) -> list[str]:
        return data.get(k, [])

    # ── Host metadata ─────────────────────────────────────────────────────────
    hostname   = first("hostname")
    os_name    = first("os_name")
    os_version = first("os_version")
    os_info    = f"{os_name} {os_version}".strip() if os_name else None
    kernel     = first("os_kernel_version_full") or first("os_kernel_version")

    # ── Warnings ──────────────────────────────────────────────────────────────
    vulns: list[dict] = []

    for raw_warn in values("warning[]"):
        # Format: TEST-ID|Description|Details|Solution
        parts = [p.strip() for p in raw_warn.split("|")]
        if not parts:
            continue
        test_id     = parts[0]
        description = parts[1] if len(parts) > 1 else test_id
        details     = parts[2] if len(parts) > 2 else ""
        solution    = parts[3] if len(parts) > 3 else ""

        cve_matches = _CVE_RE.findall(description + " " + details)
        cve_id      = cve_matches[0].upper() if cve_matches else None

        full_desc = description
        if details:
            full_desc += f"\nDetails: {details}"
        if kernel:
            full_desc += f"\nKernel: {kernel}"

        vulns.append({
            "cve_id":      cve_id,
            "title":       f"[{test_id}] {description}"[:300],
            "severity":    "HIGH",
            "description": full_desc,
            "recommendation": _build_recommendation(test_id, solution, description, details),
            "evidence":    f"Lynis test {test_id} — {_category(test_id)}",
            "source":      "lynis",
        })

    # ── Suggestions ───────────────────────────────────────────────────────────
    for raw_sugg in values("suggestion[]"):
        # Format: TEST-ID|Description|Details|Solution
        parts = [p.strip() for p in raw_sugg.split("|")]
        if not parts:
            continue
        test_id     = parts[0]
        description = parts[1] if len(parts) > 1 else test_id
        details     = parts[2] if len(parts) > 2 else ""
        solution    = parts[3] if len(parts) > 3 else ""

        cve_matches = _CVE_RE.findall(description + " " + details)
        cve_id      = cve_matches[0].upper() if cve_matches else None

        full_desc = description
        if details:
            full_desc += f"\nDetails: {details}"

        vulns.append({
            "cve_id":      cve_id,
            "title":       f"[{test_id}] {description}"[:300],
            "severity":    "LOW",
            "description": full_desc,
            "recommendation": _build_recommendation(test_id, solution, description, details),
            "evidence":    f"Lynis test {test_id} — {_category(test_id)}",
            "source":      "lynis",
        })

    # ── Hardening index as an INFO finding ────────────────────────────────────
    hardening_index = first("hardening_index")
    if hardening_index:
        vulns.append({
            "cve_id":      None,
            "title":       f"Lynis hardening index: {hardening_index}/100",
            "severity":    "INFO",
            "description": (
                f"Lynis calculated a hardening index of {hardening_index}/100 "
                f"for {hostname or target_ip}.\n"
                f"OS: {os_info or 'unknown'}\n"
                f"Kernel: {kernel or 'unknown'}"
            ),
            "evidence":    "lynis-report.dat / hardening_index",
            "source":      "lynis",
        })

    host = {
        "ip":          target_ip,
        "hostname":    hostname or None,
        "os_info":     os_info,
        "mac_address": None,
        "mac_vendor":  None,
        "ports":       [],
        "vulnerabilities": vulns,
        "http_pages":  [],
    }
    return {"hosts": [host], "error": None}


# ---------------------------------------------------------------------------
# lynis.log parser
# ---------------------------------------------------------------------------

# Matches lines produced by Lynis WARNING/SUGGESTION result entries
# e.g.:
#   2026-03-26 09:53:39 Result: WARNING (SSH-7408)
#   2026-03-26 09:53:39 Test: Checking PermitRootLogin ... Result: WARNING
_LOG_RESULT_RE = re.compile(
    r"Result:\s*(WARNING|SUGGESTION|OK|FOUND|NOT_FOUND|MANUAL)[^\n]*",
    re.IGNORECASE,
)
_LOG_WARN_BLOCK_RE = re.compile(
    r"\*\s*(WARNING):\s*(.*?)(?:\n|$)",
    re.IGNORECASE,
)
_LOG_SUGG_BLOCK_RE = re.compile(
    r"\*\s*(Suggestion):\s*(.*?)(?:\n|$)",
    re.IGNORECASE,
)

# Pattern that matches individual test result lines in lynis.log
# e.g. "  - Test: SSH-7408 ... Result: WARNING"
_TEST_LINE_RE = re.compile(
    r"Test:\s*(.+?)\s+\.\.\.\s+Result:\s*(WARNING|SUGGESTION|OK|MANUAL|FOUND|NOT_FOUND)",
    re.IGNORECASE,
)

# Pattern for the [ WARNING ] lines that appear in the summary section
# e.g.  "  * WARNING: PermitRootLogin not disabled [test:SSH-7408]"
_WARN_SUMMARY_RE = re.compile(
    r"\*\s*(?:WARNING|DANGER):\s*(.+?)(?:\s+\[test:([A-Z0-9-]+)\])?\s*$",
    re.IGNORECASE,
)
_SUGG_SUMMARY_RE = re.compile(
    r"\*\s*Suggestion:\s*(.+?)(?:\s+\[test:([A-Z0-9-]+)\])?\s*$",
    re.IGNORECASE,
)

# Header line that contains hostname/OS info in the log
_HOSTNAME_RE = re.compile(r"Hostname:\s+(.+)", re.IGNORECASE)
_OS_RE       = re.compile(r"Operating system(?: name)?:\s+(.+)", re.IGNORECASE)
_OS_VER_RE   = re.compile(r"Operating system version:\s+(.+)", re.IGNORECASE)
_KERNEL_RE   = re.compile(r"Kernel version.*?:\s+(.+)", re.IGNORECASE)


def parse_lynis_log(file_path: str, target_ip: str) -> dict:
    """Parse a lynis.log verbose log file."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
    except OSError as exc:
        return {"hosts": [], "error": str(exc)}

    # ── Extract metadata from header ─────────────────────────────────────────
    hostname   = None
    os_name    = None
    os_version = None
    kernel     = None

    for line in raw.splitlines():
        line_clean = line.strip()
        if not hostname:
            m = _HOSTNAME_RE.search(line_clean)
            if m:
                hostname = m.group(1).strip()
        if not os_name:
            m = _OS_RE.search(line_clean)
            if m:
                os_name = m.group(1).strip()
        if not os_version:
            m = _OS_VER_RE.search(line_clean)
            if m:
                os_version = m.group(1).strip()
        if not kernel:
            m = _KERNEL_RE.search(line_clean)
            if m:
                kernel = m.group(1).strip()

    os_info = f"{os_name} {os_version}".strip() if os_name else None

    # ── Extract findings from log body ────────────────────────────────────────
    # Lynis log lines have format: "YYYY-MM-DD HH:MM:SS <text>"
    # Strip the timestamp prefix for matching.
    _TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} ")

    def strip_ts(line: str) -> str:
        return _TS_RE.sub("", line).strip()

    lines = raw.splitlines()
    stripped = [strip_ts(l) for l in lines]

    vulns: list[dict] = []
    seen_titles: set[str] = set()

    # Strategy: scan for WARNING / SUGGESTION result lines.
    # Lynis logs look like:
    #   "Result: WARNING"  preceded by "Test: ..."  or  "Performing tests..."
    # We use a sliding-window approach: when we see a WARNING/SUGGESTION result,
    # look back a few lines for the test name / description.
    for i, ls in enumerate(stripped):
        sev = None
        if re.search(r"\bResult:\s*WARNING\b", ls, re.IGNORECASE):
            sev = "HIGH"
        elif re.search(r"\bResult:\s*SUGGESTION\b", ls, re.IGNORECASE):
            sev = "LOW"
        else:
            continue

        # Look back up to 10 lines for "Test: <name>"
        test_id   = None
        test_desc = None
        for j in range(max(0, i - 10), i):
            m = re.search(r"Test:\s*(.+)", stripped[j], re.IGNORECASE)
            if m:
                test_desc = m.group(1).strip()
                # Try to extract test ID like SSH-7408 from description
                tid_match = re.search(r"\b([A-Z]{2,6}-\d{4})\b", test_desc)
                if tid_match:
                    test_id = tid_match.group(1)
                break

        # Also scan forward 3 lines for detail
        detail_lines = []
        for j in range(i + 1, min(len(stripped), i + 4)):
            if stripped[j] and not re.search(r"^(Test:|Result:|====|Skipping)", stripped[j]):
                detail_lines.append(stripped[j])

        title = f"[{test_id}] {test_desc}" if test_id and test_desc else (test_desc or ls[:200])
        title = title[:300]

        if title in seen_titles:
            continue
        seen_titles.add(title)

        description = test_desc or ""
        if kernel:
            description += f"\nKernel: {kernel}"
        if detail_lines:
            description += "\n" + "\n".join(detail_lines[:2])

        cve_matches = _CVE_RE.findall(description)
        cve_id = cve_matches[0].upper() if cve_matches else None

        vulns.append({
            "cve_id":      cve_id,
            "title":       title,
            "severity":    sev,
            "description": description.strip(),
            "recommendation": _build_recommendation(test_id or "", "", test_desc or ""),
            "evidence":    f"Lynis result{(' — '+_category(test_id)) if test_id else ''}",
            "source":      "lynis",
        })

    # ── Fallback: scan summary WARNING/SUGGESTION bullets ────────────────────
    # These appear in the "Lynis Results" section near the end of the log.
    for ls in stripped:
        for pattern, sev in ((_WARN_SUMMARY_RE, "HIGH"), (_SUGG_SUMMARY_RE, "LOW")):
            m = pattern.match(ls)
            if m:
                desc    = m.group(1).strip()
                test_id = m.group(2) if m.lastindex >= 2 and m.group(2) else None
                title   = f"[{test_id}] {desc}" if test_id else desc
                title   = title[:300]
                if title not in seen_titles:
                    seen_titles.add(title)
                    cve_matches = _CVE_RE.findall(desc)
                    cve_id = cve_matches[0].upper() if cve_matches else None
                    vulns.append({
                        "cve_id":      cve_id,
                        "title":       title,
                        "severity":    sev,
                        "description": desc,
                        "recommendation": _build_recommendation(test_id or "", "", desc),
                        "evidence":    f"Lynis summary{(' — '+_category(test_id)) if test_id else ''}",
                        "source":      "lynis",
                    })

    if not vulns:
        # Produce at least an INFO finding so the file isn't silently empty
        vulns.append({
            "cve_id":      None,
            "title":       "Lynis audit completed — no warnings or suggestions extracted",
            "severity":    "INFO",
            "description": (
                "The Lynis log was parsed but no WARNING or SUGGESTION results "
                "were found. The system may be well-hardened, or the log may be "
                "incomplete.\n"
                f"OS: {os_info or 'unknown'}  Kernel: {kernel or 'unknown'}"
            ),
            "evidence":    "lynis.log",
            "source":      "lynis",
        })

    host = {
        "ip":          target_ip,
        "hostname":    hostname or None,
        "os_info":     os_info,
        "mac_address": None,
        "mac_vendor":  None,
        "ports":       [],
        "vulnerabilities": vulns,
        "http_pages":  [],
    }
    return {"hosts": [host], "error": None}
