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
    re.compile(r"\*\*\s*(?:Finding|Vulnerability|Issue|Risk)[:\s]+([^\*\n]+)\*\*", re.IGNORECASE),
    # "### CVE-…" or "## Finding …" markdown headings
    re.compile(r"^#{2,4}\s+(CVE-\d{4}-\d{4,7}[^\n]*)", re.MULTILINE),
]


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
    Build a minimal list of vulnerability dicts from the AI's markdown report.
    We match CVE IDs and bold/heading findings with heuristic severity.
    """
    vulns = []
    seen_cves: set = set()

    if not report_md:
        return vulns

    # Walk line by line to find CVE mentions
    for line in report_md.splitlines():
        for cve_id in _CVE_RE.findall(line):
            cve_upper = cve_id.upper()
            if cve_upper in seen_cves:
                continue
            seen_cves.add(cve_upper)
            sev = _severity_from_context(line)
            vulns.append({
                "cve_id": cve_upper,
                "title": cve_upper,
                "severity": sev,
                "description": line.strip()[:400],
                "source": "ai_analysis",
            })

    # Walk for bold/heading findings (non-CVE)
    for pat in (_VULN_PATTERNS[1], _VULN_PATTERNS[2]):
        for m in pat.finditer(report_md):
            title = m.group(1).strip()
            if _CVE_RE.search(title):
                continue  # already captured above
            context = report_md[max(0, m.start() - 200): m.end() + 200]
            sev = _severity_from_context(context)
            vulns.append({
                "cve_id": None,
                "title": title[:200],
                "severity": sev,
                "description": context.strip()[:400],
                "source": "ai_analysis",
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

    vulns = _extract_vulns_from_report(final_report, target)

    hosts: list = []
    if target:
        hosts.append({
            "ip": target,
            "vulnerabilities": vulns,
            "ports": [],
            "http_pages": [],
            "extra_data": {},
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

    # --- ai_report.md (preferred over conversation-derived report) ---
    if os.path.isfile(report_path):
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                md = f.read()
            result["ai_scan_data"]["ai_report_md"] = md
            # Re-extract vulns from the dedicated report file
            if target:
                vulns = _extract_vulns_from_report(md, target)
                for h in result["hosts"]:
                    if h.get("ip") == target:
                        seen_titles = {v["title"] for v in h.get("vulnerabilities", [])}
                        for v in vulns:
                            if v["title"] not in seen_titles:
                                h["vulnerabilities"].append(v)
                        break
        except Exception:
            pass

    # --- suggested_tools.json ---
    if os.path.isfile(tools_path):
        try:
            with open(tools_path, "r", encoding="utf-8") as f:
                tools = json.load(f)
            if isinstance(tools, list):
                result["ai_scan_data"]["suggested_tools"] = tools
        except Exception:
            pass

    return result
