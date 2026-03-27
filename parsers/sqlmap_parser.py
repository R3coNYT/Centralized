"""
Parser for AutoRecon / standalone sqlmap output files.

Supports two formats:

1. **Raw text** (``sqlmap_output.txt``) — captured sqlmap stdout/stderr.
   AutoRecon saves one per scanned URL under:
     results/<target>/sqlmap/<safe_url>/sqlmap_output.txt

2. **CSV results file** — produced by sqlmap's ``--results-file`` flag or by
   some wrappers that export findings as CSV.
   Expected header (order-insensitive): Target URL, Place, Parameter,
   Type, Title, Vector, Payload

Both formats produce CRITICAL Vulnerability records in Centralized.
A Target IP must be supplied (prompted in the upload UI).
"""
from __future__ import annotations

import csv
import re


def parse_sqlmap_txt(file_path: str, target_ip: str) -> dict:
    """
    Parse an AutoRecon sqlmap_output.txt file.

    Returns a Centralized-compatible result dict::

        {
            "hosts": [
                {
                    "ip": <target_ip>,
                    "vulnerabilities": [...],
                }
            ],
            "error": None
        }
    """
    target_ip = (target_ip or "").strip()
    if not target_ip:
        return {"hosts": [], "error": "A Target IP is required to import a sqlmap output file."}

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except Exception as exc:
        return {"hosts": [], "error": f"Cannot read file: {exc}"}

    vulnerabilities = _parse_findings(content)

    return {
        "hosts": [
            {
                "ip": target_ip,
                "vulnerabilities": vulnerabilities,
            }
        ],
        "error": None,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_findings(output: str) -> list[dict]:
    """Extract SQLi injection records from raw sqlmap output."""
    findings: list[dict] = []

    # Detect tested URL from sqlmap banner line: "testing URL 'http://...'"
    url_match = re.search(r"testing URL '([^']+)'", output, re.IGNORECASE)
    tested_url = url_match.group(1).strip() if url_match else ""

    # Detect back-end DBMS
    dbms_match = re.search(r"back-end DBMS:\s*(.+)", output, re.IGNORECASE)
    db_type = dbms_match.group(1).strip() if dbms_match else None

    # Parameter blocks: "Parameter: X (GET/POST/...)"
    param_blocks = re.findall(
        r"Parameter:\s+(\S+)\s+\((GET|POST|Cookie|User-Agent|.*?)\)(.*?)(?=Parameter:|$)",
        output,
        re.DOTALL | re.IGNORECASE,
    )

    for param, method, block in param_blocks:
        techs = re.findall(r"Type:\s*(.+)", block)
        titles = re.findall(r"Title:\s*(.+)", block)
        if not techs:
            continue

        technique = ", ".join(t.strip() for t in techs)
        title_str = titles[0].strip() if titles else "SQL injection confirmed by sqlmap"
        desc_parts = [f"Parameter: {param.strip()} ({method.strip().upper()})"]
        if db_type:
            desc_parts.append(f"DBMS: {db_type}")
        if tested_url:
            desc_parts.append(f"URL: {tested_url}")
        desc_parts.append(f"Technique: {technique}")

        findings.append({
            "title": f"SQL Injection — {param.strip()} ({method.strip().upper()})",
            "severity": "CRITICAL",
            "description": "\n".join(desc_parts),
            "evidence": title_str,
            "source": "sqlmap",
            "recommendation": (
                "Use parameterised queries / prepared statements. "
                "Never interpolate user input directly into SQL."
            ),
        })

    # If sqlmap found injectable parameters but none matched the regex above,
    # produce a generic finding based on the "is vulnerable" line.
    if not findings and re.search(r"is vulnerable", output, re.IGNORECASE):
        findings.append({
            "title": "SQL Injection detected by sqlmap",
            "severity": "CRITICAL",
            "description": (
                (f"Tested URL: {tested_url}\n" if tested_url else "")
                + (f"DBMS: {db_type}\n" if db_type else "")
                + "sqlmap confirmed injection but parameter details could not be parsed."
            ),
            "evidence": "sqlmap reported the target as vulnerable.",
            "source": "sqlmap",
            "recommendation": (
                "Use parameterised queries / prepared statements. "
                "Never interpolate user input directly into SQL."
            ),
        })

    return findings


# ---------------------------------------------------------------------------
# CSV format — sqlmap --results-file output
# ---------------------------------------------------------------------------

def parse_sqlmap_csv(file_path: str, target_ip: str) -> dict:
    """
    Parse a sqlmap CSV results file (produced by ``sqlmap --results-file``).

    Expected columns (order-insensitive):
        Target URL, Place, Parameter, Type, Title, Vector, Payload

    Returns a Centralized-compatible result dict.
    """
    target_ip = (target_ip or "").strip()
    if not target_ip:
        return {"hosts": [], "error": "A Target IP is required to import a sqlmap CSV file."}

    try:
        vulnerabilities = _parse_csv_findings(file_path)
    except Exception as exc:
        return {"hosts": [], "error": f"Cannot parse sqlmap CSV: {exc}"}

    return {
        "hosts": [{"ip": target_ip, "vulnerabilities": vulnerabilities}],
        "error": None,
    }


def _parse_csv_findings(file_path: str) -> list[dict]:
    """Read sqlmap --results-file CSV and return Vulnerability dicts."""
    findings: list[dict] = []
    with open(file_path, newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        # Normalise header names: strip whitespace, lower-case
        if reader.fieldnames is None:
            return findings
        reader.fieldnames = [h.strip().lower() for h in reader.fieldnames]
        for row in reader:
            # Map common column name variants
            param = (row.get("parameter") or row.get("param") or "").strip()
            place = (row.get("place") or row.get("method") or "").strip().upper()
            inj_type = (row.get("type") or "").strip()
            title = (row.get("title") or "").strip()
            url = (row.get("target url") or row.get("url") or "").strip()
            payload = (row.get("payload") or row.get("vector") or "").strip()

            if not param and not inj_type:
                continue  # skip empty / header-repeat rows

            desc_parts: list[str] = []
            if url:
                desc_parts.append(f"URL: {url}")
            if param:
                desc_parts.append(f"Parameter: {param}" + (f" ({place})" if place else ""))
            if inj_type:
                desc_parts.append(f"Type: {inj_type}")
            if payload:
                desc_parts.append(f"Payload: {payload}")

            findings.append({
                "title": f"SQL Injection — {param} ({place})" if param else "SQL Injection detected by sqlmap",
                "severity": "CRITICAL",
                "description": "\n".join(desc_parts),
                "evidence": title or inj_type or "sqlmap confirmed injection",
                "source": "sqlmap",
                "recommendation": (
                    "Use parameterised queries / prepared statements. "
                    "Never interpolate user input directly into SQL."
                ),
            })
    return findings
