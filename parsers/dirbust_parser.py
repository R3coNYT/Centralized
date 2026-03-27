"""
Parser for AutoRecon directory bruteforce output files.

AutoRecon saves gobuster output as plain-text to:
  results/<target>/dirbust/gobuster_<safe_url>.txt

and ffuf output as JSON to:
  results/<target>/dirbust/ffuf_<safe_url>.json

Both formats are supported here.  Results are stored as extra_data on the
host (key ``dir_bruteforce``) rather than as individual Vulnerability records.

A Target IP must be supplied (prompted in the Centralized upload UI).
"""
from __future__ import annotations

import json
import re


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def parse_dirbust_file(file_path: str, original_filename: str, target_ip: str) -> dict:
    """
    Parse a gobuster .txt or ffuf .json output file.

    Returns a Centralized-compatible result dict::

        {
            "hosts": [
                {
                    "ip": <target_ip>,
                    "extra_data": {"dir_bruteforce": [...]},
                }
            ],
            "error": None
        }
    """
    target_ip = (target_ip or "").strip()
    if not target_ip:
        return {"hosts": [], "error": "A Target IP is required to import a dirbust output file."}

    fname = (original_filename or "").lower()

    try:
        if fname.endswith(".json"):
            findings = _parse_ffuf_json(file_path)
        else:
            findings = _parse_gobuster_txt(file_path)
    except Exception as exc:
        return {"hosts": [], "error": f"Cannot parse dirbust file: {exc}"}

    return {
        "hosts": [
            {
                "ip": target_ip,
                "extra_data": {"dir_bruteforce": findings},
            }
        ],
        "error": None,
    }


# ---------------------------------------------------------------------------
# Format detectors (used by __init__.py to distinguish ffuf JSON from others)
# ---------------------------------------------------------------------------

def is_ffuf_json(data: dict) -> bool:
    """Return True when a parsed JSON dict looks like an ffuf output file."""
    return isinstance(data, dict) and "results" in data and "commandline" in data


def is_gobuster_json(data: dict) -> bool:
    """Return True when a parsed JSON dict looks like a gobuster --json output."""
    # gobuster JSON has {"results": [{"url": ..., "status": N, "size": N}]}
    if not (isinstance(data, dict) and "results" in data):
        return False
    results = data.get("results", [])
    if not results:
        return False
    first = results[0] if isinstance(results, list) else {}
    return isinstance(first, dict) and "url" in first and "status" in first


# ---------------------------------------------------------------------------
# Internal parsers
# ---------------------------------------------------------------------------

def _parse_gobuster_txt(file_path: str) -> list[dict]:
    """Parse gobuster plain-text output (one finding per line)."""
    findings: list[dict] = []
    with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Format: /path  (Status: 200) [Size: 1234]
            m = re.match(
                r"(/\S*)\s+\(Status:\s*(\d+)\)(?:\s*\[Size:\s*(\d+)\])?",
                line,
            )
            if m:
                findings.append({
                    "path": m.group(1),
                    "status": int(m.group(2)),
                    "size": int(m.group(3)) if m.group(3) else None,
                })
    return findings


def _parse_ffuf_json(file_path: str) -> list[dict]:
    """Parse ffuf JSON output file."""
    with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)

    findings: list[dict] = []
    for r in data.get("results", []):
        if not isinstance(r, dict):
            continue
        # ffuf stores the full URL in "url", path in "input.FUZZ" or derivable
        url = r.get("url", "")
        status = r.get("status")
        size = r.get("length") or r.get("size")
        findings.append({"path": url, "status": status, "size": size})
    return findings
