"""
Centralized parsers package.
Auto-detects file type and dispatches to the right parser.
"""
import json
import os
import re

# Supported file types
FILE_TYPE_NMAP_XML = "nmap_xml"
FILE_TYPE_NMAP_JSON = "nmap_json"
FILE_TYPE_AUTORECON_JSON = "autorecon_json"
FILE_TYPE_AUTORECON_ZIP = "autorecon_zip"   # AutoRecon backup ZIP (normal or AI scan)
FILE_TYPE_AUTORECON_AI_JSON = "autorecon_ai_json"  # Standalone AI conversation.json
FILE_TYPE_HTTPX_JSON = "httpx_json"
FILE_TYPE_NUCLEI_JSON = "nuclei_json"
FILE_TYPE_NIKTO_XML = "nikto_xml"
FILE_TYPE_NIKTO_JSON = "nikto_json"
FILE_TYPE_PDF = "pdf"
FILE_TYPE_LYNIS_LOG = "lynis_log"
FILE_TYPE_LYNIS_REPORT = "lynis_report"
FILE_TYPE_SQLMAP_TXT = "sqlmap_txt"
FILE_TYPE_SQLMAP_CSV = "sqlmap_csv"
FILE_TYPE_DIRBUST_JSON = "dirbust_json"
FILE_TYPE_DIRBUST_TXT = "dirbust_txt"
FILE_TYPE_SCREENSHOT = "screenshot"
FILE_TYPE_UNKNOWN = "unknown"

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def detect_file_type(file_path: str, original_filename: str) -> str:
    """Detect the type of a file based on content and extension."""
    ext = os.path.splitext(original_filename)[1].lower()

    if ext == ".pdf":
        return FILE_TYPE_PDF

    if ext in (".png", ".jpg", ".jpeg", ".gif", ".webp"):
        return FILE_TYPE_SCREENSHOT

    if ext == ".zip":
        # Detect AutoRecon backup ZIPs by inspecting the archive's member list.
        # A valid AutoRecon ZIP contains "target.txt" at its root.
        import zipfile as _zf
        try:
            with _zf.ZipFile(file_path, "r") as zf:
                names = zf.namelist()
            if "target.txt" in names:
                return FILE_TYPE_AUTORECON_ZIP
        except Exception:
            pass
        return FILE_TYPE_UNKNOWN

    if ext == ".log":
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                head = f.read(8000)
            lynis_log_signals = (
                "Starting Lynis",
                "lynis_version",
                "Lynis version",
                "Lynis 2.",
                "Lynis 3.",
                "Lynis 4.",
                "[+] Initializing",
                "LYNIS - ",
                "cisofy.com",
            )
            fname_lower = original_filename.lower()
            # Filename hint: lynis*.log is almost certainly a Lynis log
            if "lynis" in fname_lower or any(sig in head for sig in lynis_log_signals):
                return FILE_TYPE_LYNIS_LOG
        except Exception:
            pass
        return FILE_TYPE_UNKNOWN

    if ext == ".dat":
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                head = f.read(4000)
            lynis_dat_signals = (
                "lynis_version=",
                "report_version_major=",
                "# Lynis",
                "# lynis",
                "warning[]=",
                "suggestion[]=",
            )
            fname_lower = original_filename.lower()
            if "lynis" in fname_lower or any(sig in head for sig in lynis_dat_signals):
                return FILE_TYPE_LYNIS_REPORT
        except Exception:
            pass
        return FILE_TYPE_UNKNOWN

    if ext == ".txt":
        fname_lower = original_filename.lower()
        if "sqlmap_output" in fname_lower or "sqlmap" in fname_lower:
            return FILE_TYPE_SQLMAP_TXT
        # Gobuster plain-text output: check for lines matching gobuster format
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                head = f.read(4000)
            if re.search(r"^/\S+\s+\(Status:\s*\d+\)", head, re.MULTILINE):
                return FILE_TYPE_DIRBUST_TXT
            # sqlmap raw log can also be .txt without "sqlmap" in the name
            if "back-end DBMS" in head or "Parameter:" in head and "Type:" in head:
                return FILE_TYPE_SQLMAP_TXT
        except Exception:
            pass
        return FILE_TYPE_UNKNOWN

    if ext == ".csv":
        # sqlmap --results-file CSV: header row contains "Target URL" / "Parameter" / "Type"
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                header = f.readline().lower()
            sqlmap_csv_signals = ("target url", "parameter", "type", "title", "vector", "payload")
            if sum(1 for s in sqlmap_csv_signals if s in header) >= 2:
                return FILE_TYPE_SQLMAP_CSV
        except Exception:
            pass
        return FILE_TYPE_UNKNOWN

    if ext == ".xml":
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                head = f.read(2000)
            if "<nmaprun" in head:
                return FILE_TYPE_NMAP_XML
            if "<niktoscan" in head:
                return FILE_TYPE_NIKTO_XML
        except Exception:
            pass
        return FILE_TYPE_UNKNOWN

    if ext == ".json":
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)

            # AutoRecon AI conversation.json: list of turn dicts with "iteration" and "status"
            if isinstance(data, list) and len(data) > 0:
                first = data[0]
                if isinstance(first, dict) and "iteration" in first and "status" in first:
                    return FILE_TYPE_AUTORECON_AI_JSON

            # AutoRecon JSON: has "input_target" and "subdomains"
            if isinstance(data, dict) and "input_target" in data and "subdomains" in data:
                return FILE_TYPE_AUTORECON_JSON

            # Nmap JSON (AutoRecon format): has "ip" and "open_ports"
            if isinstance(data, dict) and "ip" in data and "open_ports" in data:
                return FILE_TYPE_NMAP_JSON

            # HTTPX JSON: array of objects with "url" and "status_code"
            if isinstance(data, list) and len(data) > 0:
                first = data[0]
                if isinstance(first, dict) and "url" in first and "status_code" in first:
                    return FILE_TYPE_HTTPX_JSON
                # Nuclei JSON: array with "template-id" and "info"
                if isinstance(first, dict) and ("template-id" in first or "templateID" in first or "info" in first):
                    return FILE_TYPE_NUCLEI_JSON
                # Nuclei JSON line per line (alternative)
                if isinstance(first, dict) and "severity" in first and "matched-at" in first:
                    return FILE_TYPE_NUCLEI_JSON

            # Nikto JSON: has "host" and "vulnerabilities" or "items"
            if isinstance(data, dict) and ("vulnerabilities" in data or "items" in data) and "host" in data:
                return FILE_TYPE_NIKTO_JSON

            # ffuf JSON: has "results" and "commandline"
            from parsers.dirbust_parser import is_ffuf_json, is_gobuster_json
            if is_ffuf_json(data) or is_gobuster_json(data):
                return FILE_TYPE_DIRBUST_JSON

        except (json.JSONDecodeError, UnicodeDecodeError):
            pass
        return FILE_TYPE_UNKNOWN

    return FILE_TYPE_UNKNOWN


def parse_file(file_path: str, file_type: str, audit_id: int, db_session, extra: dict = None):
    """
    Route a file to the correct parser. Returns a dict:
    {
        "hosts": [...],
        "error": None or str
    }
    Each host dict mirrors what the DB layer expects.
    """
    from parsers.nmap_xml_parser import parse_nmap_xml
    from parsers.nmap_json_parser import parse_nmap_json
    from parsers.autorecon_parser import parse_autorecon_json
    from parsers.httpx_parser import parse_httpx_json
    from parsers.nuclei_parser import parse_nuclei_json
    from parsers.nikto_parser import parse_nikto_xml, parse_nikto_json
    from parsers.pdf_parser import parse_pdf
    from parsers.lynis_parser import parse_lynis_log, parse_lynis_report

    # Parsers that require a target IP supplied by the user
    if file_type in (FILE_TYPE_LYNIS_LOG, FILE_TYPE_LYNIS_REPORT):
        target_ip = (extra or {}).get("target_ip", "")
        parser_fn = parse_lynis_log if file_type == FILE_TYPE_LYNIS_LOG else parse_lynis_report
        try:
            return parser_fn(file_path, target_ip)
        except Exception as exc:
            return {"hosts": [], "error": str(exc)}

    if file_type == FILE_TYPE_SQLMAP_TXT:
        from parsers.sqlmap_parser import parse_sqlmap_txt
        target_ip = (extra or {}).get("target_ip", "")
        try:
            return parse_sqlmap_txt(file_path, target_ip)
        except Exception as exc:
            return {"hosts": [], "error": str(exc)}

    if file_type == FILE_TYPE_SQLMAP_CSV:
        from parsers.sqlmap_parser import parse_sqlmap_csv
        target_ip = (extra or {}).get("target_ip", "")
        try:
            return parse_sqlmap_csv(file_path, target_ip)
        except Exception as exc:
            return {"hosts": [], "error": str(exc)}

    if file_type in (FILE_TYPE_DIRBUST_JSON, FILE_TYPE_DIRBUST_TXT):
        from parsers.dirbust_parser import parse_dirbust_file
        target_ip = (extra or {}).get("target_ip", "")
        original_filename = (extra or {}).get("original_filename", file_path)
        try:
            return parse_dirbust_file(file_path, original_filename, target_ip)
        except Exception as exc:
            return {"hosts": [], "error": str(exc)}

    if file_type == FILE_TYPE_SCREENSHOT:
        # Screenshots are stored as extra_data references — no DB Vulnerability created.
        # The caller (uploads.py) handles copying the file to a public location.
        target_ip = (extra or {}).get("target_ip", "")
        original_filename = (extra or {}).get("original_filename", os.path.basename(file_path))
        if not target_ip:
            return {"hosts": [], "error": "A Target IP is required to import a screenshot."}
        return {
            "hosts": [
                {
                    "ip": target_ip,
                    "extra_data": {
                        "screenshots": [{"filename": original_filename, "stored_filename": ""}]
                    },
                }
            ],
            "error": None,
        }

    # AutoRecon backup ZIP — extract and dispatch to sub-parsers
    if file_type == FILE_TYPE_AUTORECON_ZIP:
        return _parse_autorecon_zip(file_path, extra or {})

    # Standalone AI conversation.json
    if file_type == FILE_TYPE_AUTORECON_AI_JSON:
        from parsers.ai_scan_parser import parse_autorecon_ai_conversation
        target = (extra or {}).get("target", "").strip()
        try:
            return parse_autorecon_ai_conversation(file_path, target)
        except Exception as exc:
            return {"hosts": [], "error": str(exc), "ai_scan_data": {}}

    dispatch = {
        FILE_TYPE_NMAP_XML: parse_nmap_xml,
        FILE_TYPE_NMAP_JSON: parse_nmap_json,
        FILE_TYPE_AUTORECON_JSON: parse_autorecon_json,
        FILE_TYPE_HTTPX_JSON: parse_httpx_json,
        FILE_TYPE_NUCLEI_JSON: parse_nuclei_json,
        FILE_TYPE_NIKTO_XML: parse_nikto_xml,
        FILE_TYPE_NIKTO_JSON: parse_nikto_json,
        FILE_TYPE_PDF: parse_pdf,
    }

    parser_fn = dispatch.get(file_type)
    if not parser_fn:
        return {"hosts": [], "error": f"Unsupported file type: {file_type}"}

    try:
        return parser_fn(file_path)
    except Exception as exc:
        return {"hosts": [], "error": str(exc)}


def _parse_autorecon_zip(zip_path: str, extra: dict) -> dict:
    """
    Extract an AutoRecon backup ZIP to a temporary directory, run sub-parsers
    on the contents, and return a merged result.

    Expected ZIP structure (either normal or AI scan)::

        target.txt            – scan target (IP/domain/CIDR)
        logs/recon.log        – scan log (ignored)
        report.json           – normal AutoRecon JSON report  [optional]
        report.pdf            – PDF report  [ignored]
        screenshots/          – screenshot directory  [ignored here]
        ai_scan/
            conversation.json – AI conversation log
            ai_report.md      – AI final report
            suggested_tools.json
            step_NNN.txt      – individual step outputs  [ignored]
    """
    import zipfile as _zf
    import tempfile
    import shutil

    tmp_dir = tempfile.mkdtemp(prefix="centralized_zip_")
    try:
        with _zf.ZipFile(zip_path, "r") as zf:
            zf.extractall(tmp_dir)

        # Read scan target from target.txt
        target_file = os.path.join(tmp_dir, "target.txt")
        target = ""
        if os.path.isfile(target_file):
            try:
                target = open(target_file, encoding="utf-8").read().strip()
            except Exception:
                pass
        if not target:
            target = extra.get("target", "").strip()

        merged_hosts: list  = []
        ai_scan_data: dict  = {}
        errors: list        = []

        # ── Normal AutoRecon report.json ──────────────────────────────────
        report_json = os.path.join(tmp_dir, "report.json")
        if os.path.isfile(report_json):
            from parsers.autorecon_parser import parse_autorecon_json as _parse_ar
            try:
                r = _parse_ar(report_json)
                if r.get("error"):
                    errors.append(f"report.json: {r['error']}")
                else:
                    merged_hosts.extend(r.get("hosts", []))
            except Exception as exc:
                errors.append(f"report.json parse error: {exc}")

        # ── AI scan directory ─────────────────────────────────────────────
        ai_dir = os.path.join(tmp_dir, "ai_scan")
        if os.path.isdir(ai_dir):
            from parsers.ai_scan_parser import parse_autorecon_ai_directory
            try:
                ai_result = parse_autorecon_ai_directory(ai_dir, target)
                if ai_result.get("error"):
                    errors.append(f"ai_scan: {ai_result['error']}")
                ai_scan_data = ai_result.get("ai_scan_data", {})
                # Merge AI-derived vulns into existing hosts or add new ones.
                # For CIDR / domain targets the AI host IP won't match any
                # individual host from report.json, so we distribute its vulns
                # to all existing hosts rather than creating a phantom CIDR host.
                import ipaddress as _ipaddress
                for ai_host in ai_result.get("hosts", []):
                    ai_ip = ai_host.get("ip", "")
                    existing = next((h for h in merged_hosts if h.get("ip") == ai_ip), None)
                    if existing:
                        # Exact match — merge into that host
                        seen = {v["title"] for v in existing.get("vulnerabilities", [])}
                        for v in ai_host.get("vulnerabilities", []):
                            if v["title"] not in seen:
                                existing.setdefault("vulnerabilities", []).append(v)
                                seen.add(v["title"])
                    else:
                        # Check if ai_ip is a plain routable IP address
                        try:
                            _ipaddress.ip_address(ai_ip)
                            is_plain_ip = True
                        except ValueError:
                            is_plain_ip = False

                        if is_plain_ip:
                            # New individual host discovered by the AI scan
                            merged_hosts.append(ai_host)
                        elif merged_hosts:
                            # CIDR or domain target: distribute AI vulns to all
                            # known hosts (the AI analysed the whole range)
                            for mh in merged_hosts:
                                seen = {v["title"] for v in mh.get("vulnerabilities", [])}
                                for v in ai_host.get("vulnerabilities", []):
                                    if v["title"] not in seen:
                                        mh.setdefault("vulnerabilities", []).append(v)
                                        seen.add(v["title"])
                        else:
                            # No hosts from report.json either; keep as-is so
                            # the persist layer can decide what to do
                            merged_hosts.append(ai_host)
            except Exception as exc:
                errors.append(f"ai_scan parse error: {exc}")

        error_str = "; ".join(errors) if errors and not merged_hosts else None
        return {"hosts": merged_hosts, "error": error_str, "ai_scan_data": ai_scan_data}

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
