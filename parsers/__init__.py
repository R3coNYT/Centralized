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
FILE_TYPE_HTTPX_JSON = "httpx_json"
FILE_TYPE_NUCLEI_JSON = "nuclei_json"
FILE_TYPE_NIKTO_XML = "nikto_xml"
FILE_TYPE_NIKTO_JSON = "nikto_json"
FILE_TYPE_PDF = "pdf"
FILE_TYPE_LYNIS_LOG = "lynis_log"
FILE_TYPE_LYNIS_REPORT = "lynis_report"
FILE_TYPE_UNKNOWN = "unknown"

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def detect_file_type(file_path: str, original_filename: str) -> str:
    """Detect the type of a file based on content and extension."""
    ext = os.path.splitext(original_filename)[1].lower()

    if ext == ".pdf":
        return FILE_TYPE_PDF

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

    # Lynis parsers require a target IP supplied by the user
    if file_type in (FILE_TYPE_LYNIS_LOG, FILE_TYPE_LYNIS_REPORT):
        target_ip = (extra or {}).get("target_ip", "")
        parser_fn = parse_lynis_log if file_type == FILE_TYPE_LYNIS_LOG else parse_lynis_report
        try:
            return parser_fn(file_path, target_ip)
        except Exception as exc:
            return {"hosts": [], "error": str(exc)}

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
