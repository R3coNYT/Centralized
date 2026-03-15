"""
Parse PDF audit reports.
Extracts:
  - IP addresses
  - CVE IDs
  - Open ports / services
  - Severity mentions
Supports AutoRecon PDF format and generic pentest PDF reports.
"""
import re

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
PORT_RE = re.compile(r"\b(\d{1,5})/(?:tcp|udp)\b", re.IGNORECASE)
SEVERITY_KEYWORDS = re.compile(
    r"\b(Critical|High|Medium|Low|Informational|Info)\b", re.IGNORECASE
)

SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "informational": "INFO",
    "info": "INFO",
}


def parse_pdf(file_path: str) -> dict:
    try:
        import pdfplumber
    except ImportError:
        return {"hosts": [], "error": "pdfplumber is not installed. Run: pip install pdfplumber"}

    text_parts = []
    try:
        with pdfplumber.open(file_path) as pdf:
            for page in pdf.pages:
                t = page.extract_text()
                if t:
                    text_parts.append(t)
    except Exception as exc:
        return {"hosts": [], "error": f"PDF read error: {exc}"}

    full_text = "\n".join(text_parts)

    # Find all unique IPs
    all_ips = [ip for ip in set(IP_RE.findall(full_text))
               if not ip.startswith("0.") and not ip.startswith("255.")]

    # Find all CVEs
    all_cves = list(set(c.upper() for c in CVE_RE.findall(full_text)))

    # Extract port references  
    all_ports = list(set(int(p) for p in PORT_RE.findall(full_text) if int(p) < 65536))

    # Build a single "report host" per discovered IP, attach all CVEs as vulns
    hosts = []
    primary_ip = all_ips[0] if all_ips else "pdf_report"

    # Try to build severity-context for CVEs by scanning surrounding text
    vulns = []
    for cve in all_cves:
        # Find a 200-char window around the CVE mention
        idx = full_text.upper().find(cve)
        context = full_text[max(0, idx - 100): idx + 200] if idx >= 0 else ""
        sev_match = SEVERITY_KEYWORDS.search(context)
        sev = SEVERITY_MAP.get(sev_match.group(1).lower(), "UNKNOWN") if sev_match else "UNKNOWN"
        vulns.append({
            "cve_id": cve,
            "title": cve,
            "severity": sev,
            "description": context.strip(),
            "source": "pdf",
        })

    ports = [
        {
            "port": p,
            "protocol": "tcp",
            "service": None,
            "product": None,
            "version": None,
            "extra_info": None,
            "state": "open",
            "cpe": None,
        }
        for p in all_ports
    ]

    hosts.append({
        "ip": primary_ip,
        "hostname": None,
        "mac_address": None,
        "mac_vendor": None,
        "os_info": None,
        "ports": ports,
        "vulnerabilities": vulns,
        "http_pages": [],
        "_additional_ips": all_ips[1:],  # extra IPs found – stored as note
    })

    return {"hosts": hosts, "error": None}
