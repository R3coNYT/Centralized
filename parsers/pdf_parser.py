"""
Parse PDF audit reports.
Extracts:
  - IP addresses
  - CVE IDs  (scoped per host section — not globally assigned)
  - Open ports / services
  - Severity mentions
Supports AutoRecon PDF format and generic pentest PDF reports.
"""
import re

IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
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

# IPs that should never be treated as target hosts
_IGNORED_IPS = re.compile(
    r'^(127\.|0\.|255\.|224\.|239\.|169\.254\.|10\.0\.0\.0$|172\.16\.0\.0$|192\.168\.0\.0$)'
)


def _is_valid_host_ip(ip: str) -> bool:
    return not _IGNORED_IPS.match(ip)


def _extract_vulns_from_text(text: str) -> list:
    """Extract CVEs with severity context from a text block."""
    vulns = []
    seen = set()
    upper = text.upper()
    for m in CVE_RE.finditer(text):
        cve = m.group(0).upper()
        if cve in seen:
            continue
        seen.add(cve)
        start = max(0, m.start() - 150)
        end = min(len(text), m.end() + 300)
        context = text[start:end]
        sev_match = SEVERITY_KEYWORDS.search(context)
        sev = SEVERITY_MAP.get(sev_match.group(1).lower(), "UNKNOWN") if sev_match else "UNKNOWN"
        vulns.append({
            "cve_id": cve,
            "title": cve,
            "severity": sev,
            "description": context.strip(),
            "source": "pdf",
        })
    return vulns


def _extract_ports_from_text(text: str) -> list:
    """Extract unique port/proto pairs from a text block."""
    ports = []
    seen = set()
    for m in PORT_RE.finditer(text):
        p = int(m.group(1))
        if p >= 65536 or p in seen:
            continue
        seen.add(p)
        # Try to grab service name from the same line
        line = text[max(0, m.start() - 5):min(len(text), m.end() + 60)]
        proto = "tcp" if "/tcp" in m.group(0).lower() else "udp"
        ports.append({
            "port": p,
            "protocol": proto,
            "service": None,
            "product": None,
            "version": None,
            "extra_info": None,
            "state": "open",
            "cpe": None,
        })
    return ports


def _split_sections_by_ip(full_text: str, ordered_ips: list) -> dict:
    """
    Split the full document text into per-IP sections.

    Strategy: find the first occurrence of each IP in the text.  The section
    for IP[n] runs from that position up to the position of IP[n+1] (or end of
    document for the last IP).  This gives each IP ownership of the content
    that appears between its first mention and the next host's first mention.
    """
    if not ordered_ips:
        return {}

    # Find positions: use the first occurrence of each IP as the section start
    positions = {}
    for ip in ordered_ips:
        idx = full_text.find(ip)
        if idx >= 0:
            positions[ip] = idx

    # Sort IPs by their position in the document
    sorted_ips = sorted(positions, key=lambda ip: positions[ip])

    sections = {}
    for i, ip in enumerate(sorted_ips):
        start = positions[ip]
        end = positions[sorted_ips[i + 1]] if i + 1 < len(sorted_ips) else len(full_text)
        sections[ip] = full_text[start:end]

    return sections


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

    # Discover all valid host IPs in document order (preserve first-seen order)
    seen_ips: set = set()
    ordered_ips = []
    for m in IP_RE.finditer(full_text):
        ip = m.group(0)
        if ip not in seen_ips and _is_valid_host_ip(ip):
            seen_ips.add(ip)
            ordered_ips.append(ip)

    if not ordered_ips:
        return {"hosts": [], "error": "No valid IP addresses found in PDF"}

    # Split document into per-host sections, then extract CVEs/ports per section
    sections = _split_sections_by_ip(full_text, ordered_ips)

    hosts = []
    for ip, section_text in sections.items():
        vulns = _extract_vulns_from_text(section_text)
        ports = _extract_ports_from_text(section_text)

        hosts.append({
            "ip": ip,
            "hostname": None,
            "mac_address": None,
            "mac_vendor": None,
            "os_info": None,
            "ports": ports,
            "vulnerabilities": vulns,
            "http_pages": [],
        })

    # If only one IP was found but CVEs exist in the whole doc, make sure they're attached
    if len(hosts) == 1 and not hosts[0]["vulnerabilities"]:
        hosts[0]["vulnerabilities"] = _extract_vulns_from_text(full_text)
    if len(hosts) == 1 and not hosts[0]["ports"]:
        hosts[0]["ports"] = _extract_ports_from_text(full_text)

    return {"hosts": hosts, "error": None}
