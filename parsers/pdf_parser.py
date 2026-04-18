"""
Parse PDF audit reports.
Extracts:
  - IP addresses
  - CVE IDs  (scoped per host section — not globally assigned)
  - Open ports / services  (including product and version strings)
  - Structured findings with severity, evidence, and recommendations
  - Resolved hostname and OS information
Supports AutoRecon PDF format and generic pentest PDF reports.
"""
import re
from parsers.ai_scan_parser import (  # shared rich-extraction helpers
    _extract_ports_from_report    as _extract_ports_rich,
    _extract_hostname_from_report as _extract_hostname_from_text,
    _extract_os_from_report       as _extract_os_from_text,
    _extract_vulns_from_report    as _extract_vulns_rich,
)

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

# Patterns in the text BEFORE the match that indicate a version string, not an IP
_VERSION_PREFIX_RE = re.compile(
    r'(?:version|release|build|ver\b|patch|update|firmware|software|v\.?)\s*:?\s*$',
    re.IGNORECASE,
)

# Patterns in the text AFTER the match that indicate a version range, not a host IP
_VERSION_SUFFIX_RE = re.compile(
    r'^\s*(?:and\s+(?:later|above|earlier|below|prior)|through|prior\s+to|before|after|\.[x*])',
    re.IGNORECASE,
)

# Patterns in text BEFORE the match that indicate a network range label, not a host
_NETWORK_RANGE_PREFIX_RE = re.compile(
    r'(?:network\s+range|start\s*(?:address)?|end\s*(?:address)?|range|subnet|cidr|from|to)\s*:?\s*$',
    re.IGNORECASE,
)


def _is_valid_host_ip(ip: str, prefix: str = "", suffix: str = "") -> bool:
    """Return True if *ip* looks like a scannable host address and not a software version."""
    if _IGNORED_IPS.match(ip):
        return False
    # Reject network addresses (last octet 0) and broadcast addresses (last octet 255)
    last_octet = int(ip.rsplit(".", 1)[-1])
    if last_octet == 0 or last_octet == 255:
        return False
    # Reject if surrounded by version-related wording in the nearby text
    if prefix and _VERSION_PREFIX_RE.search(prefix):
        return False
    if suffix and _VERSION_SUFFIX_RE.match(suffix):
        return False
    # Reject if labelled as a network range start/end
    if prefix and _NETWORK_RANGE_PREFIX_RE.search(prefix):
        return False
    return True


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
        if ip in seen_ips:
            continue
        prefix = full_text[max(0, m.start() - 60):m.start()]
        suffix = full_text[m.end():min(len(full_text), m.end() + 40)]
        if _is_valid_host_ip(ip, prefix, suffix):
            seen_ips.add(ip)
            ordered_ips.append(ip)

    if not ordered_ips:
        return {"hosts": [], "error": "No valid IP addresses found in PDF"}

    # Split document into per-host sections, then extract CVEs/ports per section
    sections = _split_sections_by_ip(full_text, ordered_ips)

    hosts = []
    for ip, section_text in sections.items():
        # Rich extraction: structured findings, service/product/version per port, hostname, OS
        vulns    = _extract_vulns_rich(section_text, ip)
        ports    = _extract_ports_rich(section_text)
        if not ports:
            ports = _extract_ports_from_text(section_text)
        hostname = _extract_hostname_from_text(section_text)
        os_info  = _extract_os_from_text(section_text)

        hosts.append({
            "ip":          ip,
            "hostname":    hostname,
            "mac_address": None,
            "mac_vendor":  None,
            "os_info":     os_info,
            "ports":       ports,
            "vulnerabilities": vulns,
            "http_pages":  [],
        })

    # Single-IP document: try whole-document extraction as fallback
    if len(hosts) == 1:
        if not hosts[0]["vulnerabilities"]:
            hosts[0]["vulnerabilities"] = _extract_vulns_rich(full_text, hosts[0]["ip"])
        if not hosts[0]["ports"]:
            hosts[0]["ports"] = _extract_ports_rich(full_text) or _extract_ports_from_text(full_text)
        if not hosts[0]["hostname"]:
            hosts[0]["hostname"] = _extract_hostname_from_text(full_text)
        if not hosts[0]["os_info"]:
            hosts[0]["os_info"] = _extract_os_from_text(full_text)

    return {"hosts": hosts, "error": None}
