"""
Parse Nikto XML and JSON output files.
"""
import xml.etree.ElementTree as ET
import json
import re

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def parse_nikto_xml(file_path: str) -> dict:
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
    except ET.ParseError as exc:
        return {"hosts": [], "error": f"XML parse error: {exc}"}

    hosts = []
    # <niktoscan> / <scandetails targetip="..." targethostname="..." targetport="...">
    for scan in root.findall(".//scandetails"):
        ip = scan.get("targetip") or scan.get("targetip", "")
        hostname = scan.get("targethostname")
        port_str = scan.get("targetport", "80")
        try:
            port_num = int(port_str)
        except ValueError:
            port_num = 80

        vulns = []
        for item in scan.findall("item"):
            description = item.findtext("description") or ""
            uri = item.findtext("uri") or ""
            osvdb = item.get("osvdbid") or ""

            # Try to extract CVE
            cve_matches = CVE_RE.findall(description + " " + uri)
            cve_id = cve_matches[0].upper() if cve_matches else None

            vulns.append({
                "cve_id": cve_id,
                "title": description[:200] if description else "Nikto Finding",
                "severity": "MEDIUM",
                "description": description,
                "evidence": uri,
                "source": "nikto",
            })

        hosts.append({
            "ip": ip,
            "hostname": hostname,
            "mac_address": None,
            "mac_vendor": None,
            "os_info": None,
            "ports": [{"port": port_num, "protocol": "tcp", "service": "http", "product": None, "version": None, "extra_info": None, "state": "open", "cpe": None}],
            "vulnerabilities": vulns,
            "http_pages": [],
        })

    return {"hosts": hosts, "error": None}


def parse_nikto_json(file_path: str) -> dict:
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    ip = data.get("host") or data.get("ip") or "unknown"
    hostname = data.get("hostname")
    port_num = int(data.get("port", 80))

    vulns = []
    for vuln in data.get("vulnerabilities", data.get("items", [])):
        if not isinstance(vuln, dict):
            continue
        desc = vuln.get("msg") or vuln.get("description") or vuln.get("message") or ""
        cve_matches = CVE_RE.findall(desc)
        cve_id = cve_matches[0].upper() if cve_matches else None
        vulns.append({
            "cve_id": cve_id,
            "title": desc[:200] or "Nikto Finding",
            "severity": "MEDIUM",
            "description": desc,
            "evidence": vuln.get("uri") or vuln.get("url"),
            "source": "nikto",
        })

    host = {
        "ip": ip,
        "hostname": hostname,
        "mac_address": None,
        "mac_vendor": None,
        "os_info": None,
        "ports": [{"port": port_num, "protocol": "tcp", "service": "http", "product": None, "version": None, "extra_info": None, "state": "open", "cpe": None}],
        "vulnerabilities": vulns,
        "http_pages": [],
    }
    return {"hosts": [host], "error": None}
