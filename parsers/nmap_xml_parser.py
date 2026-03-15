"""
Parse Nmap XML output files.
Supports standard Nmap XML format (nmap -oX).
"""
import xml.etree.ElementTree as ET
import re

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def parse_nmap_xml(file_path: str) -> dict:
    hosts = []
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
    except ET.ParseError as exc:
        return {"hosts": [], "error": f"XML parse error: {exc}"}

    for host_el in root.findall("host"):
        # Status
        status_el = host_el.find("status")
        if status_el is not None and status_el.get("state") != "up":
            continue

        ip = None
        mac = None
        mac_vendor = None
        hostnames = []

        for addr_el in host_el.findall("address"):
            atype = addr_el.get("addrtype", "")
            if atype == "ipv4" or atype == "ipv6":
                ip = addr_el.get("addr")
            elif atype == "mac":
                mac = addr_el.get("addr")
                mac_vendor = addr_el.get("vendor")

        if not ip:
            continue

        for hn in host_el.findall(".//hostname"):
            if hn.get("name"):
                hostnames.append(hn.get("name"))

        # OS detection
        os_info = None
        os_el = host_el.find(".//osmatch")
        if os_el is not None:
            os_info = os_el.get("name")

        # Ports
        ports = []
        scripts_text = []
        for port_el in host_el.findall(".//port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") not in ("open", "open|filtered"):
                continue

            portid = int(port_el.get("portid", 0))
            proto = port_el.get("protocol", "tcp")

            svc_el = port_el.find("service")
            service = product = version = extrainfo = cpe = None
            if svc_el is not None:
                service = svc_el.get("name")
                product = svc_el.get("product")
                version = svc_el.get("version")
                extrainfo = svc_el.get("extrainfo")
                cpe_el = svc_el.find("cpe")
                if cpe_el is not None:
                    cpe = cpe_el.text

            # Collect script output for CVE hints
            for script_el in port_el.findall("script"):
                out = script_el.get("output", "")
                scripts_text.append(out)

            ports.append({
                "port": portid,
                "protocol": proto,
                "service": service,
                "product": product,
                "version": version,
                "extra_info": extrainfo,
                "state": "open",
                "cpe": cpe,
            })

        # Extract CVEs from all script output text
        all_script_text = " ".join(scripts_text)
        cve_matches = list(set(CVE_RE.findall(all_script_text)))
        vulns = [
            {
                "cve_id": cve.upper(),
                "title": cve.upper(),
                "severity": "UNKNOWN",
                "source": "nmap_script",
                "description": f"CVE reference found in nmap script output",
            }
            for cve in cve_matches
        ]

        hosts.append({
            "ip": ip,
            "hostname": " / ".join(hostnames) if hostnames else None,
            "mac_address": mac,
            "mac_vendor": mac_vendor,
            "os_info": os_info,
            "ports": ports,
            "vulnerabilities": vulns,
            "http_pages": [],
        })

    return {"hosts": hosts, "error": None}
