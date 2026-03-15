"""
Parse HTTPX JSON output (array of probe results).
"""
import json


def parse_httpx_json(file_path: str) -> dict:
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        return {"hosts": [], "error": "Expected a JSON array for HTTPX output"}

    # Group by host IP
    hosts_map: dict[str, dict] = {}

    for entry in data:
        if not isinstance(entry, dict):
            continue

        ip = entry.get("host_ip") or entry.get("host") or entry.get("input", "").split(":")[0]
        if not ip:
            continue

        if ip not in hosts_map:
            hosts_map[ip] = {
                "ip": ip,
                "hostname": None,
                "mac_address": None,
                "mac_vendor": None,
                "os_info": None,
                "ports": [],
                "vulnerabilities": [],
                "http_pages": [],
            }

        port_str = str(entry.get("port", ""))
        port_num = int(port_str) if port_str.isdigit() else None

        # Add port if present and not already tracked
        if port_num:
            existing_ports = [p["port"] for p in hosts_map[ip]["ports"]]
            if port_num not in existing_ports:
                hosts_map[ip]["ports"].append({
                    "port": port_num,
                    "protocol": "tcp",
                    "service": "http",
                    "product": None,
                    "version": None,
                    "extra_info": None,
                    "state": "open",
                    "cpe": None,
                })

        url = entry.get("url") or entry.get("input")
        tech = entry.get("tech") or entry.get("technologies") or entry.get("webserver")
        if isinstance(tech, list):
            tech = ", ".join(str(t) for t in tech)

        hosts_map[ip]["http_pages"].append({
            "url": url,
            "status_code": entry.get("status_code"),
            "title": entry.get("title"),
            "content_type": entry.get("content_type"),
            "content_length": entry.get("content_length"),
            "technology": tech,
            "redirect_location": entry.get("location"),
        })

    return {"hosts": list(hosts_map.values()), "error": None}
