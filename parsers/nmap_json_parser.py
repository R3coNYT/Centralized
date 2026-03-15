"""
Parse Nmap JSON output (AutoRecon format):
{
    "ip": "...",
    "hostname": "...",
    "open_ports": [{"port": N, "proto": "tcp", "service": "...", "product": "...", "version": "..."}]
}
"""
import json


def parse_nmap_json(file_path: str) -> dict:
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    ip = data.get("ip")
    hostname = data.get("hostname")
    if not ip:
        return {"hosts": [], "error": "No 'ip' field found in nmap JSON"}

    ports = []
    for p in data.get("open_ports", []):
        ports.append({
            "port": p.get("port"),
            "protocol": p.get("proto", "tcp"),
            "service": p.get("service"),
            "product": p.get("product"),
            "version": p.get("version"),
            "extra_info": p.get("extra_info"),
            "state": "open",
            "cpe": p.get("cpe"),
        })

    host = {
        "ip": ip,
        "hostname": hostname,
        "mac_address": None,
        "mac_vendor": None,
        "os_info": None,
        "ports": ports,
        "vulnerabilities": [],
        "http_pages": [],
    }

    return {"hosts": [host], "error": None}
