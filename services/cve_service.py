"""
NVD (National Vulnerability Database) API v2.0 service.
https://nvd.nist.gov/developers/vulnerabilities

Rate limits:
  Without API key : 5 requests / 30 s
  With API key    : 50 requests / 30 s
"""
import time
import re
import requests
from flask import current_app

_last_request_time = 0.0


def _throttle():
    """Enforce inter-request delay to respect NVD rate limits."""
    global _last_request_time
    delay = current_app.config.get("NVD_RATE_LIMIT_DELAY", 0.7)
    elapsed = time.monotonic() - _last_request_time
    if elapsed < delay:
        time.sleep(delay - elapsed)
    _last_request_time = time.monotonic()


def _headers():
    api_key = current_app.config.get("NVD_API_KEY", "")
    h = {"User-Agent": "Centralized-PentestTool/1.0"}
    if api_key:
        h["apiKey"] = api_key
    return h


def lookup_cve(cve_id: str) -> dict | None:
    """
    Fetch full CVE details from NVD by CVE ID.
    Returns a dict with: id, description, severity, cvss_score, cvss_vector, references
    or None on failure.
    """
    cve_id = cve_id.upper().strip()
    if not re.match(r"^CVE-\d{4}-\d{4,7}$", cve_id):
        return None

    url = current_app.config["NVD_API_BASE"]
    try:
        _throttle()
        resp = requests.get(
            url,
            params={"cveId": cve_id},
            headers=_headers(),
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as exc:
        current_app.logger.warning(f"NVD lookup failed for {cve_id}: {exc}")
        return None

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None

    return _extract_cve(vulns[0].get("cve", {}))


def search_cves_by_keyword(keyword: str, max_results: int = 10) -> list[dict]:
    """
    Search NVD for CVEs matching a keyword (e.g. 'OpenSSH 8.4').
    Returns a list of CVE dicts.
    """
    if not keyword or len(keyword.strip()) < 3:
        return []

    url = current_app.config["NVD_API_BASE"]
    try:
        _throttle()
        resp = requests.get(
            url,
            params={"keywordSearch": keyword, "resultsPerPage": max_results},
            headers=_headers(),
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as exc:
        current_app.logger.warning(f"NVD search failed for '{keyword}': {exc}")
        return []

    results = []
    for item in data.get("vulnerabilities", []):
        cve_data = item.get("cve", {})
        extracted = _extract_cve(cve_data)
        if extracted:
            results.append(extracted)
    return results


def enrich_vulnerabilities(port_product: str, port_version: str | None) -> list[dict]:
    """
    Given a product name and optional version, search NVD and return matching CVEs.
    Used after parsing nmap results to find known vulnerabilities.
    """
    if not port_product:
        return []
    keyword = port_product
    if port_version:
        keyword = f"{port_product} {port_version}"
    return search_cves_by_keyword(keyword, max_results=5)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_cve(cve: dict) -> dict | None:
    if not cve:
        return None

    cve_id = cve.get("id", "")
    descriptions = cve.get("descriptions", [])
    desc_en = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        descriptions[0]["value"] if descriptions else "",
    )

    severity = "UNKNOWN"
    cvss_score = None
    cvss_vector = None

    # Try CVSSv3.1 first, then CVSSv3.0, then CVSSv2
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key, [])
        if metric_list:
            m = metric_list[0]
            cvss_data = m.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString")
            severity = (
                m.get("baseSeverity")
                or cvss_data.get("baseSeverity")
                or _score_to_severity(cvss_score)
            )
            break

    refs = cve.get("references", [])
    all_ref_urls = [r.get("url", "") for r in refs if r.get("url")]

    # References tagged as patches / fixes / workarounds
    PATCH_TAGS = {"Patch", "Fix", "Mitigation", "Vendor Advisory", "Third Party Advisory"}
    patch_refs = [
        r["url"] for r in refs
        if r.get("url") and PATCH_TAGS.intersection(set(r.get("tags", [])))
    ]
    patch_available = len(patch_refs) > 0

    # CWE weaknesses
    weaknesses = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            val = d.get("value", "")
            if d.get("lang") == "en" and val.startswith("CWE-") and val not in weaknesses:
                weaknesses.append(val)

    # CISA Known Exploited Vulnerability
    exploited_in_wild = "cisaExploitAdd" in cve
    cisa_remediation = cve.get("cisaRequiredAction")

    import json as _json
    return {
        "cve_id": cve_id,
        "title": cve_id,
        "description": desc_en,
        "severity": severity.upper() if severity else "UNKNOWN",
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "references": _json.dumps(all_ref_urls[:10]),
        "patch_refs": patch_refs[:8],
        "patch_available": patch_available,
        "weaknesses": weaknesses,
        "exploited_in_wild": exploited_in_wild,
        "cisa_remediation": cisa_remediation,
        "published": cve.get("published", ""),
        "last_modified": cve.get("lastModified", ""),
        "vuln_status": cve.get("vulnStatus", ""),
        "source": "nvd",
    }


def _score_to_severity(score) -> str:
    if score is None:
        return "UNKNOWN"
    score = float(score)
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "INFO"
