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


# ---------------------------------------------------------------------------
# Version-based CVE applicability (host context correlation)
# ---------------------------------------------------------------------------

def fetch_cve_configurations(cve_id: str) -> list:
    """Fetch the CPE applicability / configuration data from NVD for a CVE.

    Returns the raw ``configurations`` list from the NVD response, or [] on
    failure.  Each entry contains ``nodes`` → ``cpeMatch`` entries with
    versionStartIncluding / versionEndExcluding bounds.
    """
    cve_id = cve_id.upper().strip()
    if not re.match(r"^CVE-\d{4}-\d{4,7}$", cve_id):
        return []
    url = current_app.config["NVD_API_BASE"]
    try:
        _throttle()
        resp = requests.get(url, params={"cveId": cve_id}, headers=_headers(), timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as exc:
        current_app.logger.warning(f"NVD config fetch failed for {cve_id}: {exc}")
        return []
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return []
    return vulns[0].get("cve", {}).get("configurations", [])


def _parse_ver(version_str: str):
    """Return a comparable version object or None if unparseable."""
    if not version_str:
        return None
    try:
        from packaging.version import Version
        return Version(str(version_str).strip())
    except Exception:
        return None


def cpe_match_for_product(configurations: list, product_hint: str) -> list:
    """Return all CPE match dicts (vulnerable=true) whose product/vendor field
    contains *product_hint* (case-insensitive substring match).
    """
    hint = product_hint.lower().strip()
    matches = []
    for node_group in configurations:
        for node in node_group.get("nodes", []):
            for cm in node.get("cpeMatch", []):
                if not cm.get("vulnerable", False):
                    continue
                cpe = cm.get("criteria", "").lower()
                # CPE format: cpe:2.3:<part>:<vendor>:<product>:<ver>:...
                parts = cpe.split(":")
                vendor  = parts[3] if len(parts) > 3 else ""
                product = parts[4] if len(parts) > 4 else ""
                if hint in vendor or hint in product or hint in cpe:
                    matches.append(cm)
    return matches


def has_os_cpe_entries(configurations: list) -> bool:
    """Return True if at least one vulnerable CPE in *configurations* has part
    type ``o`` (Operating System).  Used to decide whether a missing OS product
    match should be treated as a False Positive rather than skipped.
    """
    for node_group in configurations:
        for node in node_group.get("nodes", []):
            for cm in node.get("cpeMatch", []):
                if not cm.get("vulnerable", False):
                    continue
                cpe = cm.get("criteria", "").lower()
                parts = cpe.split(":")
                if len(parts) > 2 and parts[2] == "o":
                    return True
    return False


def is_version_affected(user_version: str, cpe_matches: list) -> bool | None:
    """Check whether *user_version* falls inside ANY of the supplied cpeMatch
    version ranges.

    Returns:
        True  — version is within a vulnerable range (CVE is relevant)
        False — version is definitely outside all ranges (CVE is a false positive)
        None  — could not determine (no bounds specified, or parse error)
    """
    if not cpe_matches:
        return None

    user_ver = _parse_ver(user_version)
    if user_ver is None:
        return None  # Can't parse user version — don't mark as false positive

    found_bounded = False  # at least one match had explicit version bounds

    for cm in cpe_matches:
        si = cm.get("versionStartIncluding")
        se = cm.get("versionStartExcluding")
        ei = cm.get("versionEndIncluding")
        ee = cm.get("versionEndExcluding")

        # If no bounds at all, this CPE matches all versions
        if not any([si, se, ei, ee]):
            # Check if the criteria itself pins an exact version
            cpe_ver = cm.get("criteria", "").split(":")[5] if ":" in cm.get("criteria", "") else "*"
            if cpe_ver not in ("*", "-", ""):
                exact = _parse_ver(cpe_ver)
                if exact and user_ver == exact:
                    return True
                if exact:
                    found_bounded = True
                    continue  # doesn't match this exact range
            else:
                return None  # wildcard — unpredictable, don't auto-fp

        found_bounded = True
        in_range = True

        if si:
            v = _parse_ver(si)
            if v and user_ver < v:
                in_range = False
        if se:
            v = _parse_ver(se)
            if v and user_ver <= v:
                in_range = False
        if ei:
            v = _parse_ver(ei)
            if v and user_ver > v:
                in_range = False
        if ee:
            v = _parse_ver(ee)
            if v and user_ver >= v:
                in_range = False

        if in_range:
            return True  # found at least one range that contains user's version

    if not found_bounded:
        return None
    return False  # user's version was outside all defined ranges

