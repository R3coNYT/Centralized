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

    result = _extract_cve(vulns[0].get("cve", {}))
    if result is None:
        return None
    return _enrich_from_extra_sources(cve_id, result)


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
    return search_cves_by_keyword(keyword, max_results=50)


# ---------------------------------------------------------------------------
# Multi-source CVE enrichment
# ---------------------------------------------------------------------------

_SOURCE_DRIVERS: dict = {
    "nvd.nist.gov":           "nvd",
    "cve.circl.lu":           "circl",
    "vulnerability.circl.lu": "circl",
    "circl.lu":               "circl",
    "cve.org":                "mitre",
    "cveawg.mitre.org":       "mitre",
    "api.first.org":          "epss",
    "first.org":              "epss",
    "osv.dev":                "osv",
    "api.osv.dev":            "osv",
    "euvd.enisa.europa.eu":   "euvd",
    "enisa.europa.eu":        "euvd",
    "cvedetails.com":         "cvedetails",
    "tenable.com":            "tenable",
    "wiz.io":                 "wiz",
    "vuldb.com":              "vuldb",
    "cvefind.com":            "cvefind",
}


def _detect_driver(url: str) -> str:
    from urllib.parse import urlparse
    host = urlparse(url if "://" in url else "https://" + url).hostname or ""
    for pattern, driver in _SOURCE_DRIVERS.items():
        if pattern in host:
            return driver
    return "generic"


# Human-facing CVE page URL template per driver ({id} is replaced with the CVE ID)
_DRIVER_HUMAN_URLS: dict[str, str] = {
    "nvd":        "https://nvd.nist.gov/vuln/detail/{id}",
    "circl":      "https://vulnerability.circl.lu/vuln/{id}",
    "mitre":      "https://cve.org/CVERecord?id={id}",
    "epss":       "",  # no human-facing per-CVE page
    "osv":        "https://osv.dev/vulnerability/{id}",
    "euvd":       "https://euvd.enisa.europa.eu/vuln/{id}",
    "cvedetails": "https://www.cvedetails.com/cve/{id}/",
    "tenable":    "https://www.tenable.com/cve/{id}",
    "wiz":        "https://www.wiz.io/vulnerability-database/{id}",
    "vuldb":      "https://vuldb.com/?cve.id={id}",
    "cvefind":    "https://www.cvefind.com/cve/{id}",
}

# Short display labels per driver
_DRIVER_LABELS: dict[str, str] = {
    "nvd":        "NVD",
    "circl":      "CIRCL CVE Search",
    "mitre":      "MITRE CVE Program",
    "epss":       "FIRST EPSS",
    "osv":        "OSV",
    "euvd":       "ENISA EUVD",
    "cvedetails": "CVE Details",
    "tenable":    "Tenable Research",
    "wiz":        "Wiz",
    "vuldb":      "VulDB",
    "cvefind":    "CVEFind",
}


def _fetch_circl(cve_id: str) -> dict | None:
    """CIRCL CVE Search — https://cve.circl.lu/api/cve/{id}"""
    try:
        resp = requests.get(
            f"https://cve.circl.lu/api/cve/{cve_id}",
            headers={"User-Agent": "Centralized-PentestTool/1.0"},
            timeout=10,
        )
        if resp.status_code != 200:
            return None
        d = resp.json()
        if not d:
            return None
        refs = [r for r in (d.get("references") or []) if r]
        score = None
        for key in ("cvss3", "cvss"):
            try:
                score = float(d[key]); break
            except (KeyError, ValueError, TypeError):
                pass
        cwe = d.get("cwe", "")
        weaknesses = [cwe] if cwe and not cwe.startswith("NVD-") else []
        return {
            "description": d.get("summary", ""),
            "references":  list(dict.fromkeys(refs)),
            "cvss_score":  score,
            "weaknesses":  weaknesses,
        }
    except Exception:
        return None


def _fetch_mitre(cve_id: str) -> dict | None:
    """MITRE CVE Program API — https://cveawg.mitre.org/api/cve/{id}"""
    try:
        resp = requests.get(
            f"https://cveawg.mitre.org/api/cve/{cve_id}",
            headers={"User-Agent": "Centralized-PentestTool/1.0"},
            timeout=10,
        )
        if resp.status_code != 200:
            return None
        d = resp.json()
        if not d:
            return None
        cna  = d.get("containers", {}).get("cna", {})
        desc = next(
            (item["value"] for item in cna.get("descriptions", [])
             if item.get("lang") in ("en", "en-US")),
            "",
        )
        refs = [r.get("url", "") for r in cna.get("references", []) if r.get("url")]
        return {
            "description": desc,
            "references":  list(dict.fromkeys(r for r in refs if r)),
        }
    except Exception:
        return None


def _fetch_epss(cve_id: str) -> dict | None:
    """FIRST EPSS score — https://api.first.org/data/v1/epss?cve={id}"""
    try:
        resp = requests.get(
            f"https://api.first.org/data/v1/epss?cve={cve_id}",
            headers={"User-Agent": "Centralized-PentestTool/1.0"},
            timeout=10,
        )
        if resp.status_code != 200:
            return None
        entries = resp.json().get("data", [])
        if not entries:
            return None
        e = entries[0]
        return {
            "epss_score":      float(e.get("epss", 0)),
            "epss_percentile": float(e.get("percentile", 0)),
        }
    except Exception:
        return None


def _fetch_osv(cve_id: str) -> dict | None:
    """OSV — https://api.osv.dev/v1/vulns/{id}"""
    try:
        resp = requests.get(
            f"https://api.osv.dev/v1/vulns/{cve_id}",
            headers={"User-Agent": "Centralized-PentestTool/1.0"},
            timeout=10,
        )
        if resp.status_code != 200:
            return None
        d = resp.json()
        if not d:
            return None
        refs = [r.get("url", "") for r in d.get("references", []) if r.get("url")]
        # Extract structured affected package data
        affected_pkgs: list[dict] = []
        for aff in (d.get("affected") or []):
            pkg = aff.get("package") or {}
            eco  = pkg.get("ecosystem", "")
            name = pkg.get("name", "")
            if not eco or not name:
                continue
            ranges_parts: list[str] = []
            for r in (aff.get("ranges") or []):
                evts = r.get("events") or []
                introduced    = next((e.get("introduced")    for e in evts if "introduced"    in e), None)
                fixed_v       = next((e.get("fixed")         for e in evts if "fixed"         in e), None)
                last_affected = next((e.get("last_affected") for e in evts if "last_affected" in e), None)
                parts: list[str] = []
                if introduced and introduced not in ("0", "", None):
                    parts.append(f">= {introduced}")
                if fixed_v:
                    parts.append(f"< {fixed_v}")
                elif last_affected:
                    parts.append(f"<= {last_affected}")
                if parts:
                    ranges_parts.append(", ".join(parts))
            affected_pkgs.append({
                "ecosystem": eco,
                "package":   name,
                "ranges":    " | ".join(ranges_parts) if ranges_parts else "all versions",
                "source":    "OSV",
            })
        return {
            "description":       d.get("summary", "") or d.get("details", ""),
            "references":        list(dict.fromkeys(r for r in refs if r)),
            "affected_packages": affected_pkgs,
        }
    except Exception:
        return None


def _fetch_euvd(cve_id: str) -> dict | None:
    """ENISA EUVD — https://euvd.enisa.europa.eu (public REST API)"""
    page_url = f"https://euvd.enisa.europa.eu/vuln/{cve_id}"
    try:
        resp = requests.get(
            "https://euvd.enisa.europa.eu/api/v1/vuln",
            params={"enisaId": cve_id},
            headers={"User-Agent": "Centralized-PentestTool/1.0", "Accept": "application/json"},
            timeout=12,
        )
        if resp.status_code != 200:
            return {"references": [page_url]}
        raw = resp.json()
        if not raw:
            return {"references": [page_url]}
        # Response may be a list or wrapped dict
        item = (raw[0] if isinstance(raw, list) else
                raw.get("items", [raw])[0] if not isinstance(raw.get("items"), type(None)) else raw)
        refs = [page_url]
        for r in (item.get("references") or []):
            url = r if isinstance(r, str) else r.get("url", "")
            if url and url not in refs:
                refs.append(url)
        score = None
        for key in ("baseScore", "cvssScore", "cvss3Score", "cvssV3Score"):
            try:
                score = float(item.get(key) or 0) or None
                if score:
                    break
            except (ValueError, TypeError):
                pass
        cwes = []
        for cwe in (item.get("cwes") or item.get("cwe") or []):
            val = cwe if isinstance(cwe, str) else cwe.get("id", "")
            if val and not val.startswith("NVD-") and val not in cwes:
                cwes.append(val)
        return {
            "description": item.get("description") or item.get("summary") or "",
            "references":  list(dict.fromkeys(refs)),
            "cvss_score":  score,
            "weaknesses":  cwes,
        }
    except Exception:
        return {"references": [page_url]}


# ── Link-only enrichment sources ────────────────────────────────────────────
# No public machine-readable API — adds a direct CVE page URL as a reference
# so users can click through from the "All References" panel.

def _fetch_cvedetails(cve_id: str) -> dict | None:
    """CVE Details — https://www.cvedetails.com"""
    return {"references": [f"https://www.cvedetails.com/cve/{cve_id}/"]}


def _fetch_tenable(cve_id: str) -> dict | None:
    """Tenable Research — https://www.tenable.com/cve"""
    return {"references": [f"https://www.tenable.com/cve/{cve_id}"]}


def _fetch_wiz(cve_id: str) -> dict | None:
    """Wiz Vulnerability Database — https://www.wiz.io"""
    return {"references": [f"https://www.wiz.io/vulnerability-database/{cve_id}"]}


def _fetch_vuldb(cve_id: str) -> dict | None:
    """VulDB — https://vuldb.com"""
    return {"references": [f"https://vuldb.com/?cve.id={cve_id}"]}


def _fetch_cvefind(cve_id: str) -> dict | None:
    """CVEFind — https://www.cvefind.com"""
    return {"references": [f"https://www.cvefind.com/cve/{cve_id}"]}


_DRIVER_FETCHERS: dict = {
    "circl":      _fetch_circl,
    "mitre":      _fetch_mitre,
    "epss":       _fetch_epss,
    "osv":        _fetch_osv,
    "euvd":       _fetch_euvd,
    "cvedetails": _fetch_cvedetails,
    "tenable":    _fetch_tenable,
    "wiz":        _fetch_wiz,
    "vuldb":      _fetch_vuldb,
    "cvefind":    _fetch_cvefind,
}


def _enrich_from_extra_sources(cve_id: str, base: dict) -> dict:
    """
    Fan-out to all enabled non-NVD CveSource records and merge results into base.
    Supplements: references (+meta), weaknesses, affected_packages, source_links,
    description (fallback), EPSS score, CVSS fallback.
    """
    import json as _json
    try:
        from models import CveSource
        sources = CveSource.query.filter_by(enabled=True, is_builtin=False).all()
    except Exception:
        sources = []

    try:
        existing_refs = _json.loads(base.get("references", "[]"))
    except Exception:
        existing_refs = []

    # Track which source(s) provided each URL
    refs_meta: dict[str, list[str]] = {}
    for ref in existing_refs:
        if ref:
            refs_meta[ref] = ["NVD"]

    all_refs          = list(existing_refs)
    weaknesses        = list(base.get("weaknesses", []))
    affected_packages: list[dict] = list(base.get("affected_packages", []))

    # NVD is always the first entry in source_links
    source_links: list[dict] = [{
        "label":  "NVD — National Vulnerability Database",
        "url":    f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "driver": "nvd",
    }]

    for src in sources:
        driver = src.driver if src.driver and src.driver not in ("generic", "") else _detect_driver(src.url)
        label  = _DRIVER_LABELS.get(driver, src.label or driver)

        # Build the human-facing URL for this source
        url_tmpl   = _DRIVER_HUMAN_URLS.get(driver, "")
        human_url  = url_tmpl.replace("{id}", cve_id) if url_tmpl else ""
        if human_url and driver != "epss":
            source_links.append({"label": label, "url": human_url, "driver": driver})

        fetcher = _DRIVER_FETCHERS.get(driver)
        if fetcher is None:
            continue
        try:
            extra = fetcher(cve_id)
            if not extra:
                continue
            if not base.get("description") and extra.get("description"):
                base["description"] = extra["description"]
            for ref in extra.get("references", []):
                if not ref:
                    continue
                if ref not in refs_meta:
                    refs_meta[ref] = [label]
                    all_refs.append(ref)
                elif label not in refs_meta[ref]:
                    refs_meta[ref].append(label)
            for cwe in extra.get("weaknesses", []):
                if cwe and cwe not in weaknesses:
                    weaknesses.append(cwe)
            if extra.get("epss_score") is not None:
                base["epss_score"]      = extra["epss_score"]
                base["epss_percentile"] = extra.get("epss_percentile", 0.0)
            if base.get("cvss_score") is None and extra.get("cvss_score"):
                base["cvss_score"] = extra["cvss_score"]
            for pkg in extra.get("affected_packages", []):
                key = (pkg.get("ecosystem", "").lower(), pkg.get("package", "").lower())
                if not any(
                    (p.get("ecosystem", "").lower(), p.get("package", "").lower()) == key
                    for p in affected_packages
                ):
                    affected_packages.append(pkg)
        except Exception:
            pass

    base["references"]        = _json.dumps(all_refs[:20])
    base["references_meta"]   = refs_meta          # {url: [source_label, ...]}
    base["source_links"]      = source_links        # [{label, url, driver}, ...]
    base["affected_packages"] = affected_packages   # [{ecosystem, package, ranges, source}, ...]
    if weaknesses:
        base["weaknesses"] = weaknesses
    return base

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
    # Deduplicate while preserving order
    all_ref_urls = list(dict.fromkeys(r.get("url", "") for r in refs if r.get("url")))

    # References tagged as patches / fixes / workarounds
    PATCH_TAGS = {"Patch", "Fix", "Mitigation", "Vendor Advisory", "Third Party Advisory"}
    patch_refs = list(dict.fromkeys(
        r["url"] for r in refs
        if r.get("url") and PATCH_TAGS.intersection(set(r.get("tags", [])))
    ))
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
    # Initialise references_meta so NVD refs are already attributed before enrichment
    refs_meta_init: dict[str, list[str]] = {url: ["NVD"] for url in all_ref_urls[:10]}
    return {
        "cve_id": cve_id,
        "title": cve_id,
        "description": desc_en,
        "severity": severity.upper() if severity else "UNKNOWN",
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "references": _json.dumps(all_ref_urls[:10]),
        "references_meta": refs_meta_init,
        "patch_refs": patch_refs[:8],
        "patch_available": patch_available,
        "weaknesses": weaknesses,
        "exploited_in_wild": exploited_in_wild,
        "cisa_remediation": cisa_remediation,
        "published": cve.get("published", ""),
        "last_modified": cve.get("lastModified", ""),
        "vuln_status": cve.get("vulnStatus", ""),
        "configurations": cve.get("configurations", []),
        "affected_packages": [],
        "source_links": [],
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


# ---------------------------------------------------------------------------
# Step-by-step remediation builder
# ---------------------------------------------------------------------------

# ── CPE product → package manager commands ──────────────────────────────────
# List of (vendor_substr, product_substr, info_dict) — first match wins.
# info_dict keys: apt, yum, apk, pip, npm, gem, choco, winget,
#                 restart, verify, note
_CPE_PKG_MAP: list[tuple[str, str, dict]] = [
    # ─── Web / HTTP servers ──────────────────────────────────────────────────
    ("apache", "http_server", {
        "apt": "apache2", "yum": "httpd", "apk": "apache2", "choco": "apache-httpd",
        "restart": "sudo systemctl restart apache2   # Debian/Ubuntu\nsudo systemctl restart httpd      # RHEL/CentOS",
        "verify": "apache2 -v 2>/dev/null || httpd -v",
    }),
    ("nginx", "nginx", {
        "apt": "nginx", "yum": "nginx", "apk": "nginx", "choco": "nginx",
        "restart": "sudo systemctl restart nginx",
        "verify": "nginx -v",
    }),
    ("lighttpd", "lighttpd", {
        "apt": "lighttpd", "yum": "lighttpd",
        "restart": "sudo systemctl restart lighttpd",
        "verify": "lighttpd -v",
    }),
    # ─── Java application servers ────────────────────────────────────────────
    ("apache", "tomcat", {
        "apt": "tomcat9 tomcat10", "yum": "tomcat",
        "restart": "sudo systemctl restart tomcat",
        "verify": "catalina.sh version 2>/dev/null || /usr/share/tomcat/bin/version.sh",
    }),
    ("eclipse", "jetty", {
        "apt": "jetty9",
        "restart": "sudo systemctl restart jetty",
        "note": "If running standalone Jetty, download the patched JARs from https://www.eclipse.org/jetty/",
    }),
    # ─── SSL / TLS ───────────────────────────────────────────────────────────
    ("openssl", "openssl", {
        "apt": "openssl libssl-dev", "yum": "openssl openssl-devel", "apk": "openssl",
        "choco": "openssl",
        "verify": "openssl version",
    }),
    ("gnutls", "gnutls", {
        "apt": "libgnutls30 gnutls-bin", "yum": "gnutls",
        "verify": "gnutls-cli --version",
    }),
    ("mozilla", "nss", {
        "apt": "libnss3 libnss3-dev", "yum": "nss",
        "verify": "python3 -c \"import ssl; print(ssl.OPENSSL_VERSION)\"",
    }),
    # ─── SSH ─────────────────────────────────────────────────────────────────
    ("openssh", "openssh", {
        "apt": "openssh-server openssh-client", "yum": "openssh-server openssh-clients",
        "apk": "openssh",
        "restart": "sudo systemctl restart sshd",
        "verify": "sshd -V 2>&1 | head -1 || ssh -V",
    }),
    # ─── Languages / Runtimes ────────────────────────────────────────────────
    ("python", "python", {
        "apt": "python3 python3-dev", "yum": "python3", "apk": "python3",
        "choco": "python3",
        "verify": "python3 --version",
    }),
    ("php", "php", {
        "apt": "php php-common", "yum": "php", "apk": "php",
        "restart": "sudo systemctl restart php-fpm || sudo systemctl restart apache2",
        "verify": "php -v | head -1",
    }),
    ("perl",  "perl",  {"apt": "perl",       "yum": "perl",  "apk": "perl",   "verify": "perl --version | head -2"}),
    ("ruby",  "ruby",  {"apt": "ruby ruby-dev","yum": "ruby", "apk": "ruby",  "verify": "ruby --version"}),
    ("node",  "node",  {
        "apt": "nodejs npm", "yum": "nodejs npm", "apk": "nodejs npm",
        "choco": "nodejs-lts",
        "verify": "node --version && npm --version",
    }),
    ("java",  "jdk",   {"apt": "default-jdk",     "yum": "java-17-openjdk-devel", "choco": "temurin17",    "verify": "java -version 2>&1 | head -1"}),
    ("java",  "jre",   {"apt": "default-jre",     "yum": "java-17-openjdk",       "choco": "temurin17jre", "verify": "java -version 2>&1 | head -1"}),
    # ─── Databases ───────────────────────────────────────────────────────────
    ("mysql",       "mysql",       {"apt": "mysql-server mysql-client",         "yum": "mysql-server mysql",         "restart": "sudo systemctl restart mysql",       "verify": "mysql --version"}),
    ("oracle",      "mysql",       {"apt": "mysql-server mysql-client",         "yum": "mysql-server mysql",         "restart": "sudo systemctl restart mysql",       "verify": "mysql --version"}),
    ("mariadb",     "mariadb",     {"apt": "mariadb-server mariadb-client",     "yum": "mariadb-server mariadb",     "restart": "sudo systemctl restart mariadb",     "verify": "mysql --version"}),
    ("postgresql",  "postgresql",  {"apt": "postgresql postgresql-client",      "yum": "postgresql-server postgresql","apk": "postgresql", "restart": "sudo systemctl restart postgresql", "verify": "psql --version"}),
    ("redis",       "redis",       {"apt": "redis-server",                      "yum": "redis",                      "apk": "redis",       "restart": "sudo systemctl restart redis",       "verify": "redis-server --version"}),
    ("mongodb",     "mongodb",     {"apt": "mongodb-org",                       "yum": "mongodb-org",                "restart": "sudo systemctl restart mongod",      "verify": "mongod --version",
                                    "note": "MongoDB requires its own repo. See: https://www.mongodb.com/docs/manual/administration/install-on-linux/"}),
    ("elastic",     "elasticsearch", {
        "apt": "elasticsearch", "yum": "elasticsearch",
        "restart": "sudo systemctl restart elasticsearch",
        "verify": "curl -s http://localhost:9200 | python3 -m json.tool | grep number",
        "note": "Elasticsearch requires its own APT/YUM repo. See: https://www.elastic.co/guide/en/elasticsearch/reference/current/install-elasticsearch.html",
    }),
    # ─── DNS / Mail / Directory ──────────────────────────────────────────────
    ("isc",       "bind",     {"apt": "bind9 bind9utils",                  "yum": "bind",            "apk": "bind",      "restart": "sudo systemctl restart named || sudo systemctl restart bind9", "verify": "named -v"}),
    ("postfix",   "postfix",  {"apt": "postfix",                           "yum": "postfix",                             "restart": "sudo systemctl restart postfix",      "verify": "postconf mail_version"}),
    ("dovecot",   "dovecot",  {"apt": "dovecot-core dovecot-imapd dovecot-pop3d", "yum": "dovecot",                      "restart": "sudo systemctl restart dovecot",      "verify": "dovecot --version"}),
    ("exim",      "exim",     {"apt": "exim4",                             "yum": "exim",                                "restart": "sudo systemctl restart exim4",        "verify": "exim --version 2>&1 | head -1"}),
    ("samba",     "samba",    {"apt": "samba",                             "yum": "samba",                               "restart": "sudo systemctl restart smbd nmbd",    "verify": "smbd --version"}),
    ("openldap",  "openldap", {"apt": "slapd ldap-utils",                  "yum": "openldap-servers openldap-clients",   "restart": "sudo systemctl restart slapd",        "verify": "slapd -VV 2>&1 | head -1"}),
    # ─── VPN / Proxy ─────────────────────────────────────────────────────────
    ("openvpn",   "openvpn",  {"apt": "openvpn",  "yum": "openvpn",  "restart": "sudo systemctl restart openvpn", "verify": "openvpn --version | head -1"}),
    ("wireguard", "wireguard",{"apt": "wireguard", "yum": "wireguard-tools",                                         "verify": "wg --version"}),
    ("squid",     "squid",    {"apt": "squid",     "yum": "squid",     "restart": "sudo systemctl restart squid",   "verify": "squid -v | head -1"}),
    # ─── CMS ─────────────────────────────────────────────────────────────────
    ("wordpress", "wordpress",{"note": "Update via WordPress admin (Dashboard → Updates) or using WP-CLI:",  "verify": "wp core version"}),
    ("drupal",    "drupal",   {"note": "Update via Drupal admin (Reports → Available updates) or Composer:", "verify": "drush status | grep 'Drupal version'"}),
    ("joomla",    "joomla",   {"note": "Update via Joomla! admin panel (Components → Joomla! Update):"}),
    # ─── System utilities ────────────────────────────────────────────────────
    ("gnu",      "bash",        {"apt": "bash",                  "yum": "bash",     "apk": "bash",        "verify": "bash --version | head -1"}),
    ("gnu",      "glibc",       {"apt": "libc6 libc-bin",        "yum": "glibc",                          "verify": "ldd --version | head -1",     "note": "After updating glibc, reboot the host."}),
    ("haxx",     "curl",        {"apt": "curl libcurl4",         "yum": "curl",     "apk": "curl",   "choco": "curl",   "verify": "curl --version | head -1"}),
    ("gnu",      "wget",        {"apt": "wget",                  "yum": "wget",                           "verify": "wget --version | head -1"}),
    ("linux",    "linux_kernel",{"apt": "linux-image-generic linux-headers-generic", "yum": "kernel",     "verify": "uname -r",                    "note": "After updating the kernel, reboot:\n  sudo reboot"}),
    ("sudo",     "sudo",        {"apt": "sudo",                  "yum": "sudo",                           "verify": "sudo --version | head -1"}),
    ("polkit",   "polkit",      {"apt": "policykit-1 polkitd",   "yum": "polkit",                         "verify": "pkaction --version 2>&1"}),
    ("systemd",  "systemd",     {"apt": "systemd",               "yum": "systemd",                        "verify": "systemctl --version | head -1","note": "Reboot after updating systemd."}),
    ("gnu_project","tar",       {"apt": "tar",                   "yum": "tar",                            "verify": "tar --version | head -1"}),
    # ─── Python packages ─────────────────────────────────────────────────────
    ("pallets",      "flask",        {"pip": "flask",        "verify": "python3 -c \"import flask; print(flask.__version__)\""}),
    ("django",       "django",       {"pip": "django",       "verify": "python3 -c \"import django; print(django.__version__)\""}),
    ("cryptography", "cryptography", {"pip": "cryptography", "verify": "python3 -c \"import cryptography; print(cryptography.__version__)\""}),
    ("pyjwt",        "pyjwt",        {"pip": "PyJWT",        "verify": "python3 -c \"import jwt; print(jwt.__version__)\""}),
    ("urllib3",      "urllib3",      {"pip": "urllib3",      "verify": "python3 -c \"import urllib3; print(urllib3.__version__)\""}),
    ("psf",          "requests",     {"pip": "requests",     "verify": "python3 -c \"import requests; print(requests.__version__)\""}),
    ("pillow",       "pillow",       {"pip": "pillow",       "verify": "python3 -c \"from PIL import Image; print(Image.__version__)\""}),
    ("sqlalchemy",   "sqlalchemy",   {"pip": "sqlalchemy",   "verify": "python3 -c \"import sqlalchemy; print(sqlalchemy.__version__)\""}),
    ("paramiko",     "paramiko",     {"pip": "paramiko",     "verify": "python3 -c \"import paramiko; print(paramiko.__version__)\""}),
    ("werkzeug",     "werkzeug",     {"pip": "werkzeug",     "verify": "python3 -c \"import werkzeug; print(werkzeug.__version__)\""}),
    ("jinja2",       "jinja2",       {"pip": "jinja2",       "verify": "python3 -c \"import jinja2; print(jinja2.__version__)\""}),
    # ─── Node.js packages ────────────────────────────────────────────────────
    ("expressjs", "express", {"npm": "express", "verify": "node -e \"console.log(require('express/package.json').version)\""}),
    ("lodash",    "lodash",  {"npm": "lodash",  "verify": "node -e \"console.log(require('lodash/package.json').version)\""}),
    ("axios",     "axios",   {"npm": "axios",   "verify": "node -e \"console.log(require('axios/package.json').version)\""}),
]


def _match_cpe_pkg(vendor: str, product: str) -> dict | None:
    """Return first matching package info from _CPE_PKG_MAP."""
    v = vendor.lower().replace("-", "_").replace(" ", "_")
    p = product.lower().replace("-", "_").replace(" ", "_")
    for vm, pm, info in _CPE_PKG_MAP:
        if vm.replace("-", "_") in v and pm.replace("-", "_") in p:
            return info
    return None


def _extract_cpe_targets(configurations: list) -> list[tuple[str, str, str | None]]:
    """
    From NVD CPE configurations, extract unique (vendor, product, fixed_ver) tuples.
    fixed_ver is versionEndExcluding (the first non-vulnerable version).
    """
    seen: set[tuple[str, str]] = set()
    targets: list[tuple[str, str, str | None]] = []
    for node_group in configurations:
        for node in (node_group.get("nodes") or []):
            for cm in (node.get("cpeMatch") or []):
                if not cm.get("vulnerable", False):
                    continue
                cpe = cm.get("criteria", "")
                parts = cpe.split(":")          # cpe:2.3:a:vendor:product:ver:...
                vendor  = parts[3] if len(parts) > 3 else ""
                product = parts[4] if len(parts) > 4 else ""
                if not vendor or not product:
                    continue
                key = (vendor, product)
                if key in seen:
                    continue
                seen.add(key)
                fixed_ver = cm.get("versionEndExcluding") or cm.get("versionEndIncluding") or None
                targets.append((vendor, product, fixed_ver))
                if len(targets) >= 5:
                    return targets
    return targets


def _build_update_commands(pkg: dict, fixed_ver: str | None,
                           product_label: str, current_ver: str | None) -> list[dict]:
    """Build a list of {label, code} command blocks for a detected package."""
    cmds: list[dict] = []
    cv_note = f"  # currently {current_ver}" if current_ver else ""
    fv_note  = f"\n\n# Target: update to {fixed_ver} or later" if fixed_ver else ""

    if pkg.get("apt"):
        cmds.append({"label": "Debian / Ubuntu", "code": (
            f"# 1. Update package lists\nsudo apt-get update\n\n"
            f"# 2. Upgrade the package{cv_note}\nsudo apt-get install --only-upgrade {pkg['apt']}{fv_note}"
        )})

    if pkg.get("yum"):
        cmds.append({"label": "RHEL / CentOS / Fedora", "code": (
            f"# CentOS / RHEL 7 (yum)\nsudo yum update {pkg['yum']}{cv_note}\n\n"
            f"# RHEL 8+ / Fedora / CentOS Stream (dnf)\nsudo dnf update {pkg['yum']}{fv_note}"
        )})

    if pkg.get("apk"):
        cmds.append({"label": "Alpine Linux", "code": (
            f"sudo apk update\nsudo apk upgrade {pkg['apk']}{cv_note}"
        )})

    if pkg.get("choco"):
        ver_flag = f" --version {fixed_ver}" if fixed_ver else ""
        cmds.append({"label": "Windows (Chocolatey)", "code": (
            f"choco upgrade {pkg['choco']}{ver_flag}{cv_note}"
        )})

    if pkg.get("winget"):
        cmds.append({"label": "Windows (winget)", "code": (
            f"winget upgrade {pkg['winget']}{cv_note}"
        )})

    if pkg.get("pip"):
        ver_pin = f">={fixed_ver}" if fixed_ver else ""
        cmds.append({"label": "Python (pip)", "code": (
            f"pip install --upgrade \"{pkg['pip']}{ver_pin}\"\n\n"
            f"# Pin in requirements.txt:\n{pkg['pip']}>={fixed_ver or 'PATCHED_VERSION'}"
        )})

    if pkg.get("npm"):
        ver_pin = f"@{fixed_ver}" if fixed_ver else "@latest"
        cmds.append({"label": "Node.js (npm)", "code": (
            f"# In your project directory:\nnpm install {pkg['npm']}{ver_pin}\n\n"
            f"# Or globally:\nnpm install -g {pkg['npm']}{ver_pin}"
        )})

    if pkg.get("gem"):
        ver_pin = f' -v ">={fixed_ver}"' if fixed_ver else ""
        cmds.append({"label": "Ruby (gem)", "code": f"gem update {pkg['gem']}{ver_pin}"})

    if pkg.get("restart"):
        cmds.append({"label": "Restart service", "code": pkg["restart"]})

    if pkg.get("verify"):
        cmds.append({"label": "Verify version", "code": f"# Confirm the installed version\n{pkg['verify']}"})

    return cmds


# CWE IDs that require a code-level fix (not a package update)
_CODE_FIX_CWES: dict[str, tuple[str, str, str]] = {
    "CWE-79": (
        "Fix Cross-Site Scripting (XSS) — output encoding + CSP",
        (
            "# 1. Enable auto-escaping in the templating engine\n"
            "# Jinja2:\nenv = Environment(autoescape=True)\n\n"
            "# React — always use JSX instead of dangerouslySetInnerHTML\n\n"
            "# PHP:\necho htmlspecialchars($output, ENT_QUOTES, 'UTF-8');\n\n"
            "# 2. Add a Content Security Policy response header\n"
            "Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{RANDOM}'; object-src 'none';\n\n"
            "# 3. Harden session cookies\nSet-Cookie: session=...; HttpOnly; Secure; SameSite=Strict"
        ),
        "bi-code-slash",
    ),
    "CWE-89": (
        "Fix SQL Injection — use parameterised queries",
        (
            "# BAD — never concatenate user input into SQL:\nquery = 'SELECT * FROM users WHERE name = ' + user_input\n\n"
            "# GOOD — Python DB-API parameterized:\ncursor.execute('SELECT * FROM users WHERE name = %s', (user_input,))\n\n"
            "# GOOD — SQLAlchemy ORM:\nUser.query.filter_by(name=user_input).first()\n\n"
            "# GOOD — Django ORM:\nUser.objects.filter(name=user_input).first()\n\n"
            "# Also: restrict the DB account — remove DROP/CREATE/ALTER privileges:\n"
            "REVOKE ALL ON *.* FROM 'app_user'@'localhost';\nGRANT SELECT, INSERT, UPDATE, DELETE ON app_db.* TO 'app_user'@'localhost';"
        ),
        "bi-database-lock",
    ),
    "CWE-78": (
        "Fix OS Command Injection — avoid shell=True",
        (
            "# BAD — never build shell commands from user input:\nos.system('ping ' + user_input)\nsubprocess.run('ls ' + path, shell=True)\n\n"
            "# GOOD — use a list (shell=False, the default):\nimport subprocess\nsubprocess.run(['ping', '-c', '4', user_input], shell=False)\n\n"
            "# If shell execution is unavoidable, enforce a strict allowlist:\nimport re\n"
            "if not re.fullmatch(r'[a-zA-Z0-9._-]+', user_input):\n    raise ValueError('Invalid input — rejected')"
        ),
        "bi-terminal",
    ),
    "CWE-22": (
        "Fix Path Traversal — canonicalize and jail file paths",
        (
            "import os\nBASE_DIR = '/var/app/uploads'\n\n"
            "# Resolve the real absolute path\nreal_path = os.path.realpath(os.path.join(BASE_DIR, user_filename))\n\n"
            "# Reject anything that escapes the base directory\nif not real_path.startswith(BASE_DIR + os.sep):\n"
            "    raise ValueError('Path traversal attempt detected')\n\n"
            "with open(real_path, 'rb') as f:\n    data = f.read()"
        ),
        "bi-folder-lock",
    ),
    "CWE-287": (
        "Fix weak authentication",
        (
            "# 1. Use strong password hashing (Argon2 recommended):\nfrom argon2 import PasswordHasher\n"
            "ph = PasswordHasher()\nhashed = ph.hash(plain_password)\nph.verify(hashed, plain_password)  # on login\n\n"
            "# 2. Rate-limit the login endpoint (Flask-Limiter):\nfrom flask_limiter import Limiter\n@limiter.limit('5 per minute')\ndef login(): ...\n\n"
            "# 3. Enforce MFA for privileged accounts (TOTP example with pyotp):\nimport pyotp\ntotp = pyotp.TOTP(user_secret)\nif not totp.verify(user_token):\n    abort(403)"
        ),
        "bi-key",
    ),
    "CWE-352": (
        "Fix CSRF — add tokens to all state-changing endpoints",
        (
            "# Flask-WTF handles this automatically. Manual approach:\nimport secrets\n\n"
            "# On session start, generate a token:\nsession['csrf_token'] = secrets.token_hex(32)\n\n"
            "# In every HTML form:\n<input type=\"hidden\" name=\"csrf_token\" value=\"{{ session.csrf_token }}\">\n\n"
            "# Validate on every POST/PUT/DELETE:\nif request.form.get('csrf_token') != session.get('csrf_token'):\n    abort(403)\n\n"
            "# Also set SameSite=Strict on session cookies:\nresponse.set_cookie('session', value, samesite='Strict', secure=True)"
        ),
        "bi-shield-lock",
    ),
    "CWE-434": (
        "Fix unrestricted file upload",
        (
            "import magic, uuid, os\n\n"
            "ALLOWED_MIME = {'image/jpeg', 'image/png', 'application/pdf'}\nMAX_SIZE = 5 * 1024 * 1024  # 5 MB\n\n"
            "data = file.read(2048); file.seek(0)\n"
            "if magic.from_buffer(data, mime=True) not in ALLOWED_MIME:\n    abort(400, 'File type not allowed')\nif file.seek(0, 2) > MAX_SIZE:\n    abort(400, 'File too large')\nfile.seek(0)\n\n"
            "# Store with a UUID name outside the web root:\nsave_path = os.path.join('/var/uploads', str(uuid.uuid4()))\nfile.save(save_path)\n\n"
            "# Serve with Content-Disposition: attachment to prevent browser execution"
        ),
        "bi-file-earmark-lock",
    ),
    "CWE-502": (
        "Fix unsafe deserialization — replace pickle with JSON",
        (
            "# SAFE alternative — JSON does not execute code:\nimport json\ndata = json.loads(user_input)\n\n"
            "# If pickle is unavoidable, use an allowlist unpickler:\nimport pickle\n\n"
            "class SafeUnpickler(pickle.Unpickler):\n"
            "    ALLOWED = {('builtins', 'dict'), ('myapp.models', 'Report')}\n"
            "    def find_class(self, module, name):\n"
            "        if (module, name) not in self.ALLOWED:\n"
            "            raise pickle.UnpicklingError(f'Forbidden: {module}.{name}')\n"
            "        return super().find_class(module, name)\n\n"
            "data = SafeUnpickler(io.BytesIO(user_bytes)).load()"
        ),
        "bi-shield-x",
    ),
    "CWE-798": (
        "Remove hardcoded credentials and rotate them immediately",
        (
            "# 1. Remove the secret from source code right now.\n"
            "# 2. Rotate the credential — assume it is already compromised.\n\n"
            "# 3. Inject via environment variable:\nimport os\ndb_password = os.environ['DB_PASSWORD']\n\n"
            "# 4. Or use a secrets manager:\n# AWS Secrets Manager:\naws secretsmanager get-secret-value --secret-id prod/db/password\n\n"
            "# HashiCorp Vault:\nvault kv get secret/db/password\n\n"
            "# 5. Scan all git history for other leaked secrets:\npip install trufflehog\ntrufflehog git file://. --since-commit HEAD~200"
        ),
        "bi-key",
    ),
    "CWE-611": (
        "Disable XML External Entity processing (XXE fix)",
        (
            "# Python (lxml):\nfrom lxml import etree\nparser = etree.XMLParser(resolve_entities=False, no_network=True)\ntree = etree.parse(source, parser)\n\n"
            "# Java (DocumentBuilderFactory):\nfactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);\nfactory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n\n"
            "# PHP:\nlibxml_disable_entity_loader(true);  // PHP < 8.0\n// PHP 8.0+: disabled by default\n\n"
            "# .NET (XmlReader):\nvar settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit };"
        ),
        "bi-file-earmark-x",
    ),
}


def build_remediation_steps(cve_data: dict,
                            affected_products: list[dict] | None = None) -> list[dict]:
    """
    Generate specific, actionable step-by-step remediation for a CVE.

    Uses NVD CPE configurations to identify the exact affected software and
    produces package-manager-specific update commands (apt / yum / pip / npm …).

    Args:
        cve_data:          Merged dict from lookup_cve() + DB (must include 'configurations').
        affected_products: Optional [{product, version, cpe, os_info}] from Port records.

    Returns a list of step dicts:
        {step, title, description, icon, priority, commands}
        where commands is a list of {label, code} blocks.
    """
    steps: list[dict] = []
    seen_titles: set[str] = set()

    def add(title: str, description: str, icon: str = "bi-check-circle",
            priority: str = "normal", commands: list | None = None) -> None:
        if title not in seen_titles:
            seen_titles.add(title)
            steps.append({
                "step": 0,
                "title": title,
                "description": description,
                "icon": icon,
                "priority": priority,
                "commands": commands or [],
            })

    # ── 1. CISA KEV urgency ────────────────────────────────────────────────────
    if cve_data.get("exploited_in_wild"):
        cisa_action = cve_data.get("cisa_remediation") or ""
        add(
            "URGENT — actively exploited in the wild (CISA KEV)",
            ("CISA Required Action: " + cisa_action) if cisa_action else (
                "This CVE is in the CISA KEV catalogue — it is being actively used by attackers. "
                "Apply the fix below immediately, do not wait for a maintenance window."
            ),
            "bi-fire", "critical",
        )

    # ── 2. CPE-driven product update commands ─────────────────────────────────
    configurations = cve_data.get("configurations", [])
    cpe_targets    = _extract_cpe_targets(configurations)
    detected       = affected_products or []

    if cpe_targets:
        for vendor, product, fixed_ver in cpe_targets:
            pkg = _match_cpe_pkg(vendor, product)
            pl  = f"{vendor.replace('_', ' ').title()} {product.replace('_', ' ').title()}"

            # Match against detected product/version from host Port scan
            current_ver: str | None = None
            for d in detected:
                dp = (d.get("product") or "").lower()
                if vendor.lower() in dp or product.lower() in dp:
                    current_ver = d.get("version")
                    break

            if pkg:
                note = pkg.get("note", "")
                desc = (
                    f"Affected software: **{pl}**"
                    + (f" — detected version: **{current_ver}**" if current_ver else "")
                    + (f" — upgrade to: **{fixed_ver}** or later" if fixed_ver else "")
                    + (f"\n\n{note}" if note else "")
                )
                cmds = _build_update_commands(pkg, fixed_ver, pl, current_ver)

                # CMS with no standard pkg manager → generate specific CLI steps
                if not cmds and "wordpress" in product.lower():
                    cmds = [
                        {"label": "WP-CLI", "code": (
                            "# Update WordPress core\nwp core update\n\n"
                            "# Update all plugins (vulnerabilities are often in plugins)\nwp plugin update --all\n\n"
                            "# Update all themes\nwp theme update --all"
                        )},
                        {"label": "Verify", "code": "wp core version"},
                    ]
                elif not cmds and "drupal" in product.lower():
                    cmds = [
                        {"label": "Composer", "code": "composer require drupal/core-recommended:^10\ncomposer update drupal/core --with-dependencies"},
                        {"label": "Drush",    "code": "drush pm-update drupal\ndrush cr"},
                    ]
                elif not cmds and "joomla" in product.lower():
                    cmds = [{"label": "CLI", "code": "php cli/joomla.php core:update"}]

                add(f"Update {pl}", desc, "bi-arrow-up-circle-fill", "critical", cmds)

            else:
                patch_refs = cve_data.get("patch_refs") or []
                ref_block  = "\n".join(patch_refs[:6]) if patch_refs else "# (check NVD references for the vendor advisory)"
                add(
                    f"Apply vendor patch for {pl}",
                    (
                        f"No automated package entry found for **{pl}**. "
                        f"Download and install the fixed release from the vendor."
                        + (f"\n\nFixed version: {fixed_ver}" if fixed_ver else "")
                    ),
                    "bi-download", "critical",
                    [{"label": "Vendor / patch references", "code": f"# Download the patched release from:\n{ref_block}"}],
                )
    else:
        # No CPE config in NVD — try to match detected port-scan products first
        patch_refs = cve_data.get("patch_refs") or []
        matched_any = False

        for d in detected:
            raw = (d.get("product") or "").lower().replace(" ", "_").replace("-", "_")
            if not raw:
                continue
            # Loose single-field match against the CPE map
            pkg = None
            for vm, pm, info in _CPE_PKG_MAP:
                if vm in raw or pm in raw:
                    pkg = info
                    break
            if pkg:
                pl          = d.get("product") or pm
                current_ver = d.get("version")
                cmds        = _build_update_commands(pkg, None, pl, current_ver)
                note        = pkg.get("note", "")
                desc = (
                    f"Affected software: **{pl}**"
                    + (f" — detected version: **{current_ver}**" if current_ver else "")
                    + "\n\nNVD does not list a fixed version — update to the latest stable release."
                    + (f"\n\n{note}" if note else "")
                )
                add(f"Update {pl}", desc, "bi-arrow-up-circle-fill", "critical", cmds)
                matched_any = True

        # Also try OSV affected packages for ecosystem-specific update commands
        for pkg_info in (cve_data.get("affected_packages") or []):
            eco  = pkg_info.get("ecosystem", "")
            name = pkg_info.get("package", "")
            rng  = pkg_info.get("ranges", "")
            if not eco or not name:
                continue
            t = f"Update {name} ({eco})"
            if t in seen_titles:
                continue
            eco_lower = eco.lower()
            if eco_lower in ("pypi", "python"):
                eco_cmds = [{"label": "pip", "code": f"pip install --upgrade \"{name}\"\n# Affected versions: {rng}"}]
            elif eco_lower in ("npm", "node", "node.js"):
                eco_cmds = [{"label": "npm", "code": f"npm install {name}@latest\n# Affected versions: {rng}"}]
            elif eco_lower in ("maven", "gradle"):
                eco_cmds = [{"label": "Maven/Gradle", "code": f"# Update {name} to latest patched version in pom.xml / build.gradle\n# Affected versions: {rng}"}]
            elif eco_lower in ("go", "golang"):
                eco_cmds = [{"label": "Go modules", "code": f"go get -u {name}\ngo mod tidy\n# Affected versions: {rng}"}]
            elif eco_lower in ("cargo", "rust"):
                eco_cmds = [{"label": "Cargo", "code": f"cargo update -p {name}\n# Affected versions: {rng}"}]
            elif eco_lower in ("rubygems", "ruby"):
                eco_cmds = [{"label": "gem", "code": f"gem update {name}\n# Affected versions: {rng}"}]
            elif eco_lower in ("nuget", ".net"):
                eco_cmds = [{"label": "NuGet", "code": f"dotnet add package {name}\n# Affected versions: {rng}"}]
            elif eco_lower in ("packagist", "composer", "php"):
                eco_cmds = [{"label": "Composer", "code": f"composer require {name}\n# Affected versions: {rng}"}]
            elif eco_lower in ("debian", "ubuntu"):
                eco_cmds = [{"label": "apt", "code": f"sudo apt-get update\nsudo apt-get install --only-upgrade {name}\n# Affected versions: {rng}"}]
            elif eco_lower in ("centos", "rhel", "fedora", "almalinux"):
                eco_cmds = [{"label": "dnf/yum", "code": f"sudo dnf update {name}\n# Affected versions: {rng}"}]
            else:
                eco_cmds = [{"label": eco, "code": f"# Update {name} to the latest patched version\n# Ecosystem: {eco}\n# Affected versions: {rng}"}]
            add(t, f"Affected package: **{name}** ({eco}) — {rng} *(source: OSV)*",
                "bi-box-arrow-up", "critical", eco_cmds)
            matched_any = True

        if not matched_any:
            # Truly generic fallback — patch refs are already shown in the section below
            add(
                "Apply the official vendor security patch",
                "NVD did not include CPE configuration data for this CVE. "
                "Consult the vendor / patch references below and apply the latest fixed release.",
                "bi-patch-check-fill",
                "critical" if (cve_data.get("cvss_score") or 0) >= 7 else "high",
            )

    # ── 2b. Supplementary OSV ecosystem packages (when CPE data was present) ───
    if cpe_targets:
        for pkg_info in (cve_data.get("affected_packages") or []):
            eco  = pkg_info.get("ecosystem", "")
            name = pkg_info.get("package", "")
            rng  = pkg_info.get("ranges", "")
            if not eco or not name:
                continue
            t = f"Update {name} ({eco})"
            if t in seen_titles:
                continue
            eco_lower = eco.lower()
            if eco_lower in ("pypi", "python"):
                eco_cmds = [{"label": "pip", "code": f"pip install --upgrade \"{name}\"\n# Affected versions: {rng}"}]
            elif eco_lower in ("npm", "node", "node.js"):
                eco_cmds = [{"label": "npm", "code": f"npm install {name}@latest\n# Affected versions: {rng}"}]
            elif eco_lower in ("maven", "gradle"):
                eco_cmds = [{"label": "Maven/Gradle", "code": f"# Update {name} to latest patched version in pom.xml / build.gradle\n# Affected versions: {rng}"}]
            elif eco_lower in ("go", "golang"):
                eco_cmds = [{"label": "Go modules", "code": f"go get -u {name}\ngo mod tidy\n# Affected versions: {rng}"}]
            else:
                eco_cmds = [{"label": eco, "code": f"# Update {name} to the latest patched version\n# Ecosystem: {eco}\n# Affected versions: {rng}"}]
            add(t, f"Affected package: **{name}** ({eco}) — {rng} *(source: OSV)*",
                "bi-box-arrow-up", "high", eco_cmds)

    # ── 3. CWE-specific code fixes ─────────────────────────────────────────────
    for cwe in (cve_data.get("weaknesses") or []):
        entry = _CODE_FIX_CWES.get(cwe.upper())
        if entry:
            title, code_text, icon = entry
            add(title, "", icon, "high", [{"label": "Code fix", "code": code_text}])

    # ── 4. Network hardening (network-reachable + no auth required) ────────────
    vec      = cve_data.get("cvss_vector") or ""
    raw_vec  = re.sub(r"^CVSS:[^/]+/", "", vec)
    vec_parts = set(raw_vec.split("/")) if raw_vec else set()

    if "AV:N" in vec_parts and "PR:N" in vec_parts:
        add(
            "Restrict network access until the patch is deployed",
            "AV:N (network-reachable) + PR:N (no authentication) = widest possible attack surface. "
            "Block external access at the firewall while you prepare the patch.",
            "bi-router", "high",
            [
                {"label": "iptables", "code": (
                    "# Replace 8080 with the actual vulnerable service port\n"
                    "sudo iptables -I INPUT -p tcp --dport 8080 -s TRUSTED_CIDR -j ACCEPT\n"
                    "sudo iptables -I INPUT -p tcp --dport 8080 -j DROP\n\n"
                    "# Make persistent:\nsudo iptables-save | sudo tee /etc/iptables/rules.v4"
                )},
                {"label": "firewalld", "code": (
                    "sudo firewall-cmd --zone=public --remove-port=8080/tcp --permanent\n"
                    "sudo firewall-cmd --reload"
                )},
                {"label": "nftables", "code": "sudo nft add rule ip filter INPUT tcp dport 8080 drop"},
            ],
        )
    elif "AV:N" in vec_parts:
        add(
            "Limit network access to the vulnerable service",
            "The vulnerability is network-reachable. Until patched, restrict access with firewall rules.",
            "bi-router", "high",
            [{"label": "iptables", "code": (
                "# Allow only trusted source IPs — replace PORT and TRUSTED_CIDR\n"
                "sudo iptables -I INPUT -p tcp --dport PORT -s TRUSTED_CIDR -j ACCEPT\n"
                "sudo iptables -I INPUT -p tcp --dport PORT -j DROP"
            )}],
        )

    # ── 4.5 EPSS exploitation-probability notice ───────────────────────────────
    epss = cve_data.get("epss_score")
    epss_pct = cve_data.get("epss_percentile")
    if epss is not None and float(epss) >= 0.5:
        pct_str = f" (top {100 - int(float(epss_pct) * 100)}% of all CVEs)" if epss_pct else ""
        add(
            f"High exploitation probability — EPSS {float(epss)*100:.1f}%{pct_str}",
            f"The FIRST EPSS model estimates a {float(epss)*100:.1f}% probability this CVE will "
            "be exploited in the next 30 days. Prioritise patching above lower-EPSS findings.",
            "bi-graph-up-arrow",
            "critical" if float(epss) >= 0.7 else "high",
        )

    # ── 5. Validate the fix ────────────────────────────────────────────────────
    # Gather cross-source verification links
    verify_links_code = "# Re-scan the affected host\nnuclei -u http://TARGET_HOST -tags cve -severity critical,high,medium"
    source_links = cve_data.get("source_links") or []
    if source_links:
        link_lines = "\n".join(
            f"# {sl['label']}:\n#   {sl['url']}" for sl in source_links
        )
        verify_links_code += f"\n\n# Verify the fix against all configured CVE sources:\n{link_lines}"

    add(
        "Validate the fix and update the audit record",
        "After patching: re-scan the host to confirm the CVE no longer fires, "
        "review logs for signs of prior exploitation, then mark this finding as 'corrected'.",
        "bi-clipboard-check", "normal",
        [
            {"label": "Re-scan with Nuclei", "code": verify_links_code},
            {"label": "Check service logs", "code": (
                "# Look for exploitation evidence in the last 7 days\n"
                "journalctl -u SERVICE_NAME --since '7 days ago' | grep -iE 'error|exploit|attack|injection'"
            )},
        ],
    )

    for i, step in enumerate(steps):
        step["step"] = i + 1
    return steps

