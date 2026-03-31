"""
AD Remediation Web Fetcher
==========================
Searches the web (DuckDuckGo HTML endpoint) for real remediation documentation
for each Active Directory security finding and extracts structured content.

Results are stored in ADFinding.remediation_web (JSON blob) and
ADFinding.remediation_web_fetched (bool) to avoid re-fetching.

Search priority:
  1. Known high-quality source URLs per indicator (Microsoft Learn, IT-Connect…)
  2. DuckDuckGo search with targeted queries for all others
  3. Clean text extraction via lxml
"""

from __future__ import annotations

import json
import logging
import re
import time
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlencode, urljoin, urlparse

import requests
from lxml import html as lxml_html

log = logging.getLogger(__name__)

# ── HTTP session shared across fetches ─────────────────────────────────────────

_SESSION: Optional[requests.Session] = None

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "fr-FR,fr;q=0.8,en-US;q=0.5,en;q=0.3",
}

_TIMEOUT = 12  # seconds per request


def _session() -> requests.Session:
    global _SESSION
    if _SESSION is None:
        _SESSION = requests.Session()
        _SESSION.headers.update(_HEADERS)
    return _SESSION


# ── Per-indicator targeted search queries ──────────────────────────────────────
# We generate very specific queries to surface Microsoft Docs, IT-Connect,
# CyberChef/SpecterOps blogs and other quality sources.

_INDICATOR_QUERIES: dict[str, str] = {
    "dangerous_paths": (
        "Active Directory Tier 0 attack path Domain Admin remediation "
        "least privilege Microsoft AdminSDHolder"
    ),
    "graph_path_objects_to_da": (
        "Active Directory shortest path to domain admin BloodHound "
        "attack path remediation Cypher ACL review"
    ),
    "graph_path_objects_to_ou_handlers": (
        "Active Directory OU handler attack path WriteDACL GenericWrite "
        "delegation remediation GPO permissions"
    ),
    "objects_to_adcs": (
        "Active Directory Certificate Services ESC1 ESC2 ESC4 remediation "
        "Certipy ADCS misconfiguration fix Microsoft PKI"
    ),
    "dom_admin_on_non_dc": (
        "Domain Admin logged on non-Domain Controller credential theft "
        "Credential Guard remediation PAW privileged access workstation"
    ),
    "non-dc_with_unconstrained_delegations": (
        "Active Directory unconstrained delegation Kerberos TGT exposure "
        "remediation constrained delegation RBCD fix"
    ),
    "users_shadow_credentials": (
        "Active Directory Shadow Credentials msDS-KeyCredentialLink "
        "exploitation remediation audit SACL"
    ),
    "users_shadow_credentials_to_non_admins": (
        "Active Directory Shadow Credentials non-admin accounts "
        "msDS-KeyCredentialLink remediation audit"
    ),
    "users_constrained_delegations": (
        "Active Directory constrained delegation S4U2Proxy "
        "remediation RBCD resource-based constrained delegation"
    ),
    "kerberoastable": (
        "Kerberoasting Active Directory SPN accounts remediation "
        "strong passwords AES Kerberos managed service accounts"
    ),
    "nb_kerberoastable_accounts": (
        "Kerberoasting réduction comptes SPN Active Directory "
        "remédiation Microsoft Group Managed Service Account"
    ),
    "asreproastable": (
        "AS-REP Roasting Active Directory pre-authentication disabled "
        "remediation fix enable Kerberos pre-auth"
    ),
    "nb_as_rep_roastable_accounts": (
        "AS-REP Roasting comptes Active Directory remédiation "
        "activer pré-authentification Kerberos"
    ),
    "computers_os_obsolete": (
        "Windows Server obsolete EOL Active Directory security risk "
        "remediation isolation network firewall rules upgrade"
    ),
    "anomaly_acl": (
        "Active Directory ACL anomalie permissions dangereuses "
        "GenericAll WriteDACL GenericWrite remédiation audit"
    ),
    "privileged_accounts_outside_Protected_Users": (
        "Active Directory Protected Users group privileged accounts "
        "NTLM credential protection remediation"
    ),
    "nb_domain_admins": (
        "trop de domain admins Active Directory réduction privileged accounts "
        "JIT Just-In-Time administration remediation"
    ),
    "da_to_da": (
        "Domain Admin cross-domain trust foreign security principal "
        "Active Directory remediation inter-domain privilege"
    ),
    "cross_domain_admin_privileges": (
        "Active Directory cross-domain admin privileges foreign security principal "
        "Tier 0 isolation remediation"
    ),
    "server_users_could_be_admin": (
        "Active Directory local admin service account path to admin "
        "remediation LAPS managed local administrator"
    ),
    "empty_ous": (
        "Active Directory empty OU organizational unit cleanup "
        "dangerous delegations security hygiene"
    ),
    "empty_groups": (
        "Active Directory empty groups cleanup ACL permissions cleanup "
        "security baseline hygiene"
    ),
    "never_logon_accounts": (
        "Active Directory stale never logged-on accounts remediation "
        "disable delete inactive accounts audit"
    ),
    "dormant_accounts": (
        "Active Directory dormant inactive accounts remediation "
        "disable stale accounts security policy"
    ),
    "guest_accounts": (
        "Active Directory guest account disable remediation security risk"
    ),
    "users_no_pw_expiry": (
        "Active Directory password never expires remediation "
        "force password change policy fine-grained"
    ),
    "users_with_reversible_encryption": (
        "Active Directory réversible encryption mot de passe "
        "remédiation désactiver AllowReversiblePasswordEncryption"
    ),
    "users_with_des_only": (
        "Active Directory DES encryption Kerberos only accounts "
        "remediation disable DES enable AES"
    ),
    "can_read_laps": (
        "Active Directory LAPS password read access restriction "
        "remediation least privilege LAPS permissions"
    ),
    "laps_not_installed": (
        "Active Directory LAPS not installed local administrator "
        "password solution deployment remediation"
    ),
    "can_sync_password": (
        "Active Directory DCSync replication password sync permission "
        "remediation GetChangesAll revoke"
    ),
    "objects_to_unconstrained_delegations": (
        "Active Directory unconstrained delegation path attack "
        "remediation restrict delegation Kerberos TGT"
    ),
    "objects_to_operators_groups": (
        "Active Directory operator groups Backup Operators Account Operators "
        "attack path remediation restrict membership"
    ),
    "objects_to_servers_with_rbcd": (
        "Active Directory RBCD resource-based constrained delegation "
        "attack path remediation msDS-AllowedToActOnBehalfOfOtherIdentity"
    ),
    "objects_to_adcs_http": (
        "Active Directory Certificate Services HTTP ESC8 relay attack "
        "remediation EPA Extended Protection Authentication HTTPS"
    ),
    "vuln_functional_level": (
        "Active Directory functional level upgrade Windows Server 2008 2012 "
        "remediation raise domain forest functional level"
    ),
    "unpriv_to_dnsadmins": (
        "Active Directory DNS Admins privilege escalation unprivileged users "
        "remediation restrict DNS Admins group"
    ),
}

# ── Known authoritative source URLs per indicator ─────────────────────────────
# These are fetched directly (no search needed) for better reliability.

_INDICATOR_DIRECT_URLS: dict[str, list[str]] = {
    "dangerous_paths": [
        "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models",
        "https://learn.microsoft.com/en-us/security/compass/privileged-access-access-model",
    ],
    "objects_to_adcs": [
        "https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-overpermissive-enrollment-agent",
        "https://learn.microsoft.com/en-us/windows-server/networking/core-network-guide/cncg/server-certs/configure-the-cdp-and-aia-extensions-on-ca1",
    ],
    "dom_admin_on_non_dc": [
        "https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure",
        "https://learn.microsoft.com/en-us/security/compass/privileged-access-devices",
    ],
    "non-dc_with_unconstrained_delegations": [
        "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview",
        "https://learn.microsoft.com/en-us/windows-server/security/kerberos/configuring-kerberos-over-ip",
    ],
    "kerberoastable": [
        "https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview",
    ],
    "asreproastable": [
        "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-kerberos-authentication-service",
    ],
    "privileged_accounts_outside_Protected_Users": [
        "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group",
    ],
    "server_users_could_be_admin": [
        "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview",
    ],
    "can_sync_password": [
        "https://learn.microsoft.com/en-us/defender-for-identity/domain-dominance-alerts",
    ],
    "laps_not_installed": [
        "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview",
        "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-deployment-guide",
    ],
    "nb_domain_admins": [
        "https://learn.microsoft.com/en-us/security/compass/privileged-access-accounts",
    ],
    "anomaly_acl": [
        "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory",
    ],
    "computers_os_obsolete": [
        "https://learn.microsoft.com/en-us/lifecycle/products/",
        "https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/configure",
    ],
}

# ── DuckDuckGo HTML search ─────────────────────────────────────────────────────


def _ddg_search(query: str, max_results: int = 4) -> list[dict]:
    """
    Scrape DuckDuckGo HTML results page.
    Returns list of {url, title} dicts (no JavaScript / API key required).
    """
    url = "https://html.duckduckgo.com/html/"
    params = {"q": query, "kl": "fr-fr"}
    try:
        resp = _session().post(url, data=params, timeout=_TIMEOUT, allow_redirects=True)
        resp.raise_for_status()
    except Exception as exc:
        log.warning("DDG search failed for %r: %s", query, exc)
        return []

    try:
        doc = lxml_html.fromstring(resp.content)
    except Exception:
        return []

    results = []
    # DDG HTML result links are in <a class="result__a">
    for anchor in doc.xpath('//a[@class="result__a"]'):
        href = anchor.get("href", "")
        title = anchor.text_content().strip()
        if href and title:
            # DDG wraps real URLs in /l/?uddg=<encoded>
            if "uddg=" in href:
                from urllib.parse import parse_qs, urlparse as _up
                qs = parse_qs(_up(href).query)
                real = qs.get("uddg", [""])[0]
                if real:
                    href = real
            if href.startswith("http"):
                results.append({"url": href, "title": title})
        if len(results) >= max_results:
            break
    return results


# ── Page content extractor ────────────────────────────────────────────────────


def _label_for_url(url: str) -> str:
    """Human-friendly source label from hostname."""
    host = urlparse(url).hostname or url
    host = host.lstrip("www.")
    _labels = {
        "learn.microsoft.com": "Microsoft Learn",
        "docs.microsoft.com": "Microsoft Docs",
        "techcommunity.microsoft.com": "Microsoft Tech Community",
        "it-connect.fr": "IT-Connect",
        "specterops.io": "SpecterOps",
        "blog.harmj0y.net": "harmj0y",
        "posts.specterops.io": "SpecterOps Blog",
        "attack.mitre.org": "MITRE ATT&CK",
        "github.com": "GitHub",
        "adsecurity.org": "ADSecurity",
    }
    for k, v in _labels.items():
        if k in host:
            return v
    return host.split(".")[0].title()


def _fetch_page(url: str) -> Optional[dict]:
    """
    Fetch a single URL and return {url, title, excerpt, source_label}.
    Returns None on error.
    """
    try:
        resp = _session().get(url, timeout=_TIMEOUT, allow_redirects=True)
        resp.raise_for_status()
        content_type = resp.headers.get("content-type", "")
        if "html" not in content_type:
            return None
    except Exception as exc:
        log.debug("Failed to fetch %s: %s", url, exc)
        return None

    try:
        doc = lxml_html.fromstring(resp.content)
    except Exception:
        return None

    # Extract page title
    title_elems = doc.xpath("//title")
    page_title = title_elems[0].text_content().strip() if title_elems else url

    # Remove noisy elements
    for tag in doc.xpath("//script | //style | //nav | //footer | //header | //aside | //form | //*[contains(@class,'menu')] | //*[contains(@class,'sidebar')]"):
        try:
            tag.drop_tree()
        except Exception:
            pass

    # Try progressively broader content selectors
    text = ""
    for selector in [
        "//main",
        "//article",
        "//*[@id='main-content']",
        "//*[@id='content']",
        "//*[contains(@class,'content')]",
        "//body",
    ]:
        elems = doc.xpath(selector)
        if elems:
            raw = elems[0].text_content()
            text = re.sub(r"\s+", " ", raw).strip()
            if len(text) > 200:
                break

    # Trim to a useful excerpt (up to 1500 chars), ending on a sentence
    if len(text) > 1500:
        cut = text[:1500]
        for sep in (". ", ".\n", "! ", "? "):
            idx = cut.rfind(sep)
            if idx > 800:
                cut = cut[:idx + 1]
                break
        text = cut.strip() + "…"

    if not text:
        return None

    return {
        "url": url,
        "title": page_title[:200],
        "excerpt": text,
        "source_label": _label_for_url(url),
    }


# ── Main fetch function ────────────────────────────────────────────────────────


def fetch_remediation_for_finding(
    indicator_key: str,
    finding_title: str,
) -> dict:
    """
    Fetch real-world remediation documentation for an AD finding.

    Returns a dict:
    {
        "fetched_at": "<ISO timestamp>",
        "indicator_key": "<key>",
        "sources": [
            {
                "url": "https://...",
                "title": "...",
                "excerpt": "...",
                "source_label": "Microsoft Learn"
            },
            ...
        ]
    }
    """
    result = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "indicator_key": indicator_key,
        "sources": [],
    }

    fetched_urls: set[str] = set()

    # ── Step 1: fetch known direct URLs ───────────────────────────────────────
    direct_urls = _INDICATOR_DIRECT_URLS.get(indicator_key, [])
    for url in direct_urls:
        if url in fetched_urls:
            continue
        fetched_urls.add(url)
        page = _fetch_page(url)
        if page:
            result["sources"].append(page)
        time.sleep(0.3)

    # ── Step 2: DuckDuckGo search for additional sources ──────────────────────
    query = _INDICATOR_QUERIES.get(
        indicator_key,
        f'"{finding_title}" Active Directory remediation fix Microsoft security',
    )
    search_results = _ddg_search(query, max_results=5)
    time.sleep(0.5)

    # Prioritize Microsoft Learn and IT-Connect results
    def _priority(r):
        u = r["url"].lower()
        if "learn.microsoft.com" in u or "docs.microsoft.com" in u:
            return 0
        if "it-connect.fr" in u:
            return 1
        if "specterops.io" in u or "adsecurity.org" in u:
            return 2
        if "techcommunity.microsoft.com" in u:
            return 3
        return 9

    search_results.sort(key=_priority)

    fetched_from_search = 0
    for sr in search_results:
        if fetched_from_search >= 3:
            break
        url = sr["url"]
        if url in fetched_urls:
            continue
        # Skip ads, trackers, social media
        if any(x in url for x in ("twitter.com", "linkedin.com", "facebook.com",
                                   "youtube.com", "reddit.com", "stackoverflow.com")):
            continue
        fetched_urls.add(url)
        page = _fetch_page(url)
        if page:
            # Override title with search result title if page title is long
            if len(page["title"]) > 80:
                page["title"] = sr["title"][:200]
            result["sources"].append(page)
            fetched_from_search += 1
        time.sleep(0.4)

    return result


# ── Batch fetch (used in background thread) ───────────────────────────────────


def fetch_all_findings(app, findings_ids: list[int]) -> None:
    """
    Background worker: fetch web remediation for a list of ADFinding IDs.
    Must be called in a thread; uses Flask app context.
    """
    from models import ADFinding
    from extensions import db as _db

    with app.app_context():
        for fid in findings_ids:
            try:
                f = ADFinding.query.get(fid)
                if f is None or f.remediation_web_fetched:
                    continue
                data = fetch_remediation_for_finding(f.indicator_key or f.title, f.title)
                if data.get("sources"):
                    f.remediation_web = json.dumps(data, ensure_ascii=False)
                    f.remediation_web_fetched = True
                    _db.session.commit()
                    log.info("Fetched web remediation for finding %d (%s): %d sources", fid, f.title, len(data["sources"]))
            except Exception as exc:
                log.warning("Web remediation fetch failed for finding %d: %s", fid, exc)
                try:
                    _db.session.rollback()
                except Exception:
                    pass
            time.sleep(0.5)
