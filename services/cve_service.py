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
    return search_cves_by_keyword(keyword, max_results=50)


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

# ---------------------------------------------------------------------------
# Step-by-step remediation builder
# ---------------------------------------------------------------------------

# CWE → list of (title, description, bootstrap-icon) tuples
_CWE_STEPS: dict[str, list[tuple[str, str, str]]] = {
    "CWE-79": [
        (
            "Encode all user-supplied output",
            "Apply HTML entity encoding on every piece of data rendered in the browser. "
            "Use context-aware escaping: HTML context, JavaScript context, CSS context and URL context "
            "each require different encoding schemes. Never inject raw user input into the DOM.",
            "bi-code-slash",
        ),
        (
            "Implement a strict Content Security Policy (CSP)",
            "Add a Content-Security-Policy HTTP response header that:\n"
            "  • Disallows inline scripts (no 'unsafe-inline')\n"
            "  • Restricts script sources to your own domain and explicitly trusted CDNs\n"
            "  • Uses 'nonce-{random}' or 'hash-{...}' for any legitimate inline code\n"
            "Test with the CSP Evaluator tool before deploying.",
            "bi-shield-lock",
        ),
        (
            "Enable auto-escaping in your templating engine",
            "Configure your templating engine (Jinja2, Twig, Handlebars, React JSX…) with "
            "auto-escaping enabled by default so every variable interpolation is safely encoded. "
            "Explicitly mark trusted HTML with a dedicated helper (e.g. Markup() in Jinja2) "
            "only when absolutely required.",
            "bi-file-code",
        ),
    ],
    "CWE-89": [
        (
            "Replace string-concatenated queries with parameterized statements",
            "Never build SQL queries by concatenating user-supplied strings. Use your framework's "
            "ORM (SQLAlchemy, Hibernate, ActiveRecord) or the database driver's parameterized query "
            "API (e.g. cursor.execute(sql, (param,))). This eliminates the injection vector entirely.",
            "bi-database-lock",
        ),
        (
            "Apply strict input validation and allowlisting",
            "Before data reaches the data layer, validate each field:\n"
            "  • Reject inputs that don't match expected type, length and format\n"
            "  • Use an allowlist of accepted characters for free-text fields\n"
            "  • Return a clear validation error rather than silently truncating",
            "bi-funnel",
        ),
        (
            "Enforce least privilege on the database account",
            "The application's DB user must only hold the minimum permissions it needs "
            "(SELECT/INSERT/UPDATE on specific tables). Remove CREATE, DROP, ALTER, EXECUTE, "
            "FILE and any DBA-level grants. Use a separate read-only account for reporting queries.",
            "bi-person-lock",
        ),
    ],
    "CWE-78": [
        (
            "Eliminate OS shell calls wherever possible",
            "Refactor the vulnerable code to use a native library instead of a shell command. "
            "If you must invoke an external process, use an API that accepts an argument list "
            "(e.g. Python subprocess with a list and shell=False) so the shell is never involved "
            "in argument parsing.",
            "bi-terminal",
        ),
        (
            "Validate and allowlist all OS-bound inputs",
            "Define a strict allowlist of permitted characters (alphanumeric + limited punctuation) "
            "for every value passed to external commands. Reject — never sanitize by escaping — "
            "any input containing shell metacharacters (;, &&, |, $, `, \\, <, >).",
            "bi-sliders",
        ),
        (
            "Run the process with minimal OS privileges",
            "The service account should own only the filesystem paths and network sockets it strictly needs. "
            "Use Linux namespaces, seccomp profiles or Windows restricted tokens to confine what the "
            "process can do even if command injection is achieved.",
            "bi-shield",
        ),
    ],
    "CWE-22": [
        (
            "Canonicalize and jail all file paths",
            "Before opening any file, resolve the path to its real absolute form "
            "(os.path.realpath() / Path.resolve()) and assert the result starts with the "
            "expected base directory. Raise an error and abort if the canonical path escapes "
            "the allowed prefix.",
            "bi-folder-lock",
        ),
        (
            "Run the file-serving component in a restricted sandbox",
            "Use chroot, a container, or a virtual filesystem mount so the process's "
            "root is the document root. Even a successful traversal cannot read files outside "
            "the sandbox.",
            "bi-box-seam",
        ),
    ],
    "CWE-287": [
        (
            "Enforce multi-factor authentication (MFA)",
            "Add a second factor (TOTP app, hardware key, push notification) so a stolen "
            "password alone is insufficient for access. Prioritize privileged and admin accounts first.",
            "bi-shield-lock",
        ),
        (
            "Harden session management",
            "Session tokens must be:\n"
            "  • Generated with a CSPRNG (≥128 bits of entropy)\n"
            "  • Short-lived (expire after inactivity)\n"
            "  • Invalidated on logout and on privilege change\n"
            "  • Transmitted only over TLS with HttpOnly + Secure + SameSite=Strict flags",
            "bi-key",
        ),
        (
            "Implement brute-force protection",
            "After a configurable number of failed login attempts (e.g. 5), apply an "
            "exponential back-off or temporary lockout. Log all authentication failures to "
            "your SIEM. Deploy a CAPTCHA or device fingerprinting challenge after repeated failures.",
            "bi-journal-check",
        ),
    ],
    "CWE-798": [
        (
            "Remove hardcoded credentials and rotate them immediately",
            "Delete the hardcoded secret from source code now and trigger an emergency rotation. "
            "Replace it with a runtime secret injection mechanism:\n"
            "  • Environment variables for simple deployments\n"
            "  • A secrets manager (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault) for production\n"
            "Never store secrets in config files committed to version control.",
            "bi-key",
        ),
        (
            "Audit version history for leaked secrets",
            "A secret that was ever committed — even if later deleted — remains in git history. "
            "Use tools such as truffleHog, git-secrets or GitHub Secret Scanning to scan the "
            "entire repository history. Rotate every discovered secret regardless of age.",
            "bi-search",
        ),
    ],
    "CWE-611": [
        (
            "Disable external entity and DTD processing in the XML parser",
            "Configure the XML parser to reject DTDs and external entities:\n"
            "  • Python lxml: resolve_entities=False, no_network=True\n"
            "  • Java: set XMLConstants.FEATURE_SECURE_PROCESSING = true, "
            "disable FEATURE_EXTERNAL_GENERAL_ENTITIES and FEATURE_EXTERNAL_PARAMETER_ENTITIES\n"
            "  • PHP: libxml_disable_entity_loader(true) (PHP < 8.0)",
            "bi-file-earmark-x",
        ),
        (
            "Switch to JSON or validate with a strict schema",
            "If the application does not specifically require XML, migrate to JSON, which "
            "has no entity expansion mechanism. If XML is required, validate all documents "
            "against a strict XSD schema before parsing.",
            "bi-file-earmark-code",
        ),
    ],
    "CWE-502": [
        (
            "Never deserialize untrusted data with native object serializers",
            "Remove all usage of pickle (Python), Java ObjectInputStream, PHP unserialize() "
            "or equivalent native formats on data received over the network or from untrusted "
            "storage. Replace with JSON + schema validation, Protocol Buffers, or Avro.",
            "bi-shield-x",
        ),
        (
            "Apply a class allowlist if deserialization cannot be removed",
            "If native deserialization is unavoidable, configure a strict allowlist of "
            "permitted classes/types and reject anything outside it before processing. "
            "Use libraries like NotSoSerial (Java) or RestrictedUnpickler (Python) to enforce this.",
            "bi-funnel",
        ),
    ],
    "CWE-20": [
        (
            "Implement strict server-side input validation",
            "Define and enforce an allowlist of accepted values for every external input:\n"
            "  • Data type check (integer, email, UUID…)\n"
            "  • Length bounds\n"
            "  • Format / regex pattern\n"
            "  • Value range for numeric fields\n"
            "Reject — do not silently strip — anything outside the allowlist.",
            "bi-check-square",
        ),
        (
            "Apply output encoding appropriate to each context",
            "Even after validation, encode data before injecting it into HTML, SQL, "
            "OS commands, LDAP queries or any other interpreted context. Validation reduces "
            "attack surface; output encoding prevents injection even when validation is incomplete.",
            "bi-code-slash",
        ),
    ],
    "CWE-434": [
        (
            "Validate file type by inspecting file content (magic bytes), not extension",
            "Read the first bytes of the uploaded file and check them against known magic byte "
            "signatures. Never trust the client-supplied filename or Content-Type header. "
            "Use a library such as python-magic or Apache Tika for reliable MIME detection.",
            "bi-file-earmark-lock",
        ),
        (
            "Store uploaded files outside the web root and serve through a controller",
            "Save uploads to a directory that the web server does not serve directly. "
            "Serve files through a controller that:\n"
            "  • Re-validates the file before delivery\n"
            "  • Enforces access control (authentication + authorization)\n"
            "  • Sets Content-Disposition: attachment to prevent browser execution",
            "bi-folder-lock",
        ),
        (
            "Scan uploaded files for malware before storage",
            "Integrate an antivirus / YARA scanner into the upload pipeline. "
            "Quarantine suspicious files rather than immediately rejecting them to enable forensic review.",
            "bi-shield-check",
        ),
    ],
    "CWE-352": [
        (
            "Add CSRF tokens to all state-changing forms and AJAX requests",
            "Generate a cryptographically random, per-session (or per-request) CSRF token. "
            "Include it as a hidden field in every HTML form and as a custom header in every "
            "state-changing AJAX call. Validate the token server-side before processing.",
            "bi-shield-lock",
        ),
        (
            "Set the SameSite cookie attribute",
            "Add SameSite=Strict (preferred) or SameSite=Lax to all session and authentication "
            "cookies. This prevents cross-site requests from automatically carrying the session cookie.",
            "bi-shield",
        ),
    ],
    "CWE-862": [
        (
            "Add server-side authorization checks to every sensitive endpoint",
            "Never rely on hiding UI elements to restrict access. Every API endpoint and server "
            "action that accesses sensitive data or performs state changes must verify the caller's "
            "role and permissions server-side, regardless of how the request arrived.",
            "bi-person-lock",
        ),
        (
            "Apply the principle of least privilege",
            "Users and service accounts should be granted only the minimum permissions "
            "required for their function. Conduct a permission audit and remove any "
            "over-privileged grants.",
            "bi-lock",
        ),
    ],
    "CWE-306": [
        (
            "Add authentication middleware to all sensitive routes",
            "Apply an authentication check (login_required decorator, JWT validation middleware, "
            "etc.) to every endpoint that exposes sensitive data or performs actions. "
            "Write an integration test that accesses each route without credentials and "
            "asserts a 401/403 response to prevent regression.",
            "bi-shield-lock",
        ),
    ],
    "CWE-400": [
        (
            "Implement rate limiting on resource-intensive endpoints",
            "Add rate limiting (e.g. Flask-Limiter, nginx limit_req, AWS WAF rate rules) "
            "to prevent a single client from exhausting server resources. Define limits "
            "per IP, per account and globally.",
            "bi-speedometer2",
        ),
        (
            "Apply timeouts and queue size caps",
            "Set maximum timeouts on all external service calls (HTTP, DB, cache). "
            "Cap the size of internal thread pools, task queues and connection pools. "
            "This prevents a slow upstream from causing cascading resource exhaustion.",
            "bi-hourglass-split",
        ),
    ],
    "CWE-295": [
        (
            "Enable and enforce proper TLS certificate validation",
            "Ensure the TLS client verifies:\n"
            "  • Certificate chain up to a trusted CA\n"
            "  • Hostname matches the presented certificate (SNI)\n"
            "  • Certificate is within its validity period and not revoked\n"
            "Never disable certificate verification (verify=False, "
            "InsecureRequestWarning, CURLOPT_SSL_VERIFYPEER=false) in production.",
            "bi-lock",
        ),
    ],
    "CWE-119": [
        (
            "Apply the vendor security patch (memory corruption fix required)",
            "Buffer overflow vulnerabilities require a code-level fix. The only reliable "
            "remediation is to apply the vendor's security patch. Update the affected library "
            "or application to the patched version.",
            "bi-arrow-up-circle",
        ),
        (
            "Enable OS and compiler memory protection features",
            "Verify the following mitigations are active on all affected hosts:\n"
            "  • ASLR (Address Space Layout Randomization) — sysctl kernel.randomize_va_space=2\n"
            "  • DEP/NX (Data Execution Prevention / No-Execute) — enabled in BIOS and OS\n"
            "  • Stack canaries — compile with -fstack-protector-strong",
            "bi-cpu",
        ),
    ],
    "CWE-125": [
        (
            "Update to the patched version (out-of-bounds read fix required)",
            "Out-of-bounds read vulnerabilities are memory safety bugs that must be fixed "
            "at the source. Apply the vendor security patch to close the vulnerability.",
            "bi-arrow-up-circle",
        ),
        (
            "Enable memory protection mitigations",
            "Ensure ASLR, DEP/NX and stack canaries are active on all affected systems "
            "to reduce the exploitability of residual memory safety issues.",
            "bi-cpu",
        ),
    ],
    "CWE-787": [
        (
            "Apply the vendor patch immediately (potential RCE — out-of-bounds write)",
            "Out-of-bounds write vulnerabilities are frequently exploitable for remote code "
            "execution. This is a high-urgency patch. Apply the vendor's security update to "
            "all affected systems as soon as possible.",
            "bi-arrow-up-circle",
        ),
        (
            "Enable compiler and OS memory hardening",
            "Build with -fstack-protector-strong, enable ASLR and DEP/NX, and consider "
            "deploying a memory-safe allocator (jemalloc, hardened_malloc) to reduce "
            "exploitation reliability.",
            "bi-cpu",
        ),
    ],
    "CWE-416": [
        (
            "Update the affected library or application (use-after-free fix required)",
            "Use-after-free is a memory corruption class that must be fixed at the source. "
            "Apply the vendor patch to all affected systems.",
            "bi-arrow-up-circle",
        ),
        (
            "Enable heap hardening",
            "Deploy a hardened memory allocator (e.g. glibc MALLOC_CHECK_=3, jemalloc, "
            "or libhardened_malloc) to detect and mitigate UAF exploitation at runtime.",
            "bi-cpu",
        ),
    ],
}

# CVSS vector component → (title, description, icon)
_CVSS_STEPS: dict[str, tuple[str, str, str]] = {
    "AV:N": (
        "Restrict network exposure with firewall rules",
        "This vulnerability is exploitable over the network. Until the patch is applied:\n"
        "  • Block access to the affected port/service at the perimeter firewall\n"
        "  • Limit source IPs to only those that legitimately need access\n"
        "  • Consider temporarily taking the service offline if it is not business-critical",
        "bi-router",
    ),
    "AV:A": (
        "Segment the adjacent network",
        "The attack requires adjacent network access. Isolate the vulnerable service in a "
        "dedicated VLAN and ensure only explicitly authorized hosts can reach it. "
        "Review switch ACLs and wireless SSIDs that share the same broadcast domain.",
        "bi-diagram-3",
    ),
    "PR:N": (
        "Treat as high-priority — no authentication required to exploit",
        "Pre-authentication vulnerabilities have the widest attack surface because any "
        "unauthenticated user or automated scanner can trigger them. Apply network "
        "restrictions and the patch as emergency changes, not scheduled maintenance.",
        "bi-exclamation-triangle",
    ),
    "UI:N": (
        "Assume automated or worm-like exploitation is possible",
        "No user interaction is required, meaning exploitation can be scripted, "
        "automated or even worm-like. Do not assume attackers will wait — "
        "treat active exploitation as a baseline assumption and expedite patching.",
        "bi-bug",
    ),
    "S:C": (
        "Isolate the service to limit blast radius (scope change possible)",
        "A scope-changed vulnerability lets an attacker pivot from the vulnerable component "
        "to other systems (e.g. container escape, hypervisor breakout, cross-tenant access). "
        "Place the service in a dedicated container/VM with tightly restricted outbound network "
        "access and minimal filesystem permissions.",
        "bi-box-seam",
    ),
    "C:H": (
        "Protect and audit access to sensitive data",
        "This vulnerability can fully expose confidential data. Take the following steps:\n"
        "  • Audit what data the affected service can access and reduce it to the minimum\n"
        "  • Ensure data is encrypted at rest (AES-256) and in transit (TLS 1.2+)\n"
        "  • Review access logs for signs of prior exfiltration\n"
        "  • Notify your data protection officer if personal data may have been exposed",
        "bi-database-lock",
    ),
    "I:H": (
        "Deploy data-integrity controls",
        "This vulnerability allows full integrity compromise. Apply:\n"
        "  • File-integrity monitoring (FIM) on critical binaries and configs (AIDE, Wazuh)\n"
        "  • Cryptographic checksums or digital signatures on critical data at rest\n"
        "  • Immutable infrastructure patterns (rebuild from trusted images rather than patching in-place)",
        "bi-lock",
    ),
    "A:H": (
        "Protect service availability with redundancy and DoS mitigations",
        "This vulnerability can fully disable the service. Mitigations:\n"
        "  • Deploy a WAF or DDoS protection layer (Cloudflare, AWS Shield) in front of the service\n"
        "  • Add circuit breakers and health-check auto-restart policies\n"
        "  • Ensure a tested runbook exists for rapid service restoration\n"
        "  • Configure alerting to detect abnormal traffic patterns before an outage",
        "bi-cloud-arrow-up",
    ),
}


def build_remediation_steps(cve_data: dict) -> list[dict]:
    """
    Generate a structured, step-by-step remediation guide for a CVE.

    Combines intelligence from:
      - CISA KEV status (exploited_in_wild, cisa_remediation)
      - Patch availability (patch_refs)
      - CWE weakness categories (_CWE_STEPS knowledge base)
      - CVSS vector components (_CVSS_STEPS hardening advice)

    Returns a list of dicts: {step, title, description, icon, priority}
    where priority is one of "critical" | "high" | "normal".
    """
    steps: list[dict] = []
    seen_titles: set[str] = set()

    def add(title: str, description: str, icon: str = "bi-check-circle",
            priority: str = "normal") -> None:
        if title not in seen_titles:
            seen_titles.add(title)
            steps.append({
                "step": 0,       # renumbered at the end
                "title": title,
                "description": description,
                "icon": icon,
                "priority": priority,
            })

    # ── 1. CISA KEV / actively exploited ─────────────────────────────────────
    if cve_data.get("exploited_in_wild"):
        cisa_action = cve_data.get("cisa_remediation") or ""
        add(
            "IMMEDIATE: vulnerability is actively exploited in the wild",
            ("CISA Required Action: " + cisa_action) if cisa_action else (
                "CISA has catalogued this CVE as a Known Exploited Vulnerability (KEV). "
                "Active exploitation means real attackers are using this right now. "
                "Apply the patch or the mitigations below immediately — "
                "do not wait for a scheduled maintenance window."
            ),
            "bi-fire",
            "critical",
        )

    # ── 2. Patch / no-patch step ──────────────────────────────────────────────
    patch_refs = cve_data.get("patch_refs") or []
    score = cve_data.get("cvss_score") or 0
    if patch_refs:
        n = len(patch_refs)
        add(
            "Apply the official vendor security patch",
            f"The NVD lists {n} patch/advisory reference{'s' if n != 1 else ''} for this CVE "
            f"(see the Patch References section). Steps:\n"
            "  1. Identify the exact version of the affected component on each impacted host\n"
            "  2. Download the patch from the vendor link below\n"
            "  3. Test in a staging environment if a maintenance window allows\n"
            "  4. Deploy to all affected production systems\n"
            "  5. Verify the installed version matches the patched release",
            "bi-patch-check-fill",
            "critical" if score >= 7 else "high",
        )
    else:
        add(
            "Monitor vendor channels and apply the fix when available",
            "No official patch reference appears in NVD at this time. "
            "Until a patch is released:\n"
            "  • Subscribe to the CVE's vendor security advisory feed\n"
            "  • Apply the network and configuration mitigations described in the steps below\n"
            "  • Re-check this CVE page weekly for status updates",
            "bi-bell",
            "high" if score >= 7 else "normal",
        )

    # ── 3. CWE-specific technical steps ──────────────────────────────────────
    for cwe in (cve_data.get("weaknesses") or []):
        for title, desc, icon in _CWE_STEPS.get(cwe.upper(), []):
            add(title, desc, icon, "high")

    # ── 4. CVSS vector-based hardening ────────────────────────────────────────
    vec = cve_data.get("cvss_vector") or ""
    # Strip the version prefix (CVSS:3.1/, CVSS:2.0/, …) and split components
    raw_vec = re.sub(r"^CVSS:[^/]+/", "", vec)
    vec_parts = set(raw_vec.split("/")) if raw_vec else set()
    for component, (title, desc, icon) in _CVSS_STEPS.items():
        if component in vec_parts:
            add(title, desc, icon, "high")

    # ── 5. Always: validate + monitor ─────────────────────────────────────────
    add(
        "Validate the fix and set up monitoring for exploitation attempts",
        "After applying the patch or mitigation:\n"
        "  • Re-run a vulnerability scan (AutoRecon / Nuclei / OpenVAS) and confirm the "
        "CVE no longer appears on the affected hosts\n"
        "  • Review service logs for signs of prior exploitation "
        "(anomalous inputs, error spikes, unusual outbound connections)\n"
        "  • Configure a SIEM alert rule for future exploitation attempts targeting this vulnerability",
        "bi-clipboard-check",
        "normal",
    )

    # Renumber sequentially
    for i, step in enumerate(steps):
        step["step"] = i + 1

    return steps
