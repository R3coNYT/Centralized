"""
Parser for SharpHound JSON exports (BloodHound format v4/v5).

Supports:
  - Individual type-specific JSON files  (20231205_users.json, …)
  - A single ZIP archive containing the above files

Supported meta.type values:
  domains, groups, users, computers,
  enterprisecas (v5) / cas (v4), certtemplates,
  gpos, ous, containers,
  rootcas, aiacas, ntauthstores, issuancepolicies
"""
import json
import os
import time
import zipfile

SEVERITY_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

# Groups whose direct members are considered Domain Admins
_DA_GROUP_NAMES = frozenset({
    "domain admins",
    "enterprise admins",
    "schema admins",
    "administrators",
    "domain controllers",
})

# ── ADCS: EKU OIDs ────────────────────────────────────────────────────────────
_AUTH_EKUS = frozenset({
    "1.3.6.1.5.5.7.3.2",        # Client Authentication
    "1.3.6.1.4.1.311.20.2.2",   # Smart Card Logon
    "1.3.6.1.5.2.3.4",          # PKINIT Client Authentication
    "2.5.29.37.0",               # Any Purpose (also ESC2)
})
_ANY_PURPOSE_EKU = "2.5.29.37.0"
_CERT_AGENT_EKU  = "1.3.6.1.4.1.311.20.2.1"  # Certificate Request Agent (ESC3)

# ── Privileged SID detection ───────────────────────────────────────────────────
# Domain-relative RID suffixes for well-known privileged groups
_PRIV_RID_SUFFIXES = frozenset({
    "-500",  # Administrator account
    "-512",  # Domain Admins
    "-516",  # Domain Controllers
    "-517",  # Cert Publishers
    "-518",  # Schema Admins
    "-519",  # Enterprise Admins
    "-520",  # Group Policy Creator Owners
    "-526",  # Key Admins
    "-527",  # Enterprise Key Admins
})
# Well-known builtin or system SIDs that are privileged
_PRIV_BUILTIN_SIDS = frozenset({
    "S-1-5-32-544",  # Builtin\Administrators
    "S-1-5-32-548",  # Account Operators
    "S-1-5-32-549",  # Server Operators
    "S-1-5-32-550",  # Print Operators
    "S-1-5-32-551",  # Backup Operators
    "S-1-5-9",       # Enterprise Domain Controllers
    "S-1-5-18",      # NT AUTHORITY\SYSTEM
    "S-1-3-0",       # Creator Owner
})


def _load_json(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return json.load(fh)
    except Exception:
        return {}


def _is_privileged_sid(sid: str) -> bool:
    """Return True if the SID belongs to a well-known privileged principal."""
    s = sid.upper()
    if s in {b.upper() for b in _PRIV_BUILTIN_SIDS}:
        return True
    return any(s.endswith(sfx) for sfx in _PRIV_RID_SUFFIXES)


def _get_aces(obj: dict) -> list:
    """Return ACE list from an object, handling both Aces and ACEs key names."""
    return obj.get("Aces") or obj.get("ACEs") or []


def _has_low_priv_enroll(aces: list) -> bool:
    """Return True if any non-privileged principal has enrollment rights on a template."""
    enroll_rights = {"Enroll", "AutoEnroll", "GenericAll", "AllExtendedRights"}
    for ace in aces:
        if ace.get("RightName") not in enroll_rights:
            continue
        sid = ace.get("PrincipalSID", "")
        if sid and not _is_privileged_sid(sid):
            return True
    return False


def _collect_by_type(file_paths: list) -> dict:
    """
    Given a list of file paths (.json or .zip), return a dict mapping
    SharpHound meta.type → list of data items.
    """
    by_type: dict = {}

    for fp in file_paths:
        if fp.lower().endswith(".zip"):
            try:
                with zipfile.ZipFile(fp, "r") as zf:
                    for member in zf.namelist():
                        if not member.lower().endswith(".json"):
                            continue
                        try:
                            with zf.open(member) as zfp:
                                jdata = json.load(zfp)
                            meta_type = jdata.get("meta", {}).get("type", "")
                            if meta_type:
                                by_type.setdefault(meta_type, [])
                                by_type[meta_type].extend(jdata.get("data", []))
                        except Exception:
                            continue
            except Exception:
                continue
        else:
            jdata = _load_json(fp)
            meta_type = jdata.get("meta", {}).get("type", "")
            if meta_type:
                by_type.setdefault(meta_type, [])
                by_type[meta_type].extend(jdata.get("data", []))

    return by_type


def parse_sharphound_files(file_paths: list) -> dict:
    """
    Parse a collection of SharpHound JSON / ZIP files.

    Returns a dict:
      domain_name, domain_count, dc_count,
      user_count, enabled_user_count,
      group_count, computer_count, adcs_count,
      gpo_count, ou_count, cert_template_count,
      domain_admin_count, kerberoastable_count,
      asreproastable_count, unconstrained_deleg_count,
      risk_rating, risk_score,
      findings: list[dict]
    """
    by_type = _collect_by_type(file_paths)
    now_ts = time.time()
    STALE_DAYS = 90 * 86400

    result = {
        "domain_name":             "",
        "domain_count":            0,
        "dc_count":                0,
        "user_count":              0,
        "enabled_user_count":      0,
        "group_count":             0,
        "computer_count":          0,
        "adcs_count":              0,
        "gpo_count":               0,
        "ou_count":                0,
        "cert_template_count":     0,
        "domain_admin_count":      0,
        "kerberoastable_count":    0,
        "asreproastable_count":    0,
        "unconstrained_deleg_count": 0,
        "risk_rating":             "INFO",
        "risk_score":              0.0,
        "findings":                [],
    }

    # ── Domains ────────────────────────────────────────────────────────────────
    domains = by_type.get("domains", [])
    result["domain_count"] = len(domains)
    if domains:
        p = domains[0].get("Properties", {})
        result["domain_name"] = p.get("name") or p.get("domain") or domains[0].get("Name", "")

    # ── Groups — collect DA member SIDs ───────────────────────────────────────
    groups = by_type.get("groups", [])
    result["group_count"] = len(groups)
    da_sids: set = set()
    for g in groups:
        props = g.get("Properties", {})
        raw_name = props.get("name") or g.get("Name", "")
        short = raw_name.lower().split("@")[0].strip()
        if short in _DA_GROUP_NAMES:
            for m in g.get("Members", []):
                if m.get("ObjectType") in ("User", "user"):
                    sid = m.get("ObjectIdentifier", "")
                    if sid:
                        da_sids.add(sid)

    # ── Users ──────────────────────────────────────────────────────────────────
    users = by_type.get("users", [])
    result["user_count"] = len(users)

    kerberoastable, asreproastable = [], []
    pw_never_expires, stale, admin_count_users, da_users = [], [], [], []

    for u in users:
        props   = u.get("Properties", {})
        name    = props.get("name") or u.get("Name", "Unknown")
        enabled = props.get("enabled", True)
        sid     = u.get("ObjectIdentifier", "")

        if enabled:
            result["enabled_user_count"] += 1

        if props.get("hasspn"):
            kerberoastable.append(name)
        if props.get("dontreqpreauth"):
            asreproastable.append(name)
        if props.get("admincount"):
            admin_count_users.append(name)
        if enabled and props.get("pwdneverexpires"):
            pw_never_expires.append(name)

        # lastlogon is stored as Unix-epoch seconds in SharpHound JSON
        lastlogon = props.get("lastlogon") or props.get("lastlogontimestamp") or 0
        if enabled and lastlogon and lastlogon > 0:
            if (now_ts - lastlogon) > STALE_DAYS:
                stale.append(name)

        if sid and sid in da_sids:
            da_users.append(name)

    result["kerberoastable_count"]  = len(kerberoastable)
    result["asreproastable_count"]  = len(asreproastable)
    result["domain_admin_count"]    = len(da_users) if da_users else len(admin_count_users)

    # ── Computers ──────────────────────────────────────────────────────────────
    computers = by_type.get("computers", [])
    result["computer_count"] = len(computers)
    unconstrained, dc_list = [], []
    for c in computers:
        props = c.get("Properties", {})
        name  = props.get("name") or c.get("Name", "Unknown")
        if props.get("isdc"):
            dc_list.append(name)
        # Exclude DCs from unconstrained delegation (normal for DCs)
        if props.get("unconstraineddelegation") and not props.get("isdc"):
            unconstrained.append(name)

    result["dc_count"]                  = len(dc_list)
    result["unconstrained_deleg_count"] = len(unconstrained)

    # ── Enterprise CAs (v5: "enterprisecas", v4 fallback: "cas") ─────────────
    enterprise_cas = by_type.get("enterprisecas") or by_type.get("cas") or []
    result["adcs_count"] = len(enterprise_cas)
    web_enroll_cas: list = []
    for ca in enterprise_cas:
        props = ca.get("Properties", {})
        name  = props.get("name") or ca.get("Name", "Unknown")
        if props.get("webenrollmentenabled") or props.get("webenrollment"):
            web_enroll_cas.append(name)

    # ── Certificate Templates (ADCS ESC findings) ─────────────────────────────
    cert_templates = by_type.get("certtemplates", [])
    result["cert_template_count"] = len(cert_templates)
    esc1_templates:    list = []
    esc2_templates:    list = []
    esc3_templates:    list = []
    no_sec_ext_tmpl:   list = []

    for t in cert_templates:
        props   = t.get("Properties", {})
        name    = props.get("name") or t.get("Name", "Unknown")
        enabled = props.get("enabled", True)
        if not enabled:
            continue

        ekus            = props.get("ekus") or props.get("certificateapplicationpolicies") or []
        approval_req    = props.get("requiresmanagerapproval", False)
        enrollee_supply = props.get("enrolleesuppliessubject", False)
        # authenticationenabled is pre-computed by SharpHound; fall back to EKU check
        auth_enabled    = props.get("authenticationenabled") or any(e in _AUTH_EKUS for e in ekus)
        no_sec_ext      = props.get("nosecurityextension", False)
        aces            = _get_aces(t)
        # If no ACE info available, assume potentially enrollable (conservative)
        low_priv_enroll = (not aces) or _has_low_priv_enroll(aces)

        # ESC1 — SAN supplied by requester + authentication enabled + no approval
        if enrollee_supply and auth_enabled and not approval_req and low_priv_enroll:
            esc1_templates.append(name)

        # ESC2 — Any Purpose EKU or no EKUs (SubCA) + no approval
        has_any_purpose = _ANY_PURPOSE_EKU in ekus
        has_no_ekus     = not ekus
        if (has_any_purpose or has_no_ekus) and not approval_req and low_priv_enroll:
            esc2_templates.append(name)

        # ESC3 — Certificate Request Agent EKU + no approval
        if _CERT_AGENT_EKU in ekus and not approval_req and low_priv_enroll:
            esc3_templates.append(name)

        # ESC9 / No Security Extension — template doesn't embed security extension
        if no_sec_ext and auth_enabled and low_priv_enroll:
            no_sec_ext_tmpl.append(name)

    # ── GPOs — detect non-admin write ACEs ────────────────────────────────────
    gpos = by_type.get("gpos", [])
    result["gpo_count"] = len(gpos)
    gpo_write_abuse: list = []
    _gpo_write_rights = {"WriteOwner", "WriteDacl", "GenericAll", "GenericWrite", "WriteProperty"}
    for gpo in gpos:
        props = gpo.get("Properties", {})
        name  = props.get("name") or gpo.get("Name", "Unknown")
        aces  = _get_aces(gpo)
        for ace in aces:
            if ace.get("RightName") not in _gpo_write_rights:
                continue
            if ace.get("IsInherited", False):
                continue
            sid = ace.get("PrincipalSID", "")
            if sid and not _is_privileged_sid(sid):
                gpo_write_abuse.append(name)
                break

    # ── OUs — detect blocked inheritance ──────────────────────────────────────
    ous = by_type.get("ous", [])
    result["ou_count"] = len(ous)
    blocked_inh_ous: list = []
    for ou in ous:
        props = ou.get("Properties", {})
        name  = props.get("name") or ou.get("Name", "Unknown")
        if props.get("blocksinheritance"):
            blocked_inh_ous.append(name)

    # ── Build findings ─────────────────────────────────────────────────────────
    def _add(category, title, severity, desc, objects, remediation=None):
        result["findings"].append({
            "category":      category,
            "title":         title,
            "severity":      severity,
            "description":   desc,
            "affected_count": len(objects),
            "details":       json.dumps(objects[:200]),
            "remediation":   json.dumps(remediation or []),
        })

    if kerberoastable:
        _add(
            "kerberoastable",
            f"Kerberoastable Users ({len(kerberoastable)})",
            "HIGH",
            "Accounts with Service Principal Names (SPNs). An attacker can request TGS tickets for these accounts and crack them offline to recover plaintext passwords — no privileges required.",
            kerberoastable,
        )

    if asreproastable:
        _add(
            "asreproastable",
            f"AS-REP Roastable Users ({len(asreproastable)})",
            "HIGH",
            "Accounts with Kerberos pre-authentication disabled. An unauthenticated attacker can retrieve an AS-REP blob and attempt offline password cracking.",
            asreproastable,
        )

    if unconstrained:
        _add(
            "unconstrained_delegation",
            f"Unconstrained Delegation Computers ({len(unconstrained)})",
            "HIGH",
            "Non-DC computers trusted for unconstrained Kerberos delegation. If an attacker compromises such a machine and coerces DC authentication (e.g., via PrinterBug), they can steal a DC TGT and gain full domain control.",
            unconstrained,
        )

    if esc1_templates:
        _add(
            "adcs_esc1",
            f"ADCS ESC1 — Enrollee-Controlled SAN ({len(esc1_templates)} template(s))",
            "CRITICAL",
            "Certificate templates allow the requester to supply a Subject Alternative Name (SAN), have an authentication EKU, and require no manager approval. A low-privileged user can request a certificate for any identity in the domain (e.g., Domain Admin) and use it to authenticate.",
            esc1_templates,
            [
                {"step": 1, "description": "Disable CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT on affected templates", "command": "Set-ADObject -Identity 'CN=<template>,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local' -Replace @{'msPKI-Certificate-Name-Flag'=0}", "shell": "PowerShell (ADCS)"},
                {"step": 2, "description": "Require manager approval on sensitive templates", "command": "certutil -setreg policy\\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2", "shell": "PowerShell (ADCS)"},
            ],
        )

    if esc2_templates:
        _add(
            "adcs_esc2",
            f"ADCS ESC2 — Any Purpose / No EKU Templates ({len(esc2_templates)} template(s))",
            "HIGH",
            "Certificate templates have the 'Any Purpose' EKU or no EKUs at all (SubCA). These certificates can be used for any purpose including client authentication, code signing, or as a subordinate CA.",
            esc2_templates,
            [
                {"step": 1, "description": "Replace Any Purpose EKU with specific restricted EKUs appropriate for the template's intended use", "command": "certutil -setcatemplates <template>", "shell": "PowerShell (ADCS)"},
                {"step": 2, "description": "Review and restrict enrollment rights to only necessary principals"},
            ],
        )

    if esc3_templates:
        _add(
            "adcs_esc3",
            f"ADCS ESC3 — Certificate Request Agent Templates ({len(esc3_templates)} template(s))",
            "HIGH",
            "Certificate templates have the Certificate Request Agent EKU (1.3.6.1.4.1.311.20.2.1). A low-privileged user can enroll in these templates and use the issued certificate to request certificates on behalf of any user, enabling privilege escalation.",
            esc3_templates,
            [
                {"step": 1, "description": "Restrict Certificate Request Agent template enrollment to only designated enrollment agent accounts"},
                {"step": 2, "description": "Enable 'This CA certificate may only be used by...' restriction on the issuing CA for enrollment agent certificates", "command": "certutil -setreg ca\\EnrollmentAgentRestrictions ...", "shell": "PowerShell (ADCS)"},
            ],
        )

    if no_sec_ext_tmpl:
        _add(
            "adcs_esc9",
            f"ADCS ESC9 — No Security Extension ({len(no_sec_ext_tmpl)} template(s))",
            "MEDIUM",
            "Certificate templates do not embed the szOID_NTDS_CA_SECURITY_EXT security extension (CT_FLAG_NO_SECURITY_EXTENSION). If the CA has StrongCertificateBindingEnforcement disabled, these certificates may bypass user/certificate binding checks.",
            no_sec_ext_tmpl,
        )

    if web_enroll_cas:
        _add(
            "adcs_web_enrollment",
            f"ADCS Web Enrollment Enabled ({len(web_enroll_cas)} CA(s))",
            "HIGH",
            "Enterprise Certificate Authorities have Web Enrollment (certsrv) enabled. If served over HTTP (not HTTPS), credentials are transmitted in cleartext. Combined with NTLM relay attacks, an attacker can coerce DC authentication and relay it to the CA to obtain a Domain Controller certificate.",
            web_enroll_cas,
            [
                {"step": 1, "description": "Enforce HTTPS on the Web Enrollment endpoint and disable HTTP", "command": "Get-WebConfiguration -Filter 'system.webServer/security/access' -PSPath 'IIS:\\Sites\\Default Web Site\\CertSrv'", "shell": "PowerShell (IIS)"},
                {"step": 2, "description": "Disable NTLM on the Web Enrollment endpoint and require Extended Protection for Authentication (EPA)", "command": "Set-WebConfigurationProperty -Filter 'system.webServer/security/authentication/windowsAuthentication/extendedProtection' -Name 'tokenChecking' -Value 'Require' -PSPath 'IIS:\\Sites\\Default Web Site'", "shell": "PowerShell (IIS)"},
            ],
        )

    if gpo_write_abuse:
        _add(
            "gpo_write_acl",
            f"GPO Write Rights for Non-Privileged Principals ({len(gpo_write_abuse)} GPO(s))",
            "MEDIUM",
            "Group Policy Objects have write-level ACEs (WriteOwner, WriteDacl, GenericAll, or GenericWrite) granted to non-privileged principals. An attacker controlling such a principal can modify the GPO to execute code on all machines or users the GPO applies to.",
            gpo_write_abuse,
            [
                {"step": 1, "description": "Review and remove non-privileged write ACEs from affected GPOs", "command": "Get-GPPermissions -Name '<GPO>' -All | Where-Object {$_.Permission -in 'GpoEditDeleteModifySecurity','GpoEdit'}", "shell": "PowerShell (RSAT)"},
            ],
        )

    if pw_never_expires:
        _add(
            "password_never_expires",
            f"Passwords Never Expire ({len(pw_never_expires)})",
            "MEDIUM",
            "Enabled accounts configured with 'Password Never Expires'. These accounts may use old, weak, or compromised passwords that have never been rotated.",
            pw_never_expires,
        )

    if stale:
        _add(
            "stale_accounts",
            f"Stale Accounts — No Login > 90 Days ({len(stale)})",
            "LOW",
            "Enabled accounts that have not authenticated in over 90 days. These represent unnecessary attack surface and should be disabled or reviewed.",
            stale,
        )

    # AdminCount=1 accounts that are not already in DA (extra AC risk)
    extra_ac = [u for u in admin_count_users if u not in da_users]
    if extra_ac:
        _add(
            "admin_count",
            f"AdminCount=1 Non-DA Accounts ({len(extra_ac)})",
            "MEDIUM",
            "Accounts with AdminCount=1 were previously protected by AdminSDHolder. They may retain strong ACL protections or elevated permissions that are no longer necessary.",
            extra_ac,
        )

    if blocked_inh_ous:
        _add(
            "ou_blocked_inheritance",
            f"OUs with Blocked GPO Inheritance ({len(blocked_inh_ous)})",
            "LOW",
            "Organizational Units with GPO inheritance blocked. Policy exceptions applied this way may bypass domain-wide security baselines (e.g., password complexity, audit policies).",
            blocked_inh_ous,
        )

    # Sort by severity descending
    result["findings"].sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 0), reverse=True)

    # ── Risk score (0–100) ─────────────────────────────────────────────────────
    score =  min(len(esc1_templates)  * 20, 30)   # ESC1 critical — up to 30
    score += min(len(kerberoastable)  *  8, 20)
    score += min(len(asreproastable)  * 12, 20)
    score += min(len(unconstrained)   * 15, 20)
    score += min(len(esc2_templates)  * 10, 15)
    score += min(len(esc3_templates)  * 10, 15)
    score += min(len(web_enroll_cas)  * 10, 15)
    score += min(len(gpo_write_abuse) *  5, 10)
    score += min(len(pw_never_expires) * 2, 10)
    score += min(len(stale) * 1, 10)
    score = min(round(score, 1), 100.0)
    result["risk_score"] = score

    if score >= 60:
        result["risk_rating"] = "CRITICAL"
    elif score >= 35:
        result["risk_rating"] = "HIGH"
    elif score >= 15:
        result["risk_rating"] = "MEDIUM"
    elif score > 0:
        result["risk_rating"] = "LOW"
    else:
        result["risk_rating"] = "INFO"

    return result
