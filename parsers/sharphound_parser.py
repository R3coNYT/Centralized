"""
Parser for SharpHound JSON exports (BloodHound format v4/v5).

Supports:
  - Individual type-specific JSON files  (20231205_users.json, …)
  - A single ZIP archive containing the above files
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


def _load_json(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return json.load(fh)
    except Exception:
        return {}


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

    # ── ADCS (Certificate Authorities — SharpHound v5 type "cas") ─────────────
    result["adcs_count"] = len(by_type.get("cas", []))

    # ── Build findings ─────────────────────────────────────────────────────────
    def _add(category, title, severity, desc, objects):
        result["findings"].append({
            "category":      category,
            "title":         title,
            "severity":      severity,
            "description":   desc,
            "affected_count": len(objects),
            "details":       json.dumps(objects[:200]),
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

    # Sort by severity descending
    result["findings"].sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 0), reverse=True)

    # ── Risk score (0–100) ─────────────────────────────────────────────────────
    score =  min(len(kerberoastable) * 8,  25)
    score += min(len(asreproastable) * 12, 25)
    score += min(len(unconstrained)  * 15, 30)
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
