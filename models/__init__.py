from extensions import db
from flask_login import UserMixin
from datetime import datetime, timezone


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default="analyst")  # admin / analyst
    created_at = db.Column(db.DateTime, default=utcnow)

    audits = db.relationship("Audit", backref="creator", lazy="dynamic")

    def __repr__(self):
        return f"<User {self.username}>"


# ---------------------------------------------------------------------------
# Clients & Audits
# ---------------------------------------------------------------------------

class Client(db.Model):
    __tablename__ = "clients"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    contact = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=utcnow)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)

    audits = db.relationship("Audit", backref="client", lazy="dynamic", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Client {self.name}>"


class Audit(db.Model):
    __tablename__ = "audits"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    client_id = db.Column(db.Integer, db.ForeignKey("clients.id"), nullable=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    target = db.Column(db.String(500))          # target IP/range/domain
    scope = db.Column(db.Text)
    start_date = db.Column(db.DateTime)
    end_date = db.Column(db.DateTime)
    status = db.Column(db.String(30), default="in_progress")  # in_progress/completed/archived
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=utcnow)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)

    hosts = db.relationship("Host", backref="audit", lazy="dynamic", cascade="all, delete-orphan")
    uploaded_files = db.relationship("UploadedFile", backref="audit", lazy="dynamic", cascade="all, delete-orphan")
    findings = db.relationship("Finding", backref="audit", lazy="dynamic", cascade="all, delete-orphan")

    @property
    def host_count(self):
        return self.hosts.count()

    @property
    def vuln_count(self):
        return (
            db.session.query(Vulnerability)
            .join(Host, Host.id == Vulnerability.host_id)
            .filter(Host.audit_id == self.id,
                    ~Vulnerability.cve_status.in_(CVE_STATUS_EXCLUDED))
            .count()
        )

    @property
    def critical_count(self):
        return (
            db.session.query(Vulnerability)
            .join(Host, Host.id == Vulnerability.host_id)
            .filter(Host.audit_id == self.id, Vulnerability.severity == "CRITICAL",
                    ~Vulnerability.cve_status.in_(CVE_STATUS_EXCLUDED))
            .count()
        )

    def __repr__(self):
        return f"<Audit {self.name}>"


# ---------------------------------------------------------------------------
# Hosts & Ports
# ---------------------------------------------------------------------------

class Host(db.Model):
    __tablename__ = "hosts"
    id = db.Column(db.Integer, primary_key=True)
    audit_id = db.Column(db.Integer, db.ForeignKey("audits.id"), nullable=False)
    ip = db.Column(db.String(45), nullable=False)
    hostname = db.Column(db.String(500))
    os_info = db.Column(db.String(500))
    mac_address = db.Column(db.String(30))
    mac_vendor = db.Column(db.String(200))
    risk_score = db.Column(db.Float, default=0.0)
    risk_level = db.Column(db.String(20))       # INFO/LOW/MEDIUM/HIGH/CRITICAL
    cms = db.Column(db.String(200))
    waf = db.Column(db.String(200))
    tag = db.Column(db.String(100))
    extra_data = db.Column(db.Text)             # JSON blob: shodan, theharvester, login_forms, dir_bruteforce, param_discovery
    created_at = db.Column(db.DateTime, default=utcnow)

    ports = db.relationship("Port", backref="host", lazy="dynamic", cascade="all, delete-orphan")
    vulnerabilities = db.relationship("Vulnerability", backref="host", lazy="dynamic", cascade="all, delete-orphan")
    http_pages = db.relationship("HttpPage", backref="host", lazy="dynamic", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Host {self.ip}>"


class Port(db.Model):
    __tablename__ = "ports"
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey("hosts.id"), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(10), default="tcp")
    service = db.Column(db.String(200))
    product = db.Column(db.String(200))
    version = db.Column(db.String(200))
    extra_info = db.Column(db.String(500))
    state = db.Column(db.String(20), default="open")
    cpe = db.Column(db.String(300))
    created_at = db.Column(db.DateTime, default=utcnow)

    vulnerabilities = db.relationship("Vulnerability", backref="port", lazy="dynamic")

    def __repr__(self):
        return f"<Port {self.port}/{self.protocol}>"


class HttpPage(db.Model):
    __tablename__ = "http_pages"
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey("hosts.id"), nullable=False)
    url = db.Column(db.String(2000))
    status_code = db.Column(db.Integer)
    title = db.Column(db.String(500))
    content_type = db.Column(db.String(200))
    content_length = db.Column(db.Integer)
    technology = db.Column(db.String(500))
    redirect_location = db.Column(db.String(2000))
    created_at = db.Column(db.DateTime, default=utcnow)


# ---------------------------------------------------------------------------
# Vulnerabilities / CVEs
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "NONE": 0}


# Valid values for Vulnerability.cve_status
CVE_STATUS_ACTIVE        = "active"
CVE_STATUS_CORRECTED     = "corrected"
CVE_STATUS_FALSE_POSITIVE = "false_positive"
CVE_STATUS_MITIGATED     = "mitigated"
CVE_STATUS_ACCEPTED      = "accepted"
CVE_STATUS_VALUES = [CVE_STATUS_ACTIVE, CVE_STATUS_CORRECTED, CVE_STATUS_FALSE_POSITIVE,
                     CVE_STATUS_MITIGATED, CVE_STATUS_ACCEPTED]
# Statuses that should NOT contribute to risk scoring
CVE_STATUS_EXCLUDED = {CVE_STATUS_CORRECTED, CVE_STATUS_FALSE_POSITIVE}


class Vulnerability(db.Model):
    __tablename__ = "vulnerabilities"
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey("hosts.id"), nullable=False)
    port_id = db.Column(db.Integer, db.ForeignKey("ports.id"), nullable=True)
    cve_id = db.Column(db.String(30))          # CVE-YYYY-NNNNN
    title = db.Column(db.String(500))
    severity = db.Column(db.String(20))        # CRITICAL/HIGH/MEDIUM/LOW/INFO
    cvss_score = db.Column(db.Float)
    cvss_vector = db.Column(db.String(100))
    description = db.Column(db.Text)
    references = db.Column(db.Text)           # JSON list of URLs
    source = db.Column(db.String(50))         # nmap/nuclei/nikto/nvd/autorecon/pdf
    template_id = db.Column(db.String(200))   # nuclei template id
    evidence = db.Column(db.Text)
    recommendation = db.Column(db.Text)
    cve_status = db.Column(db.String(30), default=CVE_STATUS_ACTIVE, nullable=False)  # active/corrected/false_positive/mitigated/accepted
    created_at = db.Column(db.DateTime, default=utcnow)

    def __repr__(self):
        return f"<Vulnerability {self.cve_id or self.title}>"


# ---------------------------------------------------------------------------
# Findings (manual analyst notes)
# ---------------------------------------------------------------------------

class Finding(db.Model):
    __tablename__ = "findings"
    id = db.Column(db.Integer, primary_key=True)
    audit_id = db.Column(db.Integer, db.ForeignKey("audits.id"), nullable=False)
    host_id = db.Column(db.Integer, db.ForeignKey("hosts.id"), nullable=True)
    title = db.Column(db.String(500), nullable=False)
    severity = db.Column(db.String(20), default="MEDIUM")
    description = db.Column(db.Text)
    evidence = db.Column(db.Text)
    recommendation = db.Column(db.Text)
    status = db.Column(db.String(30), default="open")   # open / confirmed / mitigated / false_positive
    created_at = db.Column(db.DateTime, default=utcnow)

    host = db.relationship("Host", foreign_keys=[host_id])


# ---------------------------------------------------------------------------
# Uploaded files
# ---------------------------------------------------------------------------

class UploadedFile(db.Model):
    __tablename__ = "uploaded_files"
    id = db.Column(db.Integer, primary_key=True)
    audit_id = db.Column(db.Integer, db.ForeignKey("audits.id"), nullable=False)
    original_filename = db.Column(db.String(500))
    stored_filename = db.Column(db.String(500))         # UUID-based safe filename
    file_type = db.Column(db.String(50))                # nmap_xml/nmap_json/httpx_json/nuclei_json/nikto_xml/autorecon_json/pdf/unknown
    file_size = db.Column(db.Integer)
    parsed = db.Column(db.Boolean, default=False)
    parse_error = db.Column(db.Text)
    target_ip = db.Column(db.String(255))               # filled for Lynis files (user-supplied host IP/hostname)
    created_at = db.Column(db.DateTime, default=utcnow)


# ---------------------------------------------------------------------------
# Site-wide settings (admin-configurable key/value pairs)
# ---------------------------------------------------------------------------

class SiteSettings(db.Model):
    __tablename__ = "site_settings"
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.String(500))


# ---------------------------------------------------------------------------
# Host context (analyst-provided OS / service version hints)
# ---------------------------------------------------------------------------

class HostContext(db.Model):
    __tablename__ = "host_contexts"
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey("hosts.id"), unique=True, nullable=False)
    os_version = db.Column(db.String(200))          # e.g. "Microsoft Windows 11 Professionnel"
    os_build = db.Column(db.String(50))             # e.g. "25H2" / "22H2" / "1809"
    service_versions = db.Column(db.Text)           # JSON: [{"name": "openssl", "version": "3.0.2"}]
    notes = db.Column(db.Text)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)

    host = db.relationship(
        "Host",
        backref=db.backref("context", uselist=False, cascade="all, delete-orphan", single_parent=True),
    )


# ---------------------------------------------------------------------------
# CVE Sources (admin-configurable external CVE databases)
# ---------------------------------------------------------------------------

class CveSource(db.Model):
    __tablename__ = "cve_sources"
    id         = db.Column(db.Integer, primary_key=True)
    url        = db.Column(db.String(512), nullable=False, unique=True)
    label      = db.Column(db.String(128), nullable=True)
    # driver: nvd | circl | mitre | epss | osv | generic
    driver     = db.Column(db.String(32), default="generic")
    enabled    = db.Column(db.Boolean, default=True)
    is_builtin = db.Column(db.Boolean, default=False)   # NVD is builtin — cannot be deleted
    created_at = db.Column(db.DateTime, default=utcnow)

    def to_dict(self):
        return {
            "id":         self.id,
            "url":        self.url,
            "label":      self.label or self.url,
            "driver":     self.driver,
            "enabled":    self.enabled,
            "is_builtin": self.is_builtin,
        }


# ---------------------------------------------------------------------------
# CVE Cache (persist enriched CVE data to avoid repeated API calls)
# ---------------------------------------------------------------------------

class CveCache(db.Model):
    __tablename__ = "cve_cache"
    id                = db.Column(db.Integer, primary_key=True)
    cve_id            = db.Column(db.String(20), unique=True, nullable=False, index=True)
    title             = db.Column(db.String(200))
    description       = db.Column(db.Text)
    severity          = db.Column(db.String(20))
    cvss_score        = db.Column(db.Float, nullable=True)
    cvss_vector       = db.Column(db.String(200), nullable=True)
    epss_score        = db.Column(db.Float, nullable=True)
    epss_percentile   = db.Column(db.Float, nullable=True)
    patch_available   = db.Column(db.Boolean, default=False)
    exploited_in_wild = db.Column(db.Boolean, default=False)
    cisa_remediation  = db.Column(db.Text, nullable=True)
    published         = db.Column(db.String(30), nullable=True)
    last_modified     = db.Column(db.String(30), nullable=True)
    vuln_status       = db.Column(db.String(50), nullable=True)
    # JSON-serialised fields
    patch_refs        = db.Column(db.Text, default="[]")   # list[str]
    references        = db.Column(db.Text, default="[]")   # list[str]
    references_meta   = db.Column(db.Text, default="{}")   # {url: [labels]}
    source_links      = db.Column(db.Text, default="[]")   # [{label,url,driver}]
    affected_packages = db.Column(db.Text, default="[]")   # [{ecosystem,package,ranges,source}]
    configurations    = db.Column(db.Text, default="[]")   # NVD CPE configurations
    weaknesses        = db.Column(db.Text, default="[]")   # list[str]
    cached_at         = db.Column(db.DateTime, default=utcnow)
    expires_at        = db.Column(db.DateTime, nullable=False)

    def to_dict(self) -> dict:
        import json as _j

        def _load(val, default):
            try:
                return _j.loads(val) if val else default
            except Exception:
                return default

        return {
            "cve_id":            self.cve_id,
            "title":             self.title or self.cve_id,
            "description":       self.description or "",
            "severity":          self.severity or "UNKNOWN",
            "cvss_score":        self.cvss_score,
            "cvss_vector":       self.cvss_vector,
            "epss_score":        self.epss_score,
            "epss_percentile":   self.epss_percentile,
            "patch_available":   bool(self.patch_available),
            "exploited_in_wild": bool(self.exploited_in_wild),
            "cisa_remediation":  self.cisa_remediation,
            "published":         self.published,
            "last_modified":     self.last_modified,
            "vuln_status":       self.vuln_status,
            "patch_refs":        _load(self.patch_refs, []),
            "references":        self.references or "[]",
            "references_meta":   _load(self.references_meta, {}),
            "source_links":      _load(self.source_links, []),
            "affected_packages": _load(self.affected_packages, []),
            "configurations":    _load(self.configurations, []),
            "weaknesses":        _load(self.weaknesses, []),
            "source":            "nvd",
        }

    def __repr__(self):
        return f"<CveCache {self.cve_id} expires={self.expires_at}>"


# ---------------------------------------------------------------------------
# CVE Remediation Cache (persist computed remediation steps per CVE)
# ---------------------------------------------------------------------------

class CveRemediationCache(db.Model):
    __tablename__ = "cve_remediation_cache"
    id           = db.Column(db.Integer, primary_key=True)
    cve_id       = db.Column(db.String(20), unique=True, nullable=False, index=True)
    steps        = db.Column(db.Text, default="[]")   # JSON list of step dicts
    # SHA-256 of the inputs (cve_data + affected_products) used to detect stale entries
    input_hash   = db.Column(db.String(64))
    cached_at    = db.Column(db.DateTime, default=utcnow)
    expires_at   = db.Column(db.DateTime, nullable=False)

    def steps_list(self) -> list:
        import json as _j
        try:
            return _j.loads(self.steps) if self.steps else []
        except Exception:
            return []

    def __repr__(self):
        return f"<CveRemediationCache {self.cve_id} expires={self.expires_at}>"


# ---------------------------------------------------------------------------
# Active Directory — SharpHound / AD-Miner integration
# ---------------------------------------------------------------------------

class ADData(db.Model):
    """Parsed SharpHound statistics for a client (one row per client)."""
    __tablename__ = "ad_data"

    id                     = db.Column(db.Integer, primary_key=True)
    client_id              = db.Column(db.Integer, db.ForeignKey("clients.id"), unique=True, nullable=False)
    domain_name            = db.Column(db.String(200))
    domain_count           = db.Column(db.Integer, default=0)
    dc_count               = db.Column(db.Integer, default=0)
    user_count             = db.Column(db.Integer, default=0)
    enabled_user_count     = db.Column(db.Integer, default=0)
    group_count            = db.Column(db.Integer, default=0)
    computer_count         = db.Column(db.Integer, default=0)
    adcs_count             = db.Column(db.Integer, default=0)
    domain_admin_count     = db.Column(db.Integer, default=0)
    kerberoastable_count   = db.Column(db.Integer, default=0)
    asreproastable_count   = db.Column(db.Integer, default=0)
    unconstrained_deleg_count = db.Column(db.Integer, default=0)
    risk_rating            = db.Column(db.String(20), default="INFO")   # CRITICAL/HIGH/MEDIUM/LOW/INFO
    risk_score             = db.Column(db.Float, default=0.0)
    adminer_folder_path    = db.Column(db.String(500))                  # relative path under UPLOAD_FOLDER
    created_at             = db.Column(db.DateTime, default=utcnow)
    updated_at             = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)

    client   = db.relationship(
        "Client",
        backref=db.backref("ad_data", uselist=False, cascade="all, delete-orphan", single_parent=True),
    )
    findings = db.relationship("ADFinding", backref="ad_data", lazy="dynamic", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<ADData client_id={self.client_id} domain={self.domain_name}>"


class ADFinding(db.Model):
    """Individual security finding extracted from SharpHound data."""
    __tablename__ = "ad_findings"

    id             = db.Column(db.Integer, primary_key=True)
    ad_data_id     = db.Column(db.Integer, db.ForeignKey("ad_data.id"), nullable=False)
    category       = db.Column(db.String(100))                   # kerberoastable / asreproastable / …
    title          = db.Column(db.String(500), nullable=False)
    severity       = db.Column(db.String(20), default="MEDIUM")  # CRITICAL/HIGH/MEDIUM/LOW/INFO
    description    = db.Column(db.Text)
    affected_count = db.Column(db.Integer, default=0)
    details        = db.Column(db.Text)                          # JSON list of affected object names (max 200)
    created_at     = db.Column(db.DateTime, default=utcnow)

    def __repr__(self):
        return f"<ADFinding {self.title}>"
