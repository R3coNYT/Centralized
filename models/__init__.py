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
            .filter(Host.audit_id == self.id)
            .count()
        )

    @property
    def critical_count(self):
        return (
            db.session.query(Vulnerability)
            .join(Host, Host.id == Vulnerability.host_id)
            .filter(Host.audit_id == self.id, Vulnerability.severity == "CRITICAL")
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
    created_at = db.Column(db.DateTime, default=utcnow)
