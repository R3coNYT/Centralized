# Centralized

**Web platform for security audit management** — import scan results, detect CVEs, track vulnerabilities and generate reports, all centralized in a modern interface.

---

## Features

### Audit & Client Management
- **Login system** with role-based access: Admin / Analyst
- **Dashboard** with live charts: severity distribution, top vulnerable services, monthly audit trend
- **Client & Audit management** — organize engagements by client, track status, scope and dates
- **Real-time updates** — instant status and counter updates via SSE (Server-Sent Events) across all open tabs

### Scan File Import & Parsing

| Format | Data Extracted |
|--------|----------------|
| Nmap XML (`-oX`) | Hosts, ports, services, versions, OS, CVEs from NSE scripts |
| Nmap JSON (AutoRecon) | Hosts, ports, services, versions |
| AutoRecon `report.json` | Full data: hosts, CVEs, risk, WAF, CMS, nuclei, httpx |
| HTTPX JSON | HTTP probes, status codes, titles, technologies |
| Nuclei JSON / JSONL | Vulnerabilities, severity, CVE IDs, evidence |
| Nikto XML & JSON | Vulnerabilities, OSVDB IDs, CVEs |
| Lynis `.log` | Warnings (HIGH) and suggestions (LOW) with category and fix |
| Lynis `.dat` | Same + host metadata (OS, kernel, hostname) |
| PDF (AutoRecon / generic) | IPs, CVE IDs, port references (regex extraction) |
| Dirbust (dirb / gobuster) | Discovered paths and directories |
| SQLMap | Detected SQL injections, parameters, payload types |
| SharpHound (BloodHound) | Active Directory data (users, groups, ACLs, attack paths) |
| ADMiner data | Advanced AD analysis |

> **Lynis uploads require a Target IP** — enter it manually on the upload page as Lynis runs locally on the audited machine and does not embed a network address in its output.

### Multi-Source CVE Enrichment
NVD is the default source. Additional sources can be enabled from **Admin → Settings**:
- **NVD (NIST)** — CVSS v3/v4, official descriptions
- **CIRCL CVE Search** — CVSS fallback, affected packages
- **MITRE / cve.org** — authoritative descriptions and CWE weaknesses
- **EPSS (FIRST.org)** — exploit prediction score and percentile
- **OSV (Google)** — open-source vulnerability data, affected packages
- **EUVD / ENISA** — European Union vulnerability database
- **CVE Details, Tenable, Wiz, VulDB, CVEFind** — clickable enrichment links in the CVE modal

### Analysis & Detection
- **Automatic per-host analysis** — NVD queried for every detected service/version on upload
- **On-demand analysis** — *Analyze* button on each host or audit to re-run CVE enrichment
- **CVE modal** — click any CVE ID to instantly load CVSS score, description, references and affected packages
- **Lynis remediation guide** — button on each Lynis finding shows the fix and a direct link to the CISOfy controls database
- **AD Miner** — Active Directory analysis integration (BloodHound / SharpHound data)

### Real-Time Notifications
- **Desktop notifications** (Web Push) — instant alerts on every new event
- **Per-scope preferences** — configurable per client, audit or host
- **Available events**: new host, new vuln, audit completed, critical CVE, status change, risk score change
- **Global toggle** — enable/disable all notifications without touching individual preferences
- **Browser permission** request built into the Notifications page

### Interface & PWA
- **Progressive Web App (PWA)** — installable on desktop and mobile
- **Custom icon** — upload a custom icon from Admin → Interface; the PWA manifest and service worker update automatically with cache busting
- **Glassmorphic theme** — glass-effect toggle from Admin → Interface
- **Customisable theme colours**
- **Collapsible sidebar**
- **Native dark mode**
- **Column filters** and sorting on all tables
- **Global search filters** on all list views

### Administration
- **User management** — create / edit / delete accounts
- **Interface** — custom logo, GitHub token, glassmorphic theme, colours
- **Settings** — CVE sources, NVD API key
- **Update** — version check and one-click update from the web interface
- **AD Miner** — launch and view Active Directory analyses

---

## Installation

### Linux

```bash
git clone https://github.com/R3coNYT/Centralized.git /tmp/centralized-install
bash /tmp/centralized-install/Centralized.sh
```

- Installs to **`/opt/centralized`**
- Creates the global command **`centralized`** at `/usr/local/bin/`
- Optionally registers a **systemd** service (`centralized.service`)

```bash
centralized
# or as a service:
sudo systemctl start centralized
```

---

### macOS

```bash
# Homebrew is required (https://brew.sh)
git clone https://github.com/R3coNYT/Centralized.git /tmp/centralized-install
bash /tmp/centralized-install/Centralized.sh
```

- Installs to **`~/Tools/Centralized`**
- Creates the global command **`centralized`** at `~/.local/bin/`

```bash
centralized
```

> Reopen your terminal after install if the `centralized` command is not found (PATH update).

---

### Windows

```powershell
# Run from an Administrator PowerShell terminal
Set-ExecutionPolicy Bypass -Scope Process -Force
irm https://raw.githubusercontent.com/R3coNYT/Centralized/main/Centralized.ps1 | iex
```

- Installs to **`C:\Tools\Centralized`**
- Registers a **Windows Scheduled Task** (`Centralized`) that:
  - Starts automatically on Windows boot (runs as SYSTEM)
  - Runs in the background — no console window needed
  - Restarts automatically up to 3 times on failure (30 s delay)
  - Logs to `C:\Tools\Centralized\logs\service.log`

```powershell
# Check status
Get-ScheduledTask -TaskName Centralized

# Stop / start
Stop-ScheduledTask  -TaskName Centralized
Start-ScheduledTask -TaskName Centralized

# Disable / re-enable auto-start
Disable-ScheduledTask -TaskName Centralized
Enable-ScheduledTask  -TaskName Centralized
Start-ScheduledTask   -TaskName Centralized

# View live logs
Get-Content C:\Tools\Centralized\logs\service.log -Wait
```

> **Prerequisites:** Git and Python 3.10+ must be installed manually before running the script.  
> Git: <https://git-scm.com/download/win> | Python: <https://www.python.org/downloads/>

---

### Prerequisites Summary

| | Linux | macOS | Windows |
|---|---|---|---|
| Python 3.10+ | auto (`apt`) | auto (Homebrew) | manual |
| Git | auto (`apt`) | auto (Homebrew) | manual |
| Homebrew | — | required | — |

---

### Manual Install (any OS)

```bash
git clone https://github.com/R3coNYT/Centralized.git
cd Centralized
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

---

## Updating

The update scripts pull the latest code **without touching your existing data** (clients, audits, uploaded files, database).

Before each update, a timestamped backup is created (`backups/YYYYMMDD_HHMMSS/`) containing:
- `centralized.db` — full database
- `uploads/` — all uploaded scan files
- `.env` and `github_token.txt`

> **Tip:** set a GitHub PAT in **Admin → Interface** before checking for updates. Without it, the unauthenticated GitHub API is capped at 60 requests/hour.

```bash
# Linux / macOS
cd /opt/centralized && bash update.sh

# Windows
cd C:\Tools\Centralized
.\update.ps1
```

---

## First Login

The app starts on **http://127.0.0.1:5000**

| Field | Value |
|-------|-------|
| Username | `admin` |
| Password | `admin` |

> **Change the admin password after first login.**

---

## Configuration

Edit `config.py` or set environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | (change me) | Flask session secret — **must change in production** |
| `DATABASE_URL` | `sqlite:///centralized.db` | SQLAlchemy DB URI |
| `NVD_API_KEY` | *(empty)* | NVD API key — raises rate limit from 5 to 50 req/30s |
| `UPLOAD_FOLDER` | `./uploads/` | Where uploaded files are stored |
| `CVE_CACHE_TTL_DAYS` | `7` | How long enriched CVE data is cached locally (days) |

### GitHub API Token

Centralized checks GitHub for available updates (visible in **Admin → Update**).  
Without a token the unauthenticated GitHub API is capped at **60 requests/hour**.  
A Personal Access Token (PAT) raises this to **5 000 requests/hour**.

**Setup:**
1. Go to <https://github.com/settings/tokens> → **Generate new token (classic)**
2. Tick only the **`public_repo`** scope
3. Copy the generated token
4. In Centralized: **Admin → Interface** → *GitHub API Token* card → **Save Token**

> `github_token.txt` is in `.gitignore` and is backed up / restored by the update scripts.  
> Never commit it to a public repository.

---

## Project Structure

```
Centralized/
├── app.py                      # Flask factory + PWA routes
├── config.py                   # Configuration
├── extensions.py               # SQLAlchemy, LoginManager, CSRF instances
├── models/                     # SQLAlchemy models
├── parsers/                    # Scan file parsers
│   ├── nmap_xml_parser.py      # Nmap XML (-oX)
│   ├── nmap_json_parser.py     # Nmap JSON (AutoRecon)
│   ├── autorecon_parser.py     # AutoRecon report.json
│   ├── httpx_parser.py         # HTTPX JSON
│   ├── nuclei_parser.py        # Nuclei JSON / JSONL
│   ├── nikto_parser.py         # Nikto XML & JSON
│   ├── lynis_parser.py         # Lynis .log & .dat
│   ├── pdf_parser.py           # PDF (regex CVE/IP/port)
│   ├── dirbust_parser.py       # Dirb / Gobuster
│   ├── sqlmap_parser.py        # SQLMap
│   ├── sharphound_parser.py    # SharpHound / BloodHound
│   └── adminer_data_parser.py  # ADMiner
├── services/
│   ├── cve_service.py          # NVD API v2 + external sources integration
│   ├── notifications.py        # SSE + Web Push notification system
│   └── ad_remediation_fetcher.py # AD remediation data fetcher
├── routes/
│   ├── auth.py                 # Login / logout / user management
│   ├── dashboard.py            # Global statistics
│   ├── audits.py               # Audit CRUD + findings
│   ├── clients.py              # Client CRUD
│   ├── uploads.py              # File upload & parsing pipeline
│   ├── hosts.py                # Host detail view
│   ├── cve_search.py           # CVE search
│   ├── cve_remediation.py      # CVE remediation guide
│   ├── autorecon_launch.py     # AutoRecon launcher (SSE live terminal)
│   ├── autorecon_results.py    # AutoRecon results viewer
│   ├── ad_miner.py             # Active Directory analysis
│   ├── admin.py                # Administration (settings, interface, update)
│   └── api.py                  # REST JSON API
├── templates/                  # Jinja2 HTML templates
├── static/
│   ├── css/style.css           # Custom dark theme
│   ├── js/app.js               # Global JS (charts, filters, sorting)
│   ├── manifest.json           # PWA manifest (static base icon)
│   └── sw.js                   # Service Worker (cache + notifications)
├── Centralized.sh              # Installer — Linux & macOS
├── Centralized.ps1             # Installer — Windows
├── update.sh                   # Updater — Linux & macOS
├── update.ps1                  # Updater — Windows
├── rollback.sh / rollback.ps1  # Restore from backup
├── uninstall.sh / uninstall.ps1# Uninstaller
├── uploads/                    # Uploaded files (auto-created, in .gitignore)
├── logs/                       # Windows service logs (auto-created)
└── centralized.db              # SQLite database (auto-created, in .gitignore)
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/cve/lookup?id=CVE-2024-XXXX` | CVE details (NVD + enabled sources) |
| GET | `/api/cve/search?q=OpenSSH+8.4` | Search CVEs by keyword via NVD |
| GET | `/api/cve/<id>/affected` | Packages affected by a CVE |
| GET | `/api/audits/<id>/stats` | JSON stats for an audit |
| POST | `/api/audits/<id>/analyze` | Re-run CVE analysis for an audit |
| POST | `/api/audits/<id>/import-assets` | Import assets into an audit |
| GET | `/api/hosts/<id>/context` | Host context data |
| POST | `/api/hosts/<id>/analyze` | Re-run CVE analysis for a host |
| GET | `/api/dashboard/stats` | Global dashboard statistics |
| PATCH | `/api/vulnerabilities/<id>/status` | Update vulnerability status |
| POST | `/api/vulnerabilities/<id>/enrich` | Enrich a vulnerability with NVD |
| GET | `/api/notifications/stream` | Real-time SSE notification stream |
| GET | `/api/notifications/pending` | Pending notifications (for SW background sync) |
| GET/POST | `/api/notifications/prefs/<scope>/<id>` | Read / write notification preferences |

---

## Security Notes

- CSRF protection on all forms (Flask-WTF)
- Passwords hashed with `werkzeug.security` (PBKDF2-SHA256)
- File uploads validated by extension AND content inspection
- Open-redirect protection on login
- Session cookies: `HttpOnly`, `SameSite=Lax`
- **For production**: change `SECRET_KEY`, use HTTPS, consider PostgreSQL over SQLite
