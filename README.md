# Centralized

**Web platform to centralize pentest audits** — upload scan files, detect CVEs, visualize findings.

---

## Features

- **Login system** with role-based access (Admin / Analyst)
- **Dashboard** with live charts: severity distribution, top services, monthly audit trend
- **Client & Audit management** — organize engagements by client, track status and scope
- **File upload & auto-parsing** of:
  - Nmap XML (`-oX`) and AutoRecon Nmap JSON
  - AutoRecon full `report.json`
  - HTTPX JSON output
  - Nuclei JSON / JSONL output
  - Nikto XML and JSON output
  - PDF audit reports (AutoRecon + generic) — extracts CVEs, IPs, ports via text analysis
- **CVE detection** from uploaded files + on-demand lookup / keyword search via [NVD API v2](https://nvd.nist.gov/developers/vulnerabilities)
- **NVD enrichment** — optionally auto-query NVD for every discovered service/version during upload
- **Host detail view** — open ports, HTTP pages, vulnerabilities, TLS info
- **Manual findings** — add analyst notes with severity, status, evidence, recommendations
- **CVE modal** — click any CVE ID to instantly pull CVSS score, description and references from NVD

---

## Installation

Centralized ships with ready-to-use installer scripts for every supported OS.  
They clone the repository, create a Python virtual environment and install all dependencies automatically.

---

### Linux

```bash
# Clone the repo and run the installer (requires sudo)
git clone https://github.com/R3coNYT/Centralized.git /tmp/centralized-install
bash /tmp/centralized-install/Centralized.sh
```

- Installs to **`/opt/centralized`**
- Creates the global command **`centralized`** at `/usr/local/bin/`
- Optionally registers a **systemd** service (`centralized.service`)

**Start the app:**
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

**Start the app:**
```bash
centralized
```

> Reopen your terminal after install if the `centralized` command is not found (PATH update).

---

### Windows

```powershell
# Run from PowerShell (as a regular user, no admin required)
Set-ExecutionPolicy Bypass -Scope Process -Force
.\Centralized.ps1
```

Or download and run in one shot:
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
irm https://raw.githubusercontent.com/R3coNYT/Centralized/main/Centralized.ps1 | iex
```

- Installs to **`C:\Tools\Centralized`**
- Creates two launchers:
  - `C:\Tools\Centralized\centralized.bat` — double-click friendly
  - `C:\Tools\Centralized\centralized.ps1` — PowerShell launcher

**Start the app:**
```
C:\Tools\Centralized\centralized.bat
```

> Git and Python 3.10+ must be installed before running the script.  
> Git: <https://git-scm.com/download/win> | Python: <https://www.python.org/downloads/>

---

### Prerequisites summary

| | Linux | macOS | Windows |
|---|---|---|---|
| Python 3.10+ | via `apt` (auto) | via Homebrew (auto) | manual install |
| Git | via `apt` (auto) | via Homebrew (auto) | manual install |
| Homebrew | — | required | — |

---

### Manual install (any OS)

```bash
git clone https://github.com/R3coNYT/Centralized.git
cd Centralized
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

---

### First login

The app starts on **http://127.0.0.1:5000**

| Field    | Value   |
|----------|---------|
| Username | `admin` |
| Password | `admin` |

> **Change the admin password after first login!**

---

## Configuration

Edit `config.py` or set environment variables:

| Variable        | Default                    | Description                          |
|-----------------|----------------------------|--------------------------------------|
| `SECRET_KEY`    | (change me)                | Flask session secret — **must change in production** |
| `DATABASE_URL`  | `sqlite:///centralized.db` | SQLAlchemy DB URI                   |
| `NVD_API_KEY`   | *(empty)*                  | NVD API key — raises rate limit from 5 to 50 req/30s |
| `UPLOAD_FOLDER` | `./uploads/`               | Where uploaded files are stored      |

---

## Supported File Formats

| Format | Detection | Data Extracted |
|--------|-----------|----------------|
| Nmap XML (`-oX`) | `<nmaprun` tag | Hosts, ports, services, versions, OS, script CVE refs |
| AutoRecon Nmap JSON | `{"ip":..,"open_ports":[..]}` | Hosts, ports, services, versions |
| AutoRecon report.json | `{"input_target":..,"subdomains":{..}}` | Full audit data: hosts, CVEs, risk, WAF, CMS, nuclei, httpx |
| HTTPX JSON | Array + `url`/`status_code` keys | HTTP probes, status codes, titles, technologies |
| Nuclei JSON/JSONL | `template-id` key | Vulnerabilities, severity, CVE IDs, evidence |
| Nikto XML | `<niktoscan` tag | Vulnerabilities, OSVDB IDs, CVEs |
| Nikto JSON | `host`/`vulnerabilities` keys | Same as above |
| PDF (AutoRecon/generic) | `.pdf` extension | IPs, CVE IDs, port references (regex extraction) |

---

## Project Structure

```
Centralized/
├── Centralized.sh          # Installer — Linux & macOS
├── Centralized.ps1         # Installer — Windows
├── app.py                  # Flask factory + startup
├── config.py               # Configuration
├── models/__init__.py      # SQLAlchemy models
├── parsers/                # File parsers (nmap, httpx, nuclei, nikto, pdf, autorecon)
├── services/cve_service.py # NVD API v2 integration
├── routes/                 # Flask blueprints
│   ├── auth.py             # Login / logout / user management
│   ├── dashboard.py        # Dashboard stats
│   ├── audits.py           # Audit CRUD + findings
│   ├── clients.py          # Client CRUD
│   ├── uploads.py          # File upload & parsing pipeline
│   ├── hosts.py            # Host detail view
│   └── api.py              # JSON API (stats, CVE lookup/search)
├── templates/              # Jinja2 HTML templates
├── static/
│   ├── css/style.css       # Custom dark theme
│   └── js/app.js           # Chart.js + CVE modal
├── uploads/                # Uploaded files storage (auto-created)
└── centralized.db          # SQLite database (auto-created)
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/cve/lookup?id=CVE-2024-XXXX` | Fetch CVE details from NVD |
| GET | `/api/cve/search?q=OpenSSH+8.4` | Search CVEs by keyword |
| GET | `/api/audits/<id>/stats` | JSON stats for an audit |
| GET | `/api/dashboard/stats` | Global dashboard stats |

---

## Security Notes

- All forms use CSRF protection (Flask-WTF)
- Passwords hashed with `werkzeug.security` (PBKDF2-SHA256)
- File uploads validated by extension AND content inspection
- Open-redirect protection on login
- Session cookies: `HttpOnly`, `SameSite=Lax`
- **For production**: change `SECRET_KEY`, use HTTPS, consider PostgreSQL over SQLite

