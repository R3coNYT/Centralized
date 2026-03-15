#Requires -Version 5.1
<#
.SYNOPSIS
    Centralized — Update Script (Windows)
.DESCRIPTION
    Pulls the latest code from GitHub while preserving your database,
    uploaded files, and any local .env configuration.
    Creates a timestamped backup before updating.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Console helpers ────────────────────────────────────────────────────────────

function Write-Log  { param([string]$Msg) Write-Host "[+] $Msg" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Msg) Write-Host "[✓] $Msg" -ForegroundColor Green }
function Write-Warn { param([string]$Msg) Write-Host "[!] $Msg" -ForegroundColor Yellow }
function Write-Err  { param([string]$Msg) Write-Host "[✗] $Msg" -ForegroundColor Red }
function Write-Info { param([string]$Msg) Write-Host "[i] $Msg" -ForegroundColor Gray }

# ── Locate install directory ───────────────────────────────────────────────────

function Find-InstallDir {
    # 1) Directory where this script lives (preferred)
    $ScriptDir = Split-Path -Parent $MyInvocation.ScriptName
    if ($ScriptDir -and (Test-Path "$ScriptDir\app.py") -and (Test-Path "$ScriptDir\.git")) {
        return $ScriptDir
    }

    # 2) PSScriptRoot (works when called via & or dot-source)
    if ($PSScriptRoot -and (Test-Path "$PSScriptRoot\app.py") -and (Test-Path "$PSScriptRoot\.git")) {
        return $PSScriptRoot
    }

    # 3) Default install path
    $Default = "C:\Tools\Centralized"
    if ((Test-Path "$Default\app.py") -and (Test-Path "$Default\.git")) {
        return $Default
    }

    Write-Err "Could not locate the Centralized install directory."
    Write-Err "Run this script from inside the install directory, or install first with Centralized.ps1"
    exit 1
}

# ── Backup data ────────────────────────────────────────────────────────────────

function Backup-Data {
    param([string]$InstallDir)

    $Timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
    $BackupRoot = Join-Path $InstallDir "backups"
    $BackupDir  = Join-Path $BackupRoot $Timestamp

    Write-Log "Creating backup → $BackupDir"
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null

    # SQLite database
    $DbPath = Join-Path $InstallDir "centralized.db"
    if (Test-Path $DbPath) {
        Copy-Item $DbPath -Destination $BackupDir
        $DbSize = [math]::Round((Get-Item $DbPath).Length / 1KB, 1)
        Write-Ok "Database backed up (${DbSize} KB)"
    } else {
        Write-Warn "No database found — nothing to back up"
    }

    # Uploaded files
    $UploadsPath = Join-Path $InstallDir "uploads"
    if (Test-Path $UploadsPath) {
        $UploadsCount = (Get-ChildItem $UploadsPath -Recurse -File -ErrorAction SilentlyContinue).Count
        if ($UploadsCount -gt 0) {
            Copy-Item $UploadsPath -Destination (Join-Path $BackupDir "uploads") -Recurse
            Write-Ok "Uploads backed up ($UploadsCount files)"
        }
    }

    # Local .env override
    $EnvPath = Join-Path $InstallDir ".env"
    if (Test-Path $EnvPath) {
        Copy-Item $EnvPath -Destination $BackupDir
        Write-Ok ".env backed up"
    }

    Write-Ok "Backup complete → $BackupDir"
    return $BackupDir
}

# ── Git pull ───────────────────────────────────────────────────────────────────

function Update-Git {
    param([string]$InstallDir)

    Write-Log "Pulling latest code from GitHub"
    Set-Location $InstallDir

    # Check git is available
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Err "git is not installed or not in PATH"
        Write-Err "Install Git for Windows: https://git-scm.com/download/win"
        exit 1
    }

    # Stash any accidental local changes to tracked files
    $StashResult = git stash 2>&1
    if ($StashResult -notmatch "No local changes") {
        Write-Info "Local tracked-file changes stashed: $StashResult"
    }

    # Fetch + hard reset to match remote (safe because data files are in .gitignore)
    git fetch origin 2>&1 | Out-Null
    $Branch = (git rev-parse --abbrev-ref HEAD).Trim()
    git reset --hard "origin/$Branch" 2>&1 | Out-Null

    $Commit = (git rev-parse --short HEAD).Trim()
    Write-Ok "Code updated → commit $Commit (branch: $Branch)"
    return $Commit
}

# ── Update Python dependencies ─────────────────────────────────────────────────

function Update-Dependencies {
    param([string]$InstallDir)

    $VenvPip    = Join-Path $InstallDir "venv\Scripts\pip.exe"
    $VenvPython = Join-Path $InstallDir "venv\Scripts\python.exe"

    if (-not (Test-Path $VenvPython)) {
        Write-Err "Virtual environment not found at $InstallDir\venv"
        Write-Err "Please run Centralized.ps1 to reinstall."
        exit 1
    }

    Write-Log "Updating Python dependencies"

    & $VenvPip install --upgrade pip --quiet
    if ($LASTEXITCODE -ne 0) {
        Write-Err "pip upgrade failed"
        exit 1
    }

    & $VenvPip install -r (Join-Path $InstallDir "requirements.txt") --upgrade --quiet
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Dependency installation failed"
        exit 1
    }

    Write-Ok "Dependencies updated"
    return $VenvPython
}

# ── Apply DB migrations (create new tables) ────────────────────────────────────

function Apply-DbMigrations {
    param([string]$VenvPython, [string]$InstallDir)

    Write-Log "Applying database migrations"
    Set-Location $InstallDir

    $PythonCode = @"
from app import create_app
app = create_app()
print('  Database schema up-to-date.')
"@

    $TempScript = Join-Path $env:TEMP "centralized_migrate.py"
    $PythonCode | Set-Content -Path $TempScript -Encoding UTF8

    & $VenvPython $TempScript
    if ($LASTEXITCODE -ne 0) {
        Remove-Item $TempScript -ErrorAction SilentlyContinue
        Write-Err "Database migration failed"
        exit 1
    }

    Remove-Item $TempScript -ErrorAction SilentlyContinue
    Write-Ok "Database migrations complete"
}

# ── Clean up old backups (keep last 5) ────────────────────────────────────────

function Prune-Backups {
    param([string]$InstallDir)

    $BackupRoot = Join-Path $InstallDir "backups"
    if (-not (Test-Path $BackupRoot)) { return }

    $Entries = Get-ChildItem $BackupRoot -Directory | Sort-Object Name
    $Count   = $Entries.Count
    if ($Count -le 5) { return }

    $ToRemove = $Entries | Select-Object -First ($Count - 5)
    foreach ($Entry in $ToRemove) {
        Remove-Item $Entry.FullName -Recurse -Force
    }
    Write-Info "Old backups pruned (kept last 5 of $Count)"
}

# ── Summary ───────────────────────────────────────────────────────────────────

function Print-Done {
    param([string]$InstallDir, [string]$BackupDir, [string]$Commit)

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "     Centralized — Update Complete" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Install dir : $InstallDir"
    Write-Host "  Backup      : $BackupDir"
    Write-Host "  Commit      : $Commit"
    Write-Host ""
    Write-Host "  Your clients, audits and uploaded files are intact."
    Write-Host ""
    Write-Host "  Restart the app to apply changes:"
    Write-Host "    centralized" -ForegroundColor Cyan
    Write-Host ""
}

# ── Entry point ───────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "========================================" -ForegroundColor Blue
Write-Host "   Centralized — Update Script" -ForegroundColor Blue
Write-Host "========================================" -ForegroundColor Blue
Write-Host ""

$InstallDir = Find-InstallDir
Write-Info "Install directory: $InstallDir"

$BackupDir  = Backup-Data    -InstallDir $InstallDir
$Commit     = Update-Git     -InstallDir $InstallDir
$VenvPython = Update-Dependencies -InstallDir $InstallDir
Apply-DbMigrations -VenvPython $VenvPython -InstallDir $InstallDir
Prune-Backups      -InstallDir $InstallDir
Print-Done         -InstallDir $InstallDir -BackupDir $BackupDir -Commit $Commit
