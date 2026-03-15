#Requires -Version 5.1
<#
.SYNOPSIS
    Centralized - Update Script (Windows)
.DESCRIPTION
    Pulls the latest code from GitHub while preserving your database,
    uploaded files, and any local .env configuration.
    Creates a timestamped backup before updating.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# -- Console helpers ------------------------------------------------------------

function Write-Log  { param([string]$Msg) Write-Host "[+] $Msg" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Msg) Write-Host "[OK] $Msg" -ForegroundColor Green }
function Write-Warn { param([string]$Msg) Write-Host "[!] $Msg" -ForegroundColor Yellow }
function Write-Err  { param([string]$Msg) Write-Host "[X] $Msg" -ForegroundColor Red }
function Write-Info { param([string]$Msg) Write-Host "[i] $Msg" -ForegroundColor Gray }

# -- Locate install directory ---------------------------------------------------

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

# -- Backup data ----------------------------------------------------------------

function Backup-Data {
    param([string]$InstallDir)

    $Timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
    $BackupRoot = Join-Path $InstallDir "backups"
    $BackupDir  = Join-Path $BackupRoot $Timestamp

    Write-Log "Creating backup -> $BackupDir"
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null

    # SQLite database
    $DbPath = Join-Path $InstallDir "centralized.db"
    if (Test-Path $DbPath) {
        Copy-Item $DbPath -Destination $BackupDir
        $DbSize = [math]::Round((Get-Item $DbPath).Length / 1KB, 1)
        Write-Ok "Database backed up (${DbSize} KB)"
    } else {
        Write-Warn "No database found - nothing to back up"
    }

    # Uploaded files
    $UploadsPath = Join-Path $InstallDir "uploads"
    if (Test-Path $UploadsPath) {
        $UploadsCount = (Get-ChildItem $UploadsPath -Recurse -File -ErrorAction SilentlyContinue).Count
        if ($UploadsCount -gt 0) {
            Copy-Item $UploadsPath -Destination (Join-Path $BackupDir "uploads") -Recurse
            Write-Ok "Uploads backed up $($UploadsCount) files"
        }
    }

    # Local .env override
    $EnvPath = Join-Path $InstallDir ".env"
    if (Test-Path $EnvPath) {
        Copy-Item $EnvPath -Destination $BackupDir
        Write-Ok ".env backed up"
    }

    Write-Ok "Backup complete -> $BackupDir"
    return $BackupDir
}

# -- Git pull -------------------------------------------------------------------

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

    # Git writes informational messages to stderr; suppress NativeCommandError
    # for all git calls and rely on $LASTEXITCODE instead.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"

    # Stash any accidental local changes to tracked files
    $StashResult = (git stash --quiet 2>&1) -join " "
    if ($StashResult -and $StashResult -notmatch "No local changes") {
        Write-Info "Local tracked-file changes stashed: $StashResult"
    }

    # --- Protect data files before git reset -----------------------------------
    # centralized.db / uploads/ may still be tracked in the remote repo if they
    # were committed before .gitignore was added. git reset --hard would overwrite
    # them. We protect them by copying to a temp folder and restoring afterwards.
    $TempProtect = Join-Path $env:TEMP "centralized_protect_$(Get-Date -Format 'yyyyMMddHHmmss')"
    New-Item -ItemType Directory -Path $TempProtect -Force | Out-Null

    $DbPath      = Join-Path $InstallDir "centralized.db"
    $UploadsPath = Join-Path $InstallDir "uploads"

    if (Test-Path $DbPath) {
        Copy-Item $DbPath -Destination $TempProtect
    }
    if (Test-Path $UploadsPath) {
        Copy-Item $UploadsPath -Destination (Join-Path $TempProtect "uploads") -Recurse
    }
    # ---------------------------------------------------------------------------

    # Fetch + hard reset to match remote
    git fetch origin --quiet 2>$null
    if ($LASTEXITCODE -ne 0) {
        $ErrorActionPreference = $prev
        Write-Err "git fetch failed (exit $LASTEXITCODE). Check network / remote URL."
        exit 1
    }

    $Branch = (git rev-parse --abbrev-ref HEAD 2>$null).Trim()
    git reset --hard "origin/$Branch" --quiet 2>$null
    if ($LASTEXITCODE -ne 0) {
        $ErrorActionPreference = $prev
        Write-Err "git reset failed (exit $LASTEXITCODE)."
        exit 1
    }

    # Also untrack data files so future resets never touch them
    git rm --cached centralized.db --quiet 2>$null | Out-Null
    git rm --cached -r uploads/ --quiet 2>$null | Out-Null

    $ErrorActionPreference = $prev

    # --- Restore protected data files ------------------------------------------
    $ProtectedDb = Join-Path $TempProtect "centralized.db"
    if (Test-Path $ProtectedDb) {
        Copy-Item $ProtectedDb -Destination $InstallDir -Force
        Write-Info "Database restored after git reset"
    }
    $ProtectedUploads = Join-Path $TempProtect "uploads"
    if (Test-Path $ProtectedUploads) {
        Copy-Item $ProtectedUploads -Destination $InstallDir -Recurse -Force
        Write-Info "Uploads restored after git reset"
    }
    Remove-Item $TempProtect -Recurse -Force -ErrorAction SilentlyContinue
    # ---------------------------------------------------------------------------

    $Commit = (git rev-parse --short HEAD 2>$null).Trim()
    Write-Ok "Code updated -> commit $Commit (branch: $Branch)"
    return $Commit
}

# -- Update Python dependencies -------------------------------------------------

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

# -- Apply DB migrations (create new tables) ------------------------------------

function Apply-DbMigrations {
    param([string]$VenvPython, [string]$InstallDir)

    Write-Log "Applying database migrations"

    # Pass the install dir via sys.path so Python finds 'app' regardless of cwd
    $PythonCode = "import sys; sys.path.insert(0, r'$InstallDir'); from app import create_app; app = create_app(); print('  Database schema up-to-date.')"

    & $VenvPython -c $PythonCode
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Database migration failed"
        exit 1
    }

    Write-Ok "Database migrations complete"
}

# -- Clean up old backups (keep last 5) ----------------------------------------

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

# -- Summary -------------------------------------------------------------------

function Print-Done {
    param([string]$InstallDir, [string]$BackupDir, [string]$Commit)

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "     Centralized - Update Complete" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Install dir : $InstallDir"
    Write-Host "  Backup      : $BackupDir"
    Write-Host "  Commit      : $Commit"
    Write-Host ""
    Write-Host "  Your clients, audits and uploaded files are intact."
    Write-Host ""
    Write-Host "  Restart the app to apply changes:"
    Write-Host "    C:\Tools\Centralized\centralized.bat" -ForegroundColor Cyan
    Write-Host ""
}

# -- Entry point ---------------------------------------------------------------

Write-Host ""
Write-Host "========================================" -ForegroundColor Blue
Write-Host "   Centralized - Update Script" -ForegroundColor Blue
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
