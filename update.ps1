#Requires -Version 5.1
<#
.SYNOPSIS
    Centralized - Update Script (Windows)
.DESCRIPTION
    Pulls the latest code from GitHub while preserving your database,
    uploaded files, and any local .env configuration.
    Creates a timestamped backup before updating.
.PARAMETER NoRestart
    Skip stopping/starting the Windows service (used when called from the web UI).
#>
param(
    [switch]$NoRestart
)

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
        $UploadsCount = @(Get-ChildItem $UploadsPath -Recurse -File -ErrorAction SilentlyContinue).Count
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

    # Untrack data files BEFORE reset so git never tries to write/delete them
    # (critical on Windows where the DB file may be locked by a running process)
    git rm --cached centralized.db --quiet 2>$null | Out-Null
    git rm --cached -r uploads/ --quiet 2>$null | Out-Null

    # Fetch + hard reset to match remote
    # Note: centralized.db and uploads/ are restored afterwards by Restore-Data.
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

    $ErrorActionPreference = $prev

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

# -- Apply DB migrations (auto-detect new tables AND new columns) ---------------

function Apply-DbMigrations {
    param([string]$VenvPython, [string]$InstallDir)

    Write-Log "Applying database migrations"

    # create_app() calls db.create_all() (new tables) then _migrate_db() which
    # auto-detects every missing column across all models and runs ALTER TABLE.
    # No manual maintenance needed — any column added to models is handled here.
    $PythonCode = "import sys; sys.path.insert(0, r'$InstallDir'); from app import create_app; app = create_app(); print('  Database schema up-to-date.')"

    & $VenvPython -c $PythonCode
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Database migration failed"
        exit 1
    }

    Write-Ok "Database migrations complete"
}

# -- Restore data from backup --------------------------------------------------

function Restore-Data {
    param([string]$InstallDir, [string]$BackupDir)

    Write-Log "Restoring database and uploads from backup"

    # Database
    $BackupDb = Join-Path $BackupDir "centralized.db"
    $TargetDb = Join-Path $InstallDir "centralized.db"
    if (Test-Path $BackupDb) {
        Copy-Item $BackupDb -Destination $TargetDb -Force
        Write-Ok "Database restored"
    } else {
        Write-Warn "No database found in backup - skipping DB restore"
    }

    # Uploaded files
    $BackupUploads = Join-Path $BackupDir "uploads"
    $TargetUploads = Join-Path $InstallDir "uploads"
    if (Test-Path $BackupUploads) {
        # Merge backup back: keep any files that may have been added after backup
        Copy-Item (Join-Path $BackupUploads "*") -Destination $TargetUploads -Recurse -Force -ErrorAction SilentlyContinue
        Write-Ok "Uploads restored"
    }

    # .env
    $BackupEnv = Join-Path $BackupDir ".env"
    $TargetEnv = Join-Path $InstallDir ".env"
    if ((Test-Path $BackupEnv) -and -not (Test-Path $TargetEnv)) {
        Copy-Item $BackupEnv -Destination $TargetEnv -Force
        Write-Ok ".env restored"
    }
}

# -- Clean up old backups (keep last 5) ----------------------------------------

function Prune-Backups {
    param([string]$InstallDir)

    $BackupRoot = Join-Path $InstallDir "backups"
    if (-not (Test-Path $BackupRoot)) { return }

    $Entries = @(Get-ChildItem $BackupRoot -Directory | Sort-Object Name)
    $Count   = $Entries.Count
    if ($Count -le 5) { return }

    $ToRemove = $Entries | Select-Object -First ($Count - 5)
    foreach ($Entry in $ToRemove) {
        Remove-Item $Entry.FullName -Recurse -Force
    }
    Write-Info "Old backups pruned (kept last 5 of $Count)"
}

# -- Service management --------------------------------------------------------

function Stop-CentralizedService {
    $svc = Get-Service "Centralized" -ErrorAction SilentlyContinue
    if ($null -eq $svc) { return $false }

    if ($svc.Status -eq "Running") {
        Write-Log "Stopping Centralized service"
        Stop-Service "Centralized" -Force -ErrorAction SilentlyContinue
        # Wait up to 30 s for the service to stop
        $timeout = 30
        $elapsed = 0
        while ($elapsed -lt $timeout) {
            Start-Sleep -Seconds 1
            $elapsed++
            $svc = Get-Service "Centralized" -ErrorAction SilentlyContinue
            if ($null -eq $svc -or $svc.Status -eq "Stopped") { break }
        }
        Write-Ok "Service stopped"
    }
    return $true
}

function Start-CentralizedService {
    $svc = Get-Service "Centralized" -ErrorAction SilentlyContinue
    if ($null -eq $svc) { return }

    Write-Log "Starting Centralized service"
    Start-Service "Centralized" -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 4

    $svc = Get-Service "Centralized" -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Write-Ok "Service running -> http://127.0.0.1:5000"
    } else {
        Write-Warn "Service may not be running yet"
        Write-Warn "  Check: Get-Service Centralized"
    }
}

# -- Summary -------------------------------------------------------------------

function Print-Done {
    param([string]$InstallDir, [string]$BackupDir, [string]$Commit, [bool]$ServicePresent)

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
    if ($ServicePresent) {
        if ($NoRestart) {
            Write-Host "  Apply the update by restarting the service:" -ForegroundColor Yellow
            Write-Host "    Restart-Service Centralized" -ForegroundColor Cyan
        } else {
            Write-Host "  Service restarted -> http://127.0.0.1:5000" -ForegroundColor Cyan
        }
    } else {
        Write-Host "  Restart the app to apply changes:"
        Write-Host "    C:\Tools\Centralized\centralized.bat" -ForegroundColor Cyan
    }
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

# Stop service before updating (gives the DB exclusive access for migrations)
# Skip when called from the web UI (--NoRestart) to avoid killing the connection
$ServicePresent = $false
if (-not $NoRestart) {
    $ServicePresent = Stop-CentralizedService
}

$BackupDir  = Backup-Data    -InstallDir $InstallDir
$Commit     = Update-Git     -InstallDir $InstallDir
Restore-Data               -InstallDir $InstallDir -BackupDir $BackupDir
$VenvPython = Update-Dependencies -InstallDir $InstallDir
Apply-DbMigrations -VenvPython $VenvPython -InstallDir $InstallDir
Prune-Backups      -InstallDir $InstallDir
Print-Done         -InstallDir $InstallDir -BackupDir $BackupDir -Commit $Commit -ServicePresent $ServicePresent

# Restart the service (CLI update only; web update skips to preserve the HTTP connection)
if (-not $NoRestart -and $ServicePresent) {
    Start-CentralizedService
} elseif ($NoRestart -and $ServicePresent) {
    # Called from web UI: schedule a delayed restart via Task Scheduler so the
    # HTTP response can be delivered before the service process is killed.
    Write-Log "Scheduling automatic service restart in 10 seconds"
    $Action    = New-ScheduledTaskAction -Execute "powershell.exe" `
                     -Argument "-WindowStyle Hidden -NonInteractive -Command `"Restart-Service Centralized -Force`""
    $Trigger   = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(10)
    $Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName "CentralizedServiceRestart" `
        -Action $Action -Trigger $Trigger -Principal $Principal -Force | Out-Null
    Write-Ok "Service will restart automatically in ~10 seconds"
}