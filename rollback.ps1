#Requires -Version 5.1
<#
.SYNOPSIS
    Centralized - Rollback Script (Windows)
.DESCRIPTION
    Checks out a specific commit from GitHub while preserving your database,
    uploaded files, and any local .env configuration.
    Creates a timestamped backup before rolling back.
.PARAMETER Commit
    Git commit SHA (full or abbreviated, 7-40 hex chars) to roll back to.
.PARAMETER NoRestart
    Skip stopping/starting the Windows scheduled task (used when called from the web UI).
#>
param(
    [Parameter(Mandatory=$true)][string]$Commit,
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
    $ScriptDir = Split-Path -Parent $MyInvocation.ScriptName
    if ($ScriptDir -and (Test-Path "$ScriptDir\app.py") -and (Test-Path "$ScriptDir\.git")) {
        return $ScriptDir
    }
    if ($PSScriptRoot -and (Test-Path "$PSScriptRoot\app.py") -and (Test-Path "$PSScriptRoot\.git")) {
        return $PSScriptRoot
    }
    $Default = "C:\Tools\Centralized"
    if ((Test-Path "$Default\app.py") -and (Test-Path "$Default\.git")) {
        return $Default
    }
    Write-Err "Could not locate the Centralized install directory."
    Write-Err "Run this script from inside the install directory."
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

    $DbPath = Join-Path $InstallDir "centralized.db"
    if (Test-Path $DbPath) {
        Copy-Item $DbPath -Destination $BackupDir
        $DbSize = [math]::Round((Get-Item $DbPath).Length / 1KB, 1)
        Write-Ok "Database backed up (${DbSize} KB)"
    } else {
        Write-Warn "No database found - nothing to back up"
    }

    $UploadsPath = Join-Path $InstallDir "uploads"
    if (Test-Path $UploadsPath) {
        $Count = @(Get-ChildItem $UploadsPath -Recurse -File -ErrorAction SilentlyContinue).Count
        if ($Count -gt 0) {
            Copy-Item $UploadsPath -Destination (Join-Path $BackupDir "uploads") -Recurse
            Write-Ok "Uploads backed up ($Count files)"
        }
    }

    $EnvPath = Join-Path $InstallDir ".env"
    if (Test-Path $EnvPath) {
        Copy-Item $EnvPath -Destination $BackupDir
        Write-Ok ".env backed up"
    }

    Write-Ok "Backup complete -> $BackupDir"
    return $BackupDir
}

# -- Git rollback to specific commit --------------------------------------------

function Set-GitCommit {
    param([string]$InstallDir, [string]$CommitSha)

    Write-Log "Rolling back to commit $CommitSha"
    Set-Location $InstallDir

    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Err "git is not installed or not in PATH"
        Write-Err "Install Git for Windows: https://git-scm.com/download/win"
        exit 1
    }

    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"

    $StashResult = (git stash --quiet 2>&1) -join " "
    if ($StashResult -and $StashResult -notmatch "No local changes") {
        Write-Info "Local tracked-file changes stashed: $StashResult"
    }

    # Untrack data files so git never tries to write/delete them
    git rm --cached centralized.db --quiet 2>$null | Out-Null
    git rm --cached -r uploads/ --quiet 2>$null | Out-Null

    # Fetch all refs from remote so the target commit is available locally
    git fetch origin --quiet 2>$null
    if ($LASTEXITCODE -ne 0) {
        $ErrorActionPreference = $prev
        Write-Err "git fetch failed (exit $LASTEXITCODE). Check network / remote URL."
        exit 1
    }

    # Reset to the requested commit
    git reset --hard $CommitSha --quiet 2>$null
    if ($LASTEXITCODE -ne 0) {
        $ErrorActionPreference = $prev
        Write-Err "git reset to '$CommitSha' failed. The commit may not exist or is not reachable."
        exit 1
    }

    $ErrorActionPreference = $prev

    $Actual = (git rev-parse --short HEAD 2>$null).Trim()
    Write-Ok "Code rolled back -> commit $Actual"
    return $Actual
}

# -- Sync Python dependencies ---------------------------------------------------

function Update-Dependencies {
    param([string]$InstallDir)

    $VenvPip    = Join-Path $InstallDir "venv\Scripts\pip.exe"
    $VenvPython = Join-Path $InstallDir "venv\Scripts\python.exe"

    if (-not (Test-Path $VenvPython)) {
        Write-Err "Virtual environment not found at $InstallDir\venv"
        Write-Err "Please run Centralized.ps1 to reinstall."
        exit 1
    }

    Write-Log "Syncing Python dependencies"

    & $VenvPip install --upgrade pip --quiet
    if ($LASTEXITCODE -ne 0) { Write-Err "pip upgrade failed"; exit 1 }

    # Install (not --upgrade) to match the requirements of the rolled-back version exactly
    & $VenvPip install -r (Join-Path $InstallDir "requirements.txt") --quiet
    if ($LASTEXITCODE -ne 0) { Write-Err "Dependency installation failed"; exit 1 }

    Write-Ok "Dependencies ready"
    return $VenvPython
}

# -- Apply DB migrations --------------------------------------------------------

function Apply-DbMigrations {
    param([string]$VenvPython, [string]$InstallDir)

    Write-Log "Applying database migrations"
    $PythonCode = "import sys; sys.path.insert(0, r'$InstallDir'); from app import create_app; app = create_app(); print('  Database schema up-to-date.')"
    & $VenvPython -c $PythonCode
    if ($LASTEXITCODE -ne 0) { Write-Err "Database migration failed"; exit 1 }
    Write-Ok "Database migrations complete"
}

# -- Restore data from backup ---------------------------------------------------

function Restore-Data {
    param([string]$InstallDir, [string]$BackupDir)

    Write-Log "Restoring database and uploads from backup"

    $BackupDb = Join-Path $BackupDir "centralized.db"
    $TargetDb = Join-Path $InstallDir "centralized.db"
    if (Test-Path $BackupDb) {
        Copy-Item $BackupDb -Destination $TargetDb -Force
        Write-Ok "Database restored"
    } else {
        Write-Warn "No database found in backup - skipping DB restore"
    }

    $BackupUploads = Join-Path $BackupDir "uploads"
    $TargetUploads = Join-Path $InstallDir "uploads"
    if (Test-Path $BackupUploads) {
        Copy-Item (Join-Path $BackupUploads "*") -Destination $TargetUploads -Recurse -Force -ErrorAction SilentlyContinue
        Write-Ok "Uploads restored"
    }

    $BackupEnv = Join-Path $BackupDir ".env"
    $TargetEnv = Join-Path $InstallDir ".env"
    if ((Test-Path $BackupEnv) -and -not (Test-Path $TargetEnv)) {
        Copy-Item $BackupEnv -Destination $TargetEnv -Force
        Write-Ok ".env restored"
    }
}

# -- Clean up old backups (keep last 5) -----------------------------------------

function Prune-Backups {
    param([string]$InstallDir)

    $BackupRoot = Join-Path $InstallDir "backups"
    if (-not (Test-Path $BackupRoot)) { return }

    $Entries = @(Get-ChildItem $BackupRoot -Directory | Sort-Object Name)
    if ($Entries.Count -le 5) { return }

    $ToRemove = $Entries | Select-Object -First ($Entries.Count - 5)
    foreach ($E in $ToRemove) { Remove-Item $E.FullName -Recurse -Force }
    Write-Info "Old backups pruned (kept last 5)"
}

# -- Service management ---------------------------------------------------------

function Stop-CentralizedService {
    $task = Get-ScheduledTask -TaskName "Centralized" -ErrorAction SilentlyContinue
    if ($null -eq $task) { return $false }

    if ($task.State -eq "Running") {
        Write-Log "Stopping Centralized scheduled task"
        Stop-ScheduledTask -TaskName "Centralized" -ErrorAction SilentlyContinue
        $elapsed = 0
        while ($elapsed -lt 30) {
            Start-Sleep -Seconds 1; $elapsed++
            $t = Get-ScheduledTask -TaskName "Centralized" -ErrorAction SilentlyContinue
            if ($null -eq $t -or $t.State -ne "Running") { break }
        }
        Write-Ok "Task stopped"
    }
    return $true
}

function Start-CentralizedService {
    $task = Get-ScheduledTask -TaskName "Centralized" -ErrorAction SilentlyContinue
    if ($null -eq $task) { return }

    Write-Log "Starting Centralized scheduled task"
    Start-ScheduledTask -TaskName "Centralized" -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 4

    $task = Get-ScheduledTask -TaskName "Centralized" -ErrorAction SilentlyContinue
    if ($task -and $task.State -eq "Running") {
        Write-Ok "Task running -> http://127.0.0.1:5000"
    } else {
        Write-Warn "Task may not be running yet"
        Write-Warn "  Check: Get-ScheduledTask -TaskName Centralized"
    }
}

# -- Summary --------------------------------------------------------------------

function Print-Done {
    param([string]$InstallDir, [string]$BackupDir, [string]$Commit, [bool]$ServicePresent)

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "     Centralized - Rollback Complete" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Install dir : $InstallDir"
    Write-Host "  Backup      : $BackupDir"
    Write-Host "  Rolled to   : $Commit"
    Write-Host ""
    Write-Host "  Your clients, audits and uploaded files are intact."
    Write-Host ""
    if ($ServicePresent) {
        if ($NoRestart) {
            Write-Host "  Apply by restarting the task:" -ForegroundColor Yellow
            Write-Host "    Stop-ScheduledTask -TaskName Centralized; Start-ScheduledTask -TaskName Centralized" -ForegroundColor Cyan
        } else {
            Write-Host "  Task restarted -> http://127.0.0.1:5000" -ForegroundColor Cyan
        }
    } else {
        Write-Host "  Restart the app to apply changes:"
        Write-Host "    C:\Tools\Centralized\centralized.bat" -ForegroundColor Cyan
    }
    Write-Host ""
}

# -- Entry point ----------------------------------------------------------------

# Validate commit SHA format (7-40 hex chars)
if ($Commit -notmatch '^[0-9a-fA-F]{7,40}$') {
    Write-Err "Invalid commit SHA: '$Commit' (must be 7-40 hex characters)"
    exit 1
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Yellow
Write-Host "   Centralized - Rollback Script" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow
Write-Host ""

$InstallDir = Find-InstallDir
Write-Info "Install directory: $InstallDir"
Write-Info "Target commit    : $Commit"

$ServicePresent = $false
if (-not $NoRestart) {
    $ServicePresent = Stop-CentralizedService
}

$BackupDir  = Backup-Data         -InstallDir $InstallDir
$Actual     = Set-GitCommit       -InstallDir $InstallDir -CommitSha $Commit
Restore-Data                      -InstallDir $InstallDir -BackupDir $BackupDir
$VenvPython = Update-Dependencies -InstallDir $InstallDir
Apply-DbMigrations -VenvPython $VenvPython -InstallDir $InstallDir
Prune-Backups      -InstallDir $InstallDir
Print-Done         -InstallDir $InstallDir -BackupDir $BackupDir -Commit $Actual -ServicePresent $ServicePresent

if (-not $NoRestart -and $ServicePresent) {
    Start-CentralizedService
} elseif ($NoRestart -and $ServicePresent) {
    Write-Log "Scheduling automatic task restart in ~5 seconds"
    $RestartCmd = "Start-Sleep 5; Stop-ScheduledTask -TaskName 'Centralized' -ErrorAction SilentlyContinue; Start-Sleep 3; Start-ScheduledTask -TaskName 'Centralized'"
    Start-Process powershell.exe `
        -ArgumentList "-NonInteractive -NoProfile -WindowStyle Hidden -Command `"$RestartCmd`"" `
        -WindowStyle Hidden
    Write-Ok "Task will restart automatically in ~8 seconds"
}
