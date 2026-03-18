#Requires -Version 5.1
<#
.SYNOPSIS
    Centralized — Windows Installer
.DESCRIPTION
    Installs the Centralized pentest audit platform on Windows.
    Clones the repository, creates a Python virtual environment,
    installs all dependencies and creates a launcher script.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File Centralized.ps1
#>

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"

# ── Configuration ──────────────────────────────────────────────────────────────
$RepoUrl    = "https://github.com/R3coNYT/Centralized.git"
$InstallDir = "C:\Tools\Centralized"
$AppPort    = 5000

# ── Helpers ────────────────────────────────────────────────────────────────────

function Write-Info($msg) { Write-Host "[+] $msg" -ForegroundColor Cyan    }
function Write-Ok($msg)   { Write-Host "[√] $msg" -ForegroundColor Green   }
function Write-Warn($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow  }
function Write-Err($msg)  { Write-Host "[x] $msg" -ForegroundColor Red     }

function Test-Cmd($name) {
    return $null -ne (Get-Command $name -ErrorAction SilentlyContinue)
}

function New-Directory($Path) {
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Invoke-Retry {
    param(
        [int]$Attempts = 3,
        [scriptblock]$Script
    )
    for ($i = 1; $i -le $Attempts; $i++) {
        try {
            & $Script
            return
        } catch {
            if ($i -eq $Attempts) { throw }
            Write-Warn "Attempt $i/$Attempts failed — retrying in 2s..."
            Start-Sleep -Seconds 2
        }
    }
}

# ── Python detection ───────────────────────────────────────────────────────────

function Find-Python {
    # Prefer py launcher, then python, then python3
    $candidates = @("py -3", "python", "python3")

    foreach ($cand in $candidates) {
        $exe  = ($cand -split ' ')[0]
        $pythonArgs = ($cand -split ' ')[1..99]

        if (Test-Cmd $exe) {
            try {
                $ver = & $exe @pythonArgs -c "import sys; v=sys.version_info; print(f'{v.major}.{v.minor}')" 2>$null
                if ($ver -match '^3\.(1[0-9]|[2-9]\d)') {
                    Write-Ok "Python detected: $exe $ver"
                    return @{ Exe = $exe; Args = $pythonArgs }
                }
            } catch {}
        }
    }

    Write-Err "Python 3.10+ is required but was not found."
    Write-Err "Download it from https://www.python.org/downloads/"
    exit 1
}

# ── Admin elevation check ────────────────────────────────────────────────────

function Assert-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltinRole]::Administrator
    )
    if (-not $isAdmin) {
        Write-Err "This script must be run as Administrator (required to register the Windows service)."
        Write-Err "Right-click PowerShell > 'Run as administrator', then re-run."
        exit 1
    }
    Write-Ok "Running as Administrator"
}

# ── Git check ─────────────────────────────────────────────────────────────────

function Assert-Git {
    if (-not (Test-Cmd git)) {
        Write-Err "Git is required. Install Git for Windows: https://git-scm.com/download/win"
        exit 1
    }
    Write-Ok "Git detected: $(git --version)"
}

# ── Clone / update repository ─────────────────────────────────────────────────

function Install-Repo {
    Write-Info "Setting up repository in $InstallDir"
    New-Directory "C:\Tools"
    New-Directory $InstallDir

    if (Test-Path "$InstallDir\.git") {
        Write-Ok "Repository already present — pulling latest"
        git -C $InstallDir pull
    } else {
        Invoke-Retry -Attempts 3 -Script {
            git clone $RepoUrl $InstallDir
        }
    }
    Write-Ok "Repository ready"
}

# ── Python virtual environment ────────────────────────────────────────────────

function Install-Venv {
    param($PyInfo)

    Write-Info "Creating Python virtual environment"

    $venvPath = "$InstallDir\venv"
    $pipExe   = "$venvPath\Scripts\pip.exe"
    $pyExe    = "$venvPath\Scripts\python.exe"

    if (-not (Test-Path $venvPath)) {
        $pyExeBase = $PyInfo.Exe
        $pyArgsBase = $PyInfo.Args
        & $pyExeBase @pyArgsBase -m venv $venvPath
    } else {
        Write-Ok "Virtual environment already exists"
    }

    Invoke-Retry -Attempts 3 -Script {
        & $pyExe -m pip install --upgrade pip --quiet
    }

    Invoke-Retry -Attempts 3 -Script {
        & $pipExe install -r "$InstallDir\requirements.txt" --quiet
    }

    Write-Ok "Python environment ready"
}

# ── Uploads directory ─────────────────────────────────────────────────────────

function New-UploadsDir {
    New-Directory "$InstallDir\uploads"
    Write-Ok "Uploads directory ready"
}

# ── Launcher batch file ───────────────────────────────────────────────────────

function New-Launcher {
    Write-Info "Creating launcher"

    $bat = @"
@echo off
title Centralized — Pentest Audit Platform
call "$InstallDir\venv\Scripts\activate.bat"
cd /d "$InstallDir"
python app.py
pause
"@
    Set-Content -Path "$InstallDir\centralized.bat" -Value $bat -Encoding ASCII

    # PowerShell launcher (keeps colour output)
    $ps1 = @"
#Requires -Version 5.1
Set-Location '$InstallDir'
& '$InstallDir\venv\Scripts\Activate.ps1'
python app.py
"@
    Set-Content -Path "$InstallDir\centralized.ps1" -Value $ps1 -Encoding UTF8

    Write-Ok "Launchers created:"
    Write-Ok "  $InstallDir\centralized.bat"
    Write-Ok "  $InstallDir\centralized.ps1"
}

# ── PATH update ──────────────────────────────────────────────────────────────

function Update-UserPath {
    $current = [Environment]::GetEnvironmentVariable("Path", "User")

    $toAdd = @("C:\Tools\Centralized")
    foreach ($p in $toAdd) {
        if ($current -notlike "*$p*") {
            $current = "$current;$p"
        }
    }
    [Environment]::SetEnvironmentVariable("Path", $current, "User")
    $env:Path = "$env:Path;C:\Tools\Centralized"
    Write-Ok "User PATH updated"
}

# ── Startup task (Windows Task Scheduler) ────────────────────────────────────
# Uses only built-in Windows cmdlets — no NSSM or pywin32 required.
# The task runs as SYSTEM at startup, with automatic restart on failure,
# and redirects stdout/stderr to a log file via a small wrapper script.

function Install-CentralizedTask {
    $TaskName   = "Centralized"
    $VenvPython = "$InstallDir\venv\Scripts\python.exe"
    $LogDir     = "$InstallDir\logs"
    $WrapperPs1 = "$InstallDir\start_service.ps1"

    # Ensure logs directory exists
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

    # Wrapper script: starts waitress and tee-s output to a rotating log
    $wrapper = @"
Set-Location '$InstallDir'
`$log = '$LogDir\service.log'
# Keep at most 2 MB of log (rough rotation)
if ((Test-Path `$log) -and (Get-Item `$log).Length -gt 2MB) {
    Move-Item `$log "`$log.bak" -Force
}
& '$VenvPython' -m waitress --port=$AppPort --call app:create_app *>> `$log
"@
    Set-Content -Path $WrapperPs1 -Value $wrapper -Encoding UTF8

    Write-Info "Registering Centralized as a Windows scheduled task"

    # Remove existing task if present
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Warn "Existing task found — reinstalling"
        Stop-ScheduledTask  -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }

    $action = New-ScheduledTaskAction `
        -Execute    "powershell.exe" `
        -Argument   "-NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$WrapperPs1`"" `
        -WorkingDirectory $InstallDir

    $trigger = New-ScheduledTaskTrigger -AtStartup

    # Auto-restart up to 3 times with 30-second delay
    $settings = New-ScheduledTaskSettingsSet `
        -ExecutionTimeLimit      (New-TimeSpan -Seconds 0) `
        -RestartCount            3 `
        -RestartInterval         (New-TimeSpan -Seconds 30) `
        -StartWhenAvailable `
        -MultipleInstances       IgnoreNew

    $principal = New-ScheduledTaskPrincipal `
        -UserId    "SYSTEM" `
        -LogonType ServiceAccount `
        -RunLevel  Highest

    Register-ScheduledTask `
        -TaskName    $TaskName `
        -Action      $action `
        -Trigger     $trigger `
        -Settings    $settings `
        -Principal   $principal `
        -Description "R3coNYT Centralized pentest audit management platform" `
        -Force | Out-Null

    # Start immediately
    Start-ScheduledTask -TaskName $TaskName
    Start-Sleep -Seconds 4

    $state = (Get-ScheduledTask -TaskName $TaskName).State
    if ($state -eq "Running") {
        Write-Ok "Tâche démarrée  ->  http://127.0.0.1:$AppPort"
    } else {
        Write-Warn "Tâche enregistrée (état : $state) — vérifiez dans quelques secondes :"
        Write-Warn "  Get-ScheduledTask -TaskName Centralized"
        Write-Warn "  Logs : $LogDir\service.log"
    }
}

# ── Final summary ─────────────────────────────────────────────────────────────

function Write-Done {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "   Centralized — Installation Complete  " -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Install dir : $InstallDir"             -ForegroundColor White
    Write-Host "  App URL     : http://127.0.0.1:$AppPort" -ForegroundColor White
    Write-Host "  Login       : admin / admin"            -ForegroundColor White
    Write-Host ""
    $task = Get-ScheduledTask -TaskName "Centralized" -ErrorAction SilentlyContinue
    if ($task) {
        Write-Host "  Tâche       : Centralized (démarre au boot, tourne en arrière-plan)" -ForegroundColor Cyan
        Write-Host "  Arrêter     : Stop-ScheduledTask -TaskName Centralized"              -ForegroundColor Yellow
        Write-Host "  Désactiver  : Disable-ScheduledTask -TaskName Centralized"           -ForegroundColor Yellow
        Write-Host "  Logs        : $InstallDir\logs\service.log"                          -ForegroundColor Yellow
    } else {
        Write-Host "  Start the app (pick one):"             -ForegroundColor Cyan
        Write-Host "    $InstallDir\centralized.bat"         -ForegroundColor Yellow
        Write-Host "    $InstallDir\centralized.ps1  (PowerShell)" -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "  IMPORTANT: Change the default admin password after first login!" -ForegroundColor Red
    Write-Host ""
}

# ── Entry point ───────────────────────────────────────────────────────────────

function Main {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "   Centralized — Windows Installer      " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    Assert-Git
    Assert-Admin
    $pyInfo = Find-Python

    Install-Repo
    Install-Venv -PyInfo $pyInfo
    New-UploadsDir
    New-Launcher
    Update-UserPath
    Install-CentralizedTask

    Write-Done
}

Main
