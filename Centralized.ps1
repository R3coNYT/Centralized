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
        $args = ($cand -split ' ')[1..99]

        if (Test-Cmd $exe) {
            try {
                $ver = & $exe @args -c "import sys; v=sys.version_info; print(f'{v.major}.{v.minor}')" 2>$null
                if ($ver -match '^3\.(1[0-9]|[2-9]\d)') {
                    Write-Ok "Python detected: $exe $ver"
                    return @{ Exe = $exe; Args = $args }
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

# ── Windows Service registration (via NSSM) ───────────────────────────────────
# pythonservice.exe (pywin32) fails under the SYSTEM account because the base
# Python Lib\ directory is not found at runtime. NSSM wraps venv\Scripts\python.exe
# directly, avoiding all DLL / PATH issues.

function Get-Nssm {
    # If already present in the install dir, reuse it
    $NssmExe = "$InstallDir\nssm.exe"
    if (Test-Path $NssmExe) { return $NssmExe }

    Write-Info "Downloading NSSM from github.com/kirillkovalenko/nssm"
    $Zip  = "$env:TEMP\nssm.zip"
    $Dest = "$env:TEMP\nssm_extract"
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        # Récupère l'URL du dernier release via l'API GitHub
        $ApiUrl  = "https://api.github.com/repos/kirillkovalenko/nssm/releases/latest"
        $Headers = @{ "User-Agent" = "Centralized-Installer" }
        $Release = Invoke-RestMethod -Uri $ApiUrl -Headers $Headers -UseBasicParsing

        # Cherche un asset zip dans les assets du release
        $Asset = $Release.assets | Where-Object { $_.name -like "*.zip" } | Select-Object -First 1

        if (-not $Asset) {
            throw "Aucun asset .zip trouvé dans le dernier release (kirillkovalenko/nssm)."
        }

        Write-Info "Asset trouvé : $($Asset.name)  [$($Asset.browser_download_url)]"
        Invoke-WebRequest $Asset.browser_download_url -OutFile $Zip -UseBasicParsing
        Expand-Archive $Zip -DestinationPath $Dest -Force

        # Cherche nssm.exe dans win64/ en priorité, sinon n'importe où dans l'archive
        $Exe = Get-ChildItem $Dest -Recurse -Filter "nssm.exe" |
               Where-Object { $_.FullName -like "*win64*" } |
               Select-Object -First 1

        if (-not $Exe) {
            $Exe = Get-ChildItem $Dest -Recurse -Filter "nssm.exe" | Select-Object -First 1
        }

        if (-not $Exe) {
            throw "nssm.exe introuvable dans l'archive téléchargée."
        }

        Copy-Item $Exe.FullName $NssmExe -Force
        Write-Ok "NSSM prêt  ($($Exe.FullName))"
    } catch {
        Write-Warn "Impossible de télécharger NSSM : $_"
        return $null
    } finally {
        Remove-Item $Zip  -Force -ErrorAction SilentlyContinue
        Remove-Item $Dest -Recurse -Force -ErrorAction SilentlyContinue
    }
    return $NssmExe
}

function Install-CentralizedService {
    $ServiceName = "Centralized"
    $VenvPython  = "$InstallDir\venv\Scripts\python.exe"
    $NssmExe     = Get-Nssm

    if (-not $NssmExe) {
        Write-Warn "NSSM not available — service registration skipped"
        Write-Warn "Start the app manually: $InstallDir\centralized.bat"
        return
    }

    Write-Info "Registering Centralized as a Windows service (NSSM)"

    # Remove any existing service first (pywin32 or NSSM)
    $existing = Get-Service $ServiceName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Warn "Existing service found — reinstalling"
        if ($existing.Status -eq "Running") {
            Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
        }
        & $NssmExe remove $ServiceName confirm 2>$null | Out-Null
        # Also attempt pywin32 removal in case it was registered that way
        if (Test-Path "$InstallDir\centralized_service.py") {
            & $VenvPython "$InstallDir\centralized_service.py" remove 2>$null | Out-Null
        }
        Start-Sleep -Seconds 1
    }

    # Ensure logs directory exists (NSSM will write stdout/stderr there)
    New-Item -ItemType Directory -Path "$InstallDir\logs" -Force | Out-Null

    # Register via NSSM — points directly at the venv Python, no DLL tricks needed
    & $NssmExe install     $ServiceName $VenvPython
    & $NssmExe set         $ServiceName AppParameters   "-m waitress --port=$AppPort --call app:create_app"
    & $NssmExe set         $ServiceName AppDirectory    $InstallDir
    & $NssmExe set         $ServiceName DisplayName     "Centralized - Pentest Audit Platform"
    & $NssmExe set         $ServiceName Description     "R3coNYT Centralized pentest audit management platform"
    & $NssmExe set         $ServiceName Start           SERVICE_DELAYED_AUTO_START
    & $NssmExe set         $ServiceName AppStdout       "$InstallDir\logs\service.log"
    & $NssmExe set         $ServiceName AppStderr       "$InstallDir\logs\service.log"
    & $NssmExe set         $ServiceName AppRotateFiles  1
    & $NssmExe set         $ServiceName AppRotateBytes  1048576

    # Start the service now
    & $NssmExe start $ServiceName | Out-Null
    Start-Sleep -Seconds 5

    $svc = Get-Service $ServiceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Write-Ok "Service running  ->  http://127.0.0.1:$AppPort"
    } else {
        Write-Warn "Service installed — check status in a moment:"
        Write-Warn "  Get-Service Centralized"
        Write-Warn "  Logs: $InstallDir\logs\service.log"
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
    $svc = Get-Service "Centralized" -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Host "  Service     : Centralized (auto-start, runs in background)" -ForegroundColor Cyan
        Write-Host "  Stop        : Stop-Service Centralized" -ForegroundColor Yellow
        Write-Host "  Disable     : Set-Service Centralized -StartupType Manual; Stop-Service Centralized" -ForegroundColor Yellow
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
    Install-CentralizedService

    Write-Done
}

Main
