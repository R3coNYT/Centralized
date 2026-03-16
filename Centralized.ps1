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

# ── Windows Service registration ─────────────────────────────────────────────

function Install-CentralizedService {
    $ServiceName   = "Centralized"
    $VenvPython    = "$InstallDir\venv\Scripts\python.exe"
    $ServiceScript = "$InstallDir\centralized_service.py"

    Write-Info "Registering Centralized as a Windows service"

    if (-not (Test-Path $ServiceScript)) {
        Write-Warn "centralized_service.py not found — skipping service registration"
        Write-Warn "Start the app manually: $InstallDir\centralized.bat"
        return
    }

    # -- Copy Python DLLs next to pythonservice.exe ----------------------------
    # pythonservice.exe lives in $InstallDir\venv\  and is linked to python3xx.dll.
    # When the SCM starts it (as SYSTEM), the DLL search path does not include
    # the user's PATH, so python3xx.dll and pywintypes3xx.dll must be in the
    # same directory as the executable.
    $VenvRoot    = "$InstallDir\venv"
    $PyvenvCfg   = "$VenvRoot\pyvenv.cfg"
    if (Test-Path $PyvenvCfg) {
        $homeLine = Get-Content $PyvenvCfg | Where-Object { $_ -match "^home\s*=" } | Select-Object -First 1
        if ($homeLine) {
            $BasePyDir = (($homeLine -split "=", 2)[1]).Trim()
            if (Test-Path $BasePyDir) {
                Get-ChildItem $BasePyDir -Filter "python3*.dll" -ErrorAction SilentlyContinue | ForEach-Object {
                    Copy-Item $_.FullName "$VenvRoot\" -Force -ErrorAction SilentlyContinue
                }
                Write-Ok "Python runtime DLL copied to venv root"
            }
        }
    }
    # pywintypes3xx.dll (pywin32 helper DLL)
    $PyWin32Sys = "$VenvRoot\Lib\site-packages\pywin32_system32"
    if (Test-Path $PyWin32Sys) {
        Get-ChildItem $PyWin32Sys -Filter "*.dll" -ErrorAction SilentlyContinue | ForEach-Object {
            Copy-Item $_.FullName "$VenvRoot\" -Force -ErrorAction SilentlyContinue
        }
        Write-Ok "pywin32 DLLs copied to venv root"
    }

    # Remove any existing service first
    $existing = Get-Service $ServiceName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Warn "Existing service found — reinstalling"
        if ($existing.Status -eq "Running") {
            & sc.exe stop $ServiceName | Out-Null
            Start-Sleep -Seconds 3
        }
        & $VenvPython $ServiceScript remove 2>$null | Out-Null
        Start-Sleep -Seconds 1
    }

    # Register service (uses the venv Python so all dependencies are available)
    & $VenvPython $ServiceScript install
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "Service installation failed — you can still launch manually: $InstallDir\centralized.bat"
        return
    }

    # Set startup type to Automatic (delayed start)
    & sc.exe config $ServiceName start= delayed-auto | Out-Null
    # Set service description
    & sc.exe description $ServiceName "R3coNYT Centralized pentest audit management platform" | Out-Null

    # Start the service now
    & sc.exe start $ServiceName | Out-Null
    Start-Sleep -Seconds 5

    $svc = Get-Service $ServiceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Write-Ok "Service running  ->  http://127.0.0.1:$AppPort"
    } else {
        Write-Warn "Service installed but may need a moment to start"
        Write-Warn "  Check : Get-Service $ServiceName"
        Write-Warn "  Logs  : Get-EventLog Application -Source $ServiceName -Newest 10"
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
