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

    # Wrapper script: starts the app and redirects stdout+stderr to a rotating log.
    # Uses python app.py so SSL auto-detection in app.py __main__ is respected.
    $wrapper = @"
Set-Location '$InstallDir'
`$log = '$LogDir\service.log'
# Keep at most 2 MB of log (rough rotation)
if ((Test-Path `$log) -and (Get-Item `$log).Length -gt 2MB) {
    Move-Item `$log "`$log.bak" -Force
}
cmd /c "$VenvPython app.py >> `$log 2>&1"
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

    # Auto-restart up to 3 times with 1-minute delay (Task Scheduler minimum is 1 min)
    $settings = New-ScheduledTaskSettingsSet `
        -ExecutionTimeLimit      (New-TimeSpan -Seconds 0) `
        -RestartCount            3 `
        -RestartInterval         (New-TimeSpan -Minutes 1) `
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
        $scheme = if (Test-Path "$InstallDir\ssl\cert.pem") { "https" } else { "http" }
        Write-Ok "Task started  ->  ${scheme}://127.0.0.1:$AppPort"
    } else {
        Write-Warn "Task registered (state: $state) — check again in a moment:"
        Write-Warn "  Get-ScheduledTask -TaskName Centralized"
        Write-Warn "  Logs : $LogDir\service.log"
    }
}

# ── SSL certificate setup ─────────────────────────────────────────────────────

function Find-OpenSsl {
    # Git for Windows ships openssl.exe — always available since git is a hard requirement
    $candidates = @(
        "C:\Program Files\Git\usr\bin\openssl.exe",
        "C:\Program Files (x86)\Git\usr\bin\openssl.exe"
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { return $c }
    }
    $inPath = Get-Command openssl -ErrorAction SilentlyContinue
    if ($inPath) { return $inPath.Source }
    return $null
}

function New-SslCertPem {
    param([string]$SslDir)

    $OpenSsl = Find-OpenSsl
    if (-not $OpenSsl) {
        Write-Warn "openssl.exe not found — SSL skipped (Centralized will run over HTTP)"
        return $false
    }

    New-Item -ItemType Directory -Path $SslDir -Force | Out-Null

    # Detect the machine's LAN IP to add to the certificate SAN so the
    # site is reachable from other devices on the local network.
    $LanIp = (Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.PrefixOrigin -ne 'WellKnown' } |
        Sort-Object -Property InterfaceIndex |
        Select-Object -First 1 -ExpandProperty IPAddress)
    $San = "DNS:localhost,IP:127.0.0.1"
    if ($LanIp) { $San = "$San,IP:$LanIp" }

    $CfgPath = Join-Path $env:TEMP "centralized_ssl.cnf"
    @"
[req]
default_bits       = 2048
prompt             = no
distinguished_name = dn
x509_extensions    = san
[dn]
CN = localhost
O  = Centralized
[san]
subjectAltName = $San
"@ | Set-Content -Path $CfgPath -Encoding ASCII

    $KeyPem  = Join-Path $SslDir "key.pem"
    $CertPem = Join-Path $SslDir "cert.pem"

    & $OpenSsl req -x509 -nodes -days 365 -newkey rsa:2048 `
        -keyout $KeyPem -out $CertPem `
        -config $CfgPath 2>$null

    Remove-Item $CfgPath -Force -ErrorAction SilentlyContinue

    if ((Test-Path $KeyPem) -and (Test-Path $CertPem)) {
        $msg = if ($LanIp) { "(localhost + $LanIp, valid 365 days)" } else { "(localhost, valid 365 days)" }
        Write-Ok "Self-signed certificate generated $msg"
        return $true
    }
    Write-Warn "Certificate generation failed — Centralized will run over HTTP"
    return $false
}

function New-SslRenewalTask {
    param([string]$InstallDir)

    $SslDir  = Join-Path $InstallDir "ssl"
    $OpenSsl = Find-OpenSsl
    if (-not $OpenSsl) { return }

    $LogDir   = Join-Path $InstallDir "logs"
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

    $RenewPs1 = Join-Path $SslDir "renew.ps1"
    # Write renewal script with escaped backticks for the here-string
    $renew = @"
# Centralized SSL certificate renewal — managed by installer
`$SslDir  = '$SslDir'
`$OpenSsl = '$OpenSsl'
`$LogFile = '$LogDir\ssl_renew.log'
function Log(`$m) { Add-Content -Path `$LogFile -Value "[`$(Get-Date -f 'yyyy-MM-dd HH:mm:ss')] `$m" }

# Exit if cert has more than 30 days left
try {
    `$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(`$SslDir + '\cert.pem')
    if (`$cert.NotAfter -gt (Get-Date).AddDays(30)) { exit 0 }
    Log "Certificate expires `$(`$cert.NotAfter.ToString('yyyy-MM-dd')) — regenerating"
} catch { Log "Could not read cert — regenerating" }

`$cfg = `$env:TEMP + '\cent_ssl_renew.cnf'
# Re-detect LAN IP at renewal time so the cert stays valid even after a network change
`$lan = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { `$_.IPAddress -ne '127.0.0.1' -and `$_.PrefixOrigin -ne 'WellKnown' } | Sort-Object InterfaceIndex | Select-Object -First 1 -ExpandProperty IPAddress)
`$san = if (`$lan) { "DNS:localhost,IP:127.0.0.1,IP:`$lan" } else { "DNS:localhost,IP:127.0.0.1" }
"[req]`ndefault_bits=2048`nprompt=no`ndistinguished_name=dn`nx509_extensions=san`n[dn]`nCN=localhost`nO=Centralized`n[san]`nsubjectAltName=`$san" | Set-Content -Path `$cfg -Encoding ASCII

& "`$OpenSsl" req -x509 -nodes -days 365 -newkey rsa:2048 ``
    -keyout "`$SslDir\key.pem" -out "`$SslDir\cert.pem" ``
    -config "`$cfg" 2>`$null
Remove-Item `$cfg -Force -ErrorAction SilentlyContinue

Stop-ScheduledTask  -TaskName 'Centralized' -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Start-ScheduledTask -TaskName 'Centralized' -ErrorAction SilentlyContinue
Log "Certificate renewed"
"@
    Set-Content -Path $RenewPs1 -Value $renew -Encoding UTF8

    $TaskName = "Centralized-SslRenew"
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existing) { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false }

    $action    = New-ScheduledTaskAction `
        -Execute  "powershell.exe" `
        -Argument "-NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$RenewPs1`""
    $trigger   = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At "03:30AM"
    $settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 1)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
        -Settings $settings -Principal $principal `
        -Description "Renew Centralized TLS certificate if expiring" -Force | Out-Null

    Write-Ok "SSL auto-renewal scheduled task registered (weekly check, Mondays 03:30)"
}

function Add-CertToTrustStore {
    # Imports a PEM certificate into the Windows Trusted Root CA store.
    # Chrome on Windows uses the OS store, so once imported the browser
    # fully trusts the cert — service workers register without errors.
    param([string]$CertPem)
    try {
        $raw   = [System.IO.File]::ReadAllText($CertPem)
        $b64   = ($raw -replace '-----BEGIN CERTIFICATE-----','' `
                       -replace '-----END CERTIFICATE-----','' `
                       -replace '\s','')
        $bytes = [Convert]::FromBase64String($b64)
        $tmp   = [System.IO.Path]::GetTempFileName() + '.cer'
        [System.IO.File]::WriteAllBytes($tmp, $bytes)
        $imported = Import-Certificate -FilePath $tmp -CertStoreLocation Cert:\LocalMachine\Root -ErrorAction Stop
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        Write-Ok "Certificate trusted by Windows / Chrome (thumbprint: $($imported.Thumbprint.Substring(0,8))...)"
        return $true
    } catch {
        Write-Warn "Could not auto-import certificate: $_"
        Write-Warn "PWA SSL fix: install ssl\cert.pem manually as a Trusted Root CA"
        return $false
    }
}

function Setup-Ssl {
    param([string]$InstallDir)

    $SslDir  = Join-Path $InstallDir "ssl"
    $CertPem = Join-Path $SslDir "cert.pem"
    $KeyPem  = Join-Path $SslDir "key.pem"

    # Skip if a valid cert exists (> 30 days remaining)
    if ((Test-Path $CertPem) -and (Test-Path $KeyPem)) {
        try {
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertPem)
            if ($cert.NotAfter -gt (Get-Date).AddDays(30)) {
                Write-Ok "SSL certificate valid until $($cert.NotAfter.ToString('yyyy-MM-dd'))"
                Add-CertToTrustStore -CertPem $CertPem | Out-Null
                return $true
            }
            Write-Warn "SSL certificate expires $($cert.NotAfter.ToString('yyyy-MM-dd')) — regenerating"
        } catch {}
    }

    Write-Info "Setting up SSL / TLS certificate (self-signed)"
    Write-Info "For Let's Encrypt on Windows, see: https://github.com/win-acme/win-acme"

    $ok = New-SslCertPem -SslDir $SslDir
    if ($ok) {
        Add-CertToTrustStore -CertPem $CertPem | Out-Null
        New-SslRenewalTask -InstallDir $InstallDir
        return $true
    }
    return $false
}

# ── Final summary ─────────────────────────────────────────────────────────────

function Write-Done {
    param([bool]$HasSsl = $false)
    $scheme = if ($HasSsl) { "https" } else { "http" }
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "   Centralized — Installation Complete  " -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Install dir : $InstallDir"             -ForegroundColor White
    Write-Host "  App URL     : ${scheme}://127.0.0.1:$AppPort" -ForegroundColor White
    Write-Host "  Login       : admin / admin"            -ForegroundColor White
    Write-Host ""
    $task = Get-ScheduledTask -TaskName "Centralized" -ErrorAction SilentlyContinue
    if ($task) {
        Write-Host "  Task        : Centralized (starts at boot, runs in background)" -ForegroundColor Cyan
        Write-Host "  Stop        : Stop-ScheduledTask -TaskName Centralized"              -ForegroundColor Yellow
        Write-Host "  Disable     : Disable-ScheduledTask -TaskName Centralized"           -ForegroundColor Yellow
        Write-Host "  Logs        : $InstallDir\logs\service.log"                          -ForegroundColor Yellow
    } else {
        Write-Host "  Start the app (pick one):"             -ForegroundColor Cyan
        Write-Host "    $InstallDir\centralized.bat"         -ForegroundColor Yellow
        Write-Host "    $InstallDir\centralized.ps1  (PowerShell)" -ForegroundColor Yellow
    }
    if ($HasSsl) {
        Write-Host ""
        Write-Host "  NOTE: Self-signed certificate — browser will show a security warning." -ForegroundColor Yellow
        Write-Host "  Import $InstallDir\ssl\cert.pem into Windows trust store to suppress it." -ForegroundColor Yellow
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
    $hasSsl = Setup-Ssl -InstallDir $InstallDir

    # Open the app port in Windows Firewall so other devices can reach the site
    $FwRuleName = "Centralized HTTPS $AppPort"
    $existing   = Get-NetFirewallRule -DisplayName $FwRuleName -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-NetFirewallRule -DisplayName $FwRuleName `
            -Direction Inbound -Protocol TCP -LocalPort $AppPort `
            -Action Allow -Profile Any | Out-Null
        Write-Ok "Firewall rule added: allow inbound TCP $AppPort"
    } else {
        Write-Ok "Firewall rule already present: $FwRuleName"
    }

    Install-CentralizedTask

    Write-Done -HasSsl $hasSsl
}

Main
