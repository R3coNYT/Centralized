#Requires -Version 5.1
<#
.SYNOPSIS
    Centralized - Windows Uninstaller
.DESCRIPTION
    Stops and removes the Centralized scheduled task, then deletes the
    install directory (C:\Tools\Centralized) after an optional data backup.
.PARAMETER KeepData
    Skip deletion of centralized.db and uploads/ (keep your audit data).
.PARAMETER Force
    Skip the confirmation prompt.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File uninstall.ps1
    powershell -ExecutionPolicy Bypass -File uninstall.ps1 -KeepData -Force
#>
param(
    [switch]$KeepData,
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"

$TaskName   = "Centralized"
$InstallDir = "C:\Tools\Centralized"

# -- Helpers ------------------------------------------------------------------

function Write-Info($msg) { Write-Host "[+] $msg" -ForegroundColor Cyan   }
function Write-Ok($msg)   { Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Err($msg)  { Write-Host "[x] $msg" -ForegroundColor Red   }

# -- Admin check --------------------------------------------------------------

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator
)
if (-not $isAdmin) {
    Write-Err "This script must be run as Administrator."
    Write-Err "Right-click PowerShell > 'Run as administrator', then try again."
    exit 1
}

# -- Banner -------------------------------------------------------------------

Write-Host ""
Write-Host "========================================" -ForegroundColor Red
Write-Host "   Centralized - Uninstall              " -ForegroundColor Red
Write-Host "========================================" -ForegroundColor Red
Write-Host ""
Write-Host "  Directory  : $InstallDir" -ForegroundColor White
Write-Host "  Task       : $TaskName"  -ForegroundColor White
if ($KeepData) {
    Write-Host "  Mode       : keep data (db + uploads)" -ForegroundColor Cyan
} else {
    Write-Host "  Mode       : full removal" -ForegroundColor Yellow
}
Write-Host ""

# -- Confirmation -------------------------------------------------------------

if (-not $Force) {
    $answer = Read-Host "Confirm uninstall? [y/N]"
    if ($answer -notin @("y", "Y", "yes")) {
        Write-Warn "Cancelled."
        exit 0
    }
}

# -- 1. Stop and remove scheduled task ----------------------------------------

Write-Info "Removing scheduled task '$TaskName'..."
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($task) {
    if ($task.State -eq "Running") {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        Write-Ok "Task stopped"
    }
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Ok "Scheduled task removed"
} else {
    Write-Warn "Task '$TaskName' not found (already removed?)"
}

# -- 2. Remove install directory ----------------------------------------------

if (-not (Test-Path $InstallDir)) {
    Write-Warn "Directory '$InstallDir' not found (already removed?)"
} else {
    if ($KeepData) {
        # Remove everything except db and uploads
        Write-Info "Removing files (keeping db + uploads)..."
        Get-ChildItem $InstallDir -Force | Where-Object {
            $_.Name -notin @("centralized.db", "uploads", "backups")
        } | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Write-Ok "Files removed - data kept in $InstallDir"
    } else {
        Write-Info "Removing $InstallDir..."
        Remove-Item $InstallDir -Recurse -Force
        Write-Ok "Directory removed"

        # Remove C:\Tools if empty
        if ((Test-Path "C:\Tools") -and -not (Get-ChildItem "C:\Tools" -Force -ErrorAction SilentlyContinue)) {
            Remove-Item "C:\Tools" -Force -ErrorAction SilentlyContinue
            Write-Ok "C:\Tools removed (was empty)"
        }
    }
}

# -- 3. Clean up user PATH ----------------------------------------------------

Write-Info "Cleaning user PATH..."
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -like "*C:\Tools\Centralized*") {
    $cleaned = ($userPath -split ";" | Where-Object { $_ -ne "C:\Tools\Centralized" }) -join ";"
    [Environment]::SetEnvironmentVariable("Path", $cleaned, "User")
    Write-Ok "PATH cleaned"
} else {
    Write-Ok "PATH already clean"
}

# -- Summary ------------------------------------------------------------------

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "   Centralized - Uninstalled            " -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
if ($KeepData) {
    Write-Host "  Data kept in: $InstallDir" -ForegroundColor Cyan
}
Write-Host ""