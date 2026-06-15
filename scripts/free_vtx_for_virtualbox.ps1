# Free Intel VT-x from Hyper-V so VirtualBox runs natively (not "snail" NEM mode).
# RIGHT-CLICK this file -> "Run with PowerShell" AS ADMINISTRATOR, or run the
# commands below in an elevated PowerShell. A reboot is required afterward.
#
# Reversible: to restore Hyper-V/WSL2/Docker later, run
#   bcdedit /set hypervisorlaunchtype auto
# and re-enable any features you turned off.

$ErrorActionPreference = "Continue"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Host "[!] Not elevated. Re-launching as administrator..." -ForegroundColor Yellow
    Start-Process powershell -Verb RunAs -ArgumentList "-NoExit","-ExecutionPolicy","Bypass","-File","`"$PSCommandPath`""
    exit
}

Write-Host "[*] Stopping the Hyper-V hypervisor from launching at boot..." -ForegroundColor Cyan
bcdedit /set hypervisorlaunchtype off

Write-Host "[*] Disabling the Hyper-V optional features that grab VT-x..." -ForegroundColor Cyan
# These power WSL2 and Docker Desktop; disabling them is what frees VT-x for
# VirtualBox. They are easy to turn back on later. Errors are non-fatal.
foreach ($f in "Microsoft-Hyper-V-All","VirtualMachinePlatform","HypervisorPlatform","Windows-Defender-ApplicationGuard") {
    try { Disable-WindowsOptionalFeature -Online -FeatureName $f -NoRestart -ErrorAction Stop | Out-Null; Write-Host "    disabled $f" }
    catch { Write-Host "    (skip $f - not present)" -ForegroundColor DarkGray }
}

Write-Host ""
Write-Host "[i] Also turn OFF Memory Integrity if it's on:" -ForegroundColor Yellow
Write-Host "    Windows Security > Device security > Core isolation > Memory integrity = Off"
Write-Host ""
Write-Host "[OK] Done. REBOOT now, then start the SIFT VM again." -ForegroundColor Green
Write-Host "     Note: WSL2 / Docker Desktop will be off until you re-enable the above."
