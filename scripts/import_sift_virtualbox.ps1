# Import the SIFT OVA into VirtualBox and boot it.
# Prereqs: VirtualBox installed AND Intel VT-x / AMD-V enabled in BIOS.
# Run from the "Evil Hack" folder (the one holding sift-2026.03.24.ova).

$ErrorActionPreference = "Stop"
$vbox = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
$ova  = Join-Path (Get-Location) "sift-2026.03.24.ova"
$name = "SIFT-Workstation"

if (-not (Test-Path $vbox)) { throw "VBoxManage not found. Install VirtualBox first." }
if (-not (Test-Path $ova))  { throw "sift-2026.03.24.ova not found in $(Get-Location)." }

# Sanity: virtualization must be on or the 64-bit guest won't boot.
$vt = (Get-CimInstance Win32_Processor).VirtualizationFirmwareEnabled
if (-not $vt) { Write-Warning "Hardware virtualization appears DISABLED in BIOS. The VM will not boot until you enable Intel VT-x / AMD-V (SVM)." }

Write-Host "[*] Importing $ova (this takes a few minutes; expands to ~25-40 GB)..."
& $vbox import $ova --vsys 0 --vmname $name --memory 8192 --cpus 4

Write-Host "[*] Enabling clipboard + a shared folder for Glass Box..."
& $vbox modifyvm $name --clipboard bidirectional 2>$null
& $vbox sharedfolder add $name --name glassbox --hostpath (Resolve-Path "..\glassbox").Path --automount 2>$null

Write-Host "[*] Starting the SIFT VM..."
& $vbox startvm $name

Write-Host "[OK] Login: sansforensics / forensics"
Write-Host "     Inside SIFT, the shared folder mounts under /media/ (or run scripts/setup_sift.sh)."
