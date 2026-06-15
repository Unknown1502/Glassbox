# Running Glass Box on the SIFT Workstation

Glass Box runs **anywhere** with Python 3.10+ using bundled fixtures — you do
**not** need the SIFT VM to demo it. SIFT is only needed to run the live
forensic CLIs against a real image. This doc covers both: importing the
`sift-2026.03.24.ova` appliance, and wiring Glass Box to the live tools.

## 1. Import the SIFT appliance

The download is an OVA (Open Virtual Appliance) — a portable VM you import into
a hypervisor. It is **not** an executable; you boot it, you don't "run" it.

### VirtualBox (free)
```powershell
# Install VirtualBox first: https://www.virtualbox.org/wiki/Downloads
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" import "sift-2026.03.24.ova" `
    --vsys 0 --memory 8192 --cpus 4
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" startvm "SIFT-Workstation"
```
Or just: VirtualBox GUI → **File → Import Appliance** → pick the `.ova` → give it
≥8 GB RAM and ≥4 CPUs → **Import** → **Start**.

### VMware Workstation/Player
**File → Open** → select `sift-2026.03.24.ova` → accept → **Power On**.
(`vmrun start "SIFT-Workstation.vmx"` from CLI once imported.)

Default SIFT credentials: user `sansforensics`, password `forensics`.

> Tip: the OVA is ~9.3 GB; import needs ~25 GB free disk. Enable VT-x/AMD-V in
> BIOS if the VM won't boot.

## 2. Confirm the forensic CLIs

Inside the booted SIFT VM:
```bash
which vol.py analyzeMFT MFTECmd regripper yara evtx_dump.py
vol.py --info | head        # Volatility 3
```
Note which exist — feed those exact names to Glass Box if they differ from the
defaults in `glassbox/tools.py::WHITELISTED_BINARIES`.

## 3. Get Glass Box onto SIFT
```bash
git clone <your-repo-url> glassbox && cd glassbox
python3 run.py            # runs the bundled reference case immediately (fixtures)
```
No pip install needed for the demo. For live LLMs: `pip install anthropic openai`
and export the keys (see README).

## 4. Point it at a real image
```bash
python3 run.py --evidence /cases/WIN11-FIN-07/disk.raw
```
When a whitelisted binary is on `PATH` and a real image is supplied, each tool
shells out **read-only** (`shell=False`, validated args, binary whitelist). To
turn parsed CLI output into the tool's structured contract, implement the
per-tool parser in `ForensicTools._parse_real_cli` (it raises by default so the
demo always falls back to fixtures). Each parser maps the CLI's stdout to the
same JSON shape as the matching file in `cases/case01/fixtures/`.

### Optional: enforce the OS-level read-only mount
On SIFT, opt into the loopback `ro,noexec,nodev,nosuid` non-root mount:
```bash
export GLASSBOX_DO_MOUNT=1
```
Without it, integrity is still enforced cryptographically (pre/post SHA-256 +
canaries + the write-free tool surface); the certificate states exactly which
guarantees were in force, never overclaiming.

## 5. Attach an external MCP client (optional)
```bash
python3 -m glassbox.mcp_server --case cases/case01   # needs `pip install mcp`
python3 -m glassbox.mcp_server --list                # inspect the surface, no deps
```
The client sees only the 14 typed read-only tools — there is no shell/write tool
to expose.
