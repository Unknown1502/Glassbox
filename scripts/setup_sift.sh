#!/usr/bin/env bash
# Bootstrap Glass Box on the SANS SIFT Workstation.
# Run INSIDE the booted SIFT VM (user: sansforensics).
#
#   curl -fsSL <raw-url>/scripts/setup_sift.sh | bash       # or just run it locally
#
set -euo pipefail

echo "[*] Glass Box — SIFT bootstrap"

# 1. Python check (SIFT ships Python 3).
python3 --version || { echo "Python 3 required"; exit 1; }

# 2. Probe the SIFT forensic CLIs Glass Box can drive live.
echo "[*] Probing SIFT forensic tools on PATH:"
for bin in vol.py vol volatility3 analyzeMFT.py MFTECmd regripper rip.pl yara \
           evtx_dump.py AmcacheParser PECmd; do
  if command -v "$bin" >/dev/null 2>&1; then
    printf "    [found] %-16s %s\n" "$bin" "$(command -v "$bin")"
  fi
done
echo "    (missing tools just mean Glass Box uses the bundled fixture for that artifact)"

# 3. Optional: install Protocol SIFT alongside, for the baseline comparison clip.
if [[ "${INSTALL_PROTOCOL_SIFT:-0}" == "1" ]]; then
  echo "[*] Installing Protocol SIFT (baseline) ..."
  curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash
fi

# 4. Smoke-test Glass Box on the bundled reference case (uses fixtures).
echo "[*] Running Glass Box reference case ..."
python3 run.py

# 5. Show how to point it at a real image.
cat <<'EOF'

[✓] Glass Box is ready on SIFT.

Run against a real acquisition (drives vol.py / analyzeMFT / regripper / yara live):

    python3 run.py --evidence /cases/<host>/memory.raw
    GLASSBOX_YARA_RULES=/opt/yara-rules/index.yar python3 run.py --evidence /cases/<host>/disk.raw

Inspect the typed read-only tool surface exposed to the agent (0 write/shell tools):

    python3 -m glassbox.mcp_server --list

Outputs land in out/: report.html, ledger.jsonl, integrity_certificate.json, accuracy.json
EOF
