"""Live SIFT Workstation CLI adapters.

On the SIFT box, Glass Box drives the real forensic tools instead of fixtures.
Each adapter (a) builds a **read-only** argv for the actual SIFT binary, runs it
via the whitelisted, ``shell=False`` runner in ``tools.py``, and (b) parses the
output into the *same JSON shape* the fixtures use — so the orchestrator,
Skeptic, gate, report and scorer are identical whether data came from a fixture
or from a live Volatility 3 / analyzeMFT / RegRipper / YARA run.

Everything here is best-effort and defensive: if a binary, image layout or
output format doesn't match, the adapter raises and ``tools.py`` falls back to
the case fixture, so a run never dies on a parsing edge case. The adapters that
emit deterministic machine output (Volatility 3 ``-r json``) are the most
robust; the text-parsing disk adapters are documented integration points.

These map to the SIFT tool library exactly as the FIND EVIL! brief asks:
typed functions like ``get_amcache()`` / ``vol_pslist()`` over a custom MCP
server, never a generic shell.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import os
import re
from typing import Any, Callable

# Each adapter: (binary_argv_builder, parser). The runner is passed in so all
# subprocess execution stays in tools.py behind the whitelist + arg validation.
RunFn = Callable[[list[str]], str]


def _is_private(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).is_private
    except ValueError:
        return True  # hostnames / malformed -> treat as internal, don't over-flag


# ---------------------------------------------------------------------------
# Volatility 3 (deterministic JSON via `-r json`) — the most robust adapters.
# ---------------------------------------------------------------------------
def _vol_json(run: RunFn, vol_bin: str, mem: str, plugin: str) -> list[dict]:
    out = run([vol_bin, "-q", "-r", "json", "-f", mem, plugin])
    data = json.loads(out)
    # vol3 json is a list of row dicts; tolerate {"rows":[...]} shapes too.
    if isinstance(data, dict):
        data = data.get("rows") or data.get("data") or []
    return data if isinstance(data, list) else []


def vol_pslist(run: RunFn, vol_bin: str, mem: str, args: dict) -> dict:
    rows = _vol_json(run, vol_bin, mem, "windows.pslist")
    procs = []
    for r in rows:
        name = r.get("ImageFileName") or r.get("Name") or ""
        procs.append({
            "pid": r.get("PID"), "ppid": r.get("PPID"), "name": name,
            "path": name, "create_time": str(r.get("CreateTime", "")),
            "suspicious": False, "reason": "",
        })
    return {"source": "windows.pslist (live)", "processes": procs}


def vol_malfind(run: RunFn, vol_bin: str, mem: str, args: dict) -> dict:
    rows = _vol_json(run, vol_bin, mem, "windows.malfind")
    hits = []
    for r in rows:
        prot = r.get("Protection", "")
        hits.append({
            "pid": r.get("PID"), "process": r.get("Process", ""),
            "vad_start": str(r.get("Start VPN", r.get("Start", ""))),
            "vad_end": str(r.get("End VPN", r.get("End", ""))),
            "protection": prot,
            "disasm_head": (r.get("Disasm") or "")[:80],
            "indicators": (["RWX private memory"] if "EXECUTE_READWRITE" in prot else []),
        })
    return {"source": "windows.malfind (live)", "hits": hits}


def vol_netscan(run: RunFn, vol_bin: str, mem: str, args: dict) -> dict:
    rows = _vol_json(run, vol_bin, mem, "windows.netscan")
    conns = []
    for r in rows:
        faddr = str(r.get("ForeignAddr", ""))
        fport = r.get("ForeignPort", "")
        conns.append({
            "pid": r.get("PID"), "proc": r.get("Owner", ""),
            "proto": r.get("Proto", ""),
            "local_addr": f"{r.get('LocalAddr','')}:{r.get('LocalPort','')}",
            "foreign_addr": f"{faddr}:{fport}",
            "state": r.get("State", ""),
            "suspicious": bool(faddr) and not _is_private(faddr),
            "reason": "external endpoint" if faddr and not _is_private(faddr) else "",
        })
    return {"source": "windows.netscan (live)", "connections": conns}


def vol_cmdline(run: RunFn, vol_bin: str, mem: str, args: dict) -> dict:
    rows = _vol_json(run, vol_bin, mem, "windows.cmdline")
    cmds = [{"pid": r.get("PID"), "name": r.get("Process", ""),
             "cmdline": r.get("Args", "")} for r in rows]
    return {"source": "windows.cmdline (live)", "cmdlines": cmds}


# ---------------------------------------------------------------------------
# Disk artifacts (text/CSV parsers — documented integration points on SIFT).
# ---------------------------------------------------------------------------
def yara_scan(run: RunFn, yara_bin: str, target: str, args: dict) -> dict:
    # `yara <rules> <target>` -> lines "RuleName /path/to/target"
    ruleset = args.get("ruleset") or os.environ.get("GLASSBOX_YARA_RULES", "")
    if not ruleset:
        raise RuntimeError("no YARA ruleset configured (set GLASSBOX_YARA_RULES)")
    out = run([yara_bin, "-r", ruleset, target])
    matches = []
    for line in out.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            matches.append({"rule": parts[0], "target": parts[1],
                            "strings_hit": [], "severity": "high"})
    return {"ruleset": ruleset, "matches": matches}


def get_runkeys(run: RunFn, rip_bin: str, hive: str, args: dict) -> dict:
    # RegRipper: `rip.pl -r SOFTWARE -p run`
    out = run([rip_bin, "-r", hive, "-p", "run"])
    keys = []
    for m in re.finditer(r"^\s*(.+?)\s*->\s*(.+?)\s*$", out, re.MULTILINE):
        name, value = m.group(1).strip(), m.group(2).strip()
        susp = bool(re.search(r"\\(programdata|temp|appdata|public)\\|\.tmp\b", value, re.I))
        keys.append({"name": name, "value": value,
                     "registry_path": f"HKLM\\{hive}\\...\\Run\\{name}",
                     "suspicious": susp, "reason": "non-standard path" if susp else ""})
    return {"hive": hive, "runkeys": keys}


def get_mft_timeline(run: RunFn, mft_bin: str, mft_path: str, args: dict) -> dict:
    # analyzeMFT.py -f $MFT -c out.csv  (CSV with $SI/$FN columns)
    csv_out = run([mft_bin, "-f", mft_path, "--csv", "-"]) if "MFTECmd" in mft_bin \
        else run([mft_bin, "-f", mft_path, "-c", "/dev/stdout"])
    records = []
    reader = csv.DictReader(io.StringIO(csv_out))
    for row in reader:
        si = row.get("SI Creation") or row.get("Created0x10") or ""
        fn = row.get("FN Creation") or row.get("Created0x30") or ""
        path = row.get("Filename") or row.get("FileName") or ""
        timestomped = bool(si and fn and si[:4].isdigit() and fn[:4].isdigit() and si < fn)
        records.append({"path": path, "mft_record": row.get("Record Number", ""),
                        "si_created": si, "fn_created": fn, "timestomped": timestomped,
                        "reason": "$SI precedes $FN" if timestomped else ""})
    return {"source": "$MFT (live)", "records": records}


# Adapter registry: tool_name -> (binary_kind, callable)
# binary_kind selects which whitelisted binary in tools.py to resolve.
_ADAPTERS: dict[str, Callable[..., dict]] = {
    "vol_pslist": vol_pslist,
    "vol_malfind": vol_malfind,
    "vol_netscan": vol_netscan,
    "vol_cmdline": vol_cmdline,
    "yara_scan": yara_scan,
    "get_runkeys": get_runkeys,
    "get_mft_timeline": get_mft_timeline,
}


def supported() -> list[str]:
    return sorted(_ADAPTERS)


def parse_live(tool_name: str, cli_path: str, evidence_path: str,
               args: dict, run: RunFn) -> dict:
    """Dispatch to a live adapter. Raises if unsupported/parse fails so the
    caller falls back to the fixture."""
    fn = _ADAPTERS.get(tool_name)
    if fn is None:
        raise NotImplementedError(f"no live SIFT adapter for {tool_name}")
    # Memory tools take the image directly; disk/registry tools take the path arg
    # (an extracted artifact / hive) or the evidence path as a sane default.
    if tool_name.startswith("vol_"):
        target = evidence_path
    else:
        target = args.get("path") or args.get("ruleset") or evidence_path
    return fn(run, cli_path, target, args)
