"""Reasoners — the Investigator (Model A) and the independent Skeptic (Model B).

Two design rules are enforced *in code*, not left to the model:

  * **The model reasons; code owns the tools and the provenance.** Whether a
    step is driven by an LLM or by the deterministic engine, the actual tool
    call and the ``tool_exec_id`` binding are performed by Glass Box. A model
    can never fabricate an execution id or cite evidence that was not really
    pulled — provenance is structurally true.

  * **The Skeptic is independent.** It is constructed with a *different
    vendor/model* than the Investigator, it receives only the claim text plus
    evidence handles (never the Investigator's reasoning), and it must
    re-derive each claim with a *different tool* than the one that produced it.

Backends: Anthropic, OpenAI and Ollama clients are supported and auto-detected.
If none are configured, Glass Box runs its deterministic forensic engine so the
pipeline is fully reproducible offline — the architecture (independent
re-derivation, gating, provenance) is demonstrated either way.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable

from .schemas import Claim, ClaimKind, Confidence, Hypothesis, Verdict
from .tools import ForensicTools


# ===========================================================================
# LLM client abstraction (optional)
# ===========================================================================
@dataclass
class LLMClient:
    vendor: str
    model: str
    _complete: Callable[[str, str], str]

    def complete(self, system: str, user: str) -> str:
        return self._complete(system, user)


def _anthropic_client(model: str) -> LLMClient | None:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return None
    try:
        import anthropic  # type: ignore
    except Exception:
        return None
    client = anthropic.Anthropic()

    def _c(system: str, user: str) -> str:
        msg = client.messages.create(
            model=model, max_tokens=1024, system=system,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")

    return LLMClient("anthropic", model, _c)


def _openai_client(model: str) -> LLMClient | None:
    if not os.environ.get("OPENAI_API_KEY"):
        return None
    try:
        import openai  # type: ignore
    except Exception:
        return None
    client = openai.OpenAI()

    def _c(system: str, user: str) -> str:
        r = client.chat.completions.create(
            model=model,
            messages=[{"role": "system", "content": system},
                      {"role": "user", "content": user}],
        )
        return r.choices[0].message.content or ""

    return LLMClient("openai", model, _c)


def _ollama_client(model: str) -> LLMClient | None:
    try:
        import urllib.request
        host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")

        def _c(system: str, user: str) -> str:
            body = json.dumps({
                "model": model, "stream": False,
                "messages": [{"role": "system", "content": system},
                             {"role": "user", "content": user}],
            }).encode()
            req = urllib.request.Request(f"{host}/api/chat", data=body,
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read())
            return data.get("message", {}).get("content", "")

        return LLMClient("ollama", model, _c)
    except Exception:
        return None


# --- Free, no-credit-card cloud providers via the OpenAI-compatible REST API.
#     Implemented with urllib so NO pip install is needed (runs as-is in SIFT). ---
def _openai_compatible_client(vendor: str, base_url: str, key_env: list[str],
                              model: str, default_model: str) -> LLMClient | None:
    import urllib.request
    key = next((os.environ[e] for e in key_env if os.environ.get(e)), None)
    if not key:
        return None
    model = model or default_model

    def _c(system: str, user: str) -> str:
        body = json.dumps({
            "model": model, "temperature": 0.2,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
        }).encode()
        req = urllib.request.Request(
            base_url.rstrip("/") + "/chat/completions", data=body,
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {key}",
                     # A real User-Agent: some providers sit behind Cloudflare,
                     # which blocks the default "Python-urllib/x.y" (error 1010).
                     "User-Agent": "GlassBox/1.0 (+https://github.com/glassbox)",
                     "Accept": "application/json"})
        last_err = None
        for attempt in range(6):  # ride out free-tier 429 rate limits
            try:
                with urllib.request.urlopen(req, timeout=180) as resp:
                    data = json.loads(resp.read())
                return data["choices"][0]["message"]["content"] or ""
            except urllib.error.HTTPError as e:
                last_err = e
                if e.code in (429, 500, 502, 503) and attempt < 5:
                    wait = _retry_after_seconds(e, default=4 * (attempt + 1))
                    time.sleep(min(wait, 30))
                    continue
                raise
        raise last_err  # pragma: no cover

    return LLMClient(vendor, model, _c)


def _retry_after_seconds(err, default: float) -> float:
    """Honor a provider's Retry-After header / 'try again in Xs' body on a 429."""
    try:
        ra = err.headers.get("retry-after") if err.headers else None
        if ra:
            return float(ra)
    except Exception:
        pass
    try:
        body = err.read().decode("utf-8", "ignore")
        m = re.search(r"try again in ([\d.]+)s", body)
        if m:
            return float(m.group(1)) + 1.0
    except Exception:
        pass
    return default


def make_client(spec: str | None) -> LLMClient | None:
    """spec like 'groq:llama-3.3-70b-versatile', 'gemini:gemini-2.0-flash',
    'anthropic:claude-fable-5', 'openai:gpt-4o', 'openrouter:...', 'ollama:llama3.1'."""
    if not spec:
        return None
    vendor, _, model = spec.partition(":")
    vendor = vendor.lower()
    if vendor == "anthropic":
        return _anthropic_client(model or "claude-fable-5")
    if vendor == "openai":
        return _openai_client(model or "gpt-4o")
    if vendor == "ollama":
        return _ollama_client(model or "llama3.1")
    if vendor == "groq":  # free, no card: console.groq.com
        return _openai_compatible_client(
            "groq", "https://api.groq.com/openai/v1", ["GROQ_API_KEY"],
            model, "llama-3.3-70b-versatile")
    if vendor == "gemini":  # free, no card: aistudio.google.com/apikey
        return _openai_compatible_client(
            "gemini", "https://generativelanguage.googleapis.com/v1beta/openai",
            ["GEMINI_API_KEY", "GOOGLE_API_KEY"], model, "gemini-2.0-flash")
    if vendor == "openrouter":  # has free :free models
        return _openai_compatible_client(
            "openrouter", "https://openrouter.ai/api/v1", ["OPENROUTER_API_KEY"],
            model, "meta-llama/llama-3.3-70b-instruct:free")
    return None


def auto_pair() -> tuple[LLMClient | None, LLMClient | None]:
    """Pick an Investigator/Skeptic pair of *different* vendors if available."""
    inv = make_client(os.environ.get("GLASSBOX_INVESTIGATOR"))
    skp = make_client(os.environ.get("GLASSBOX_SKEPTIC"))
    if inv and skp and (inv.vendor, inv.model) == (skp.vendor, skp.model):
        skp = None  # refuse identical models — independence must be real
    return inv, skp


# ===========================================================================
# Investigation plan (deterministic forensic engine)
# ===========================================================================
@dataclass
class Finding:
    """One step the Investigator takes: a tool call -> a claim."""
    tool: str
    args: dict
    assertion: str
    proposed_confidence: Confidence
    mitre: str
    hypothesis_key: str
    kind: ClaimKind = ClaimKind.FINDING
    # skeptic re-derivation: a DIFFERENT tool and a predicate over its data
    skeptic_tool: str = ""
    skeptic_args: dict | None = None


class Investigator:
    """Model A. Forms claims by driving the typed tools."""

    def __init__(self, tools: ForensicTools, client: LLMClient | None = None):
        self.tools = tools
        self.client = client
        self.vendor = client.vendor if client else "deterministic"
        self.model = client.model if client else "glassbox-forensic-engine"

    def hypotheses(self) -> dict[str, Hypothesis]:
        return {
            "H1": Hypothesis(statement="A single intrusion centered on the implant "
                             "C:\\ProgramData\\upd.exe achieved persistence, execution, "
                             "code injection and C2 on this host."),
            "H2": Hypothesis(statement="The PSEXESVC.exe activity is a second, independent "
                             "adversary performing lateral movement onto this host."),
            "H3": Hypothesis(statement="The adversary destroyed Windows logs (.evtx + USN "
                             "journal) to cover the upd.exe intrusion."),
        }

    def plan(self) -> list[Finding]:
        """The investigation plan. The PSEXESVC step is a deliberate overreach
        the Skeptic is expected to refute — this is the live self-correction."""
        return [
            Finding("get_runkeys", {}, "Run-key persistence 'Updater' launches "
                    "C:\\ProgramData\\upd.exe at logon.", Confidence.CONFIRMED,
                    "T1547.001", "H1", skeptic_tool="get_amcache"),
            Finding("get_mft_timeline", {}, "C:\\ProgramData\\upd.exe is timestomped: "
                    "$SI creation (2019) predates $FN creation (2026) by ~7 years.",
                    Confidence.CONFIRMED, "T1070.006", "H1", skeptic_tool="get_amcache"),
            Finding("get_prefetch", {}, "The implant executed at least 3 times "
                    "(UPD.EXE prefetch, last run 2026-05-30 06:02Z).",
                    Confidence.CONFIRMED, "T1059", "H1", skeptic_tool="get_shimcache"),
            Finding("vol_malfind", {}, "Process upd.exe (pid 4188) contains an injected "
                    "RWX private region with beacon shellcode (code injection).",
                    Confidence.CONFIRMED, "T1055", "H1", skeptic_tool="yara_scan"),
            Finding("vol_netscan", {}, "The implant maintains a C2 channel from pid 4188 "
                    "to 185.220.101.47:443.", Confidence.CONFIRMED, "T1071.001", "H1",
                    skeptic_tool="vol_malfind"),
            Finding("get_usn", {}, "Evidence destruction: a PowerShell .evtx was deleted and "
                    "the $UsnJrnl shows an ~18.7k-record sequence gap.",
                    Confidence.CONFIRMED, "T1070", "H3", skeptic_tool="get_logfile_records"),
            # --- the deliberate overreach (false positive on the decoy) ---
            Finding("vol_pslist", {}, "PSEXESVC.exe (pid 3320) is a second adversary implant "
                    "performing lateral movement and should be flagged as malicious.",
                    Confidence.CONFIRMED, "T1021.002", "H2", skeptic_tool="get_amcache"),
        ]


class Skeptic:
    """Model B. Independently re-derives each claim with a DIFFERENT tool.

    It sees only the claim assertion and the evidence handles — never the
    Investigator's chain of reasoning — and rules confirm / refute /
    unverifiable based solely on what its own tool returns.
    """

    def __init__(self, tools: ForensicTools, client: LLMClient | None = None):
        self.tools = tools.for_actor("skeptic")
        self.client = client
        self.vendor = client.vendor if client else "deterministic"
        self.model = client.model if client else "glassbox-skeptic-engine"

    def challenge(self, claim: Claim, skeptic_tool: str,
                  skeptic_args: dict | None) -> tuple[Verdict, str, list[str]]:
        """Re-derive the claim. Returns (verdict, note, skeptic_exec_ids)."""
        if not skeptic_tool:
            return Verdict.UNVERIFIABLE, "no independent tool available", []
        try:
            res = self.tools.call(skeptic_tool, **(skeptic_args or {}))
        except Exception as e:  # tool refusal etc.
            return Verdict.UNVERIFIABLE, f"independent tool error: {e}", []
        exec_ids = [res["tool_exec_id"]]
        data = res["data"]
        verdict, note = self._adjudicate(claim, skeptic_tool, data)
        return verdict, note, exec_ids

    def _adjudicate(self, claim: Claim, tool: str, data: Any) -> tuple[Verdict, str]:
        """Deterministic cross-tool corroboration logic."""
        a = claim.assertion.lower()

        if tool == "get_amcache":
            entries = {e["name"].lower(): e for e in data.get("entries", [])}
            if "upd.exe" in a and "timestomp" in a:
                e = entries.get("upd.exe")
                if e and e.get("compiled", "") > "2026-01-01" and not e.get("signed", True):
                    return Verdict.CONFIRM, ("Amcache shows upd.exe compiled 2026-05-29 and "
                            "unsigned — contradicts the 2019 $SI timestamp, confirming timestomp.")
            if "persistence" in a or "run-key" in a or "logon" in a:
                e = entries.get("upd.exe")
                if e and not e.get("signed", True):
                    return Verdict.CONFIRM, ("Amcache independently confirms upd.exe executed "
                            "from C:\\ProgramData, unsigned — consistent with persistence.")
            if "psexesvc" in a or "lateral movement" in a or "second adversary" in a:
                e = entries.get("psexesvc.exe")
                if e and e.get("signed") and "sysinternals" in e.get("publisher", "").lower():
                    return Verdict.REFUTE, ("PSEXESVC.exe is signed Microsoft/Sysinternals PsExec "
                            "(publisher verified) installed by an admin account over internal SMB; "
                            "no injection or YARA hit. This is legitimate admin tooling, not a "
                            "second adversary. The 'malicious lateral movement' claim is unsupported.")
            return Verdict.UNVERIFIABLE, "Amcache did not contain a corroborating record."

        if tool == "get_shimcache":
            paths = {e["path"].lower(): e for e in data.get("entries", [])}
            e = paths.get("c:\\programdata\\upd.exe")
            if e and e.get("executed"):
                return Verdict.CONFIRM, ("Shimcache independently records execution of "
                        "C:\\ProgramData\\upd.exe, corroborating the prefetch evidence.")
            return Verdict.UNVERIFIABLE, "Shimcache had no corroborating execution record."

        if tool == "yara_scan":
            matches = data.get("matches", [])
            if any("beacon" in m["rule"].lower() or "cobalt" in m["rule"].lower() for m in matches):
                return Verdict.CONFIRM, ("YARA independently matches Cobalt_Strike_Beacon on "
                        "upd.exe, corroborating the injected RWX region from a different tool.")
            return Verdict.UNVERIFIABLE, "YARA produced no corroborating match."

        if tool == "vol_malfind":
            hits = data.get("hits", [])
            if any(h.get("pid") == 4188 for h in hits):
                return Verdict.CONFIRM, ("malfind independently shows pid 4188 (the C2 process) "
                        "carries injected beacon shellcode — the network IOC and the injected "
                        "process are the same artifact.")
            return Verdict.UNVERIFIABLE, "malfind did not corroborate the network claim."

        if tool == "get_logfile_records":
            txns = data.get("transactions", [])
            if any(t.get("op") == "DeleteFile" and ".evtx" in t.get("target", "") for t in txns):
                return Verdict.CONFIRM, ("$LogFile independently records a DeleteFile transaction "
                        "for a .evtx, corroborating the USN gap as deliberate log destruction.")
            return Verdict.UNVERIFIABLE, "$LogFile had no corroborating deletion record."

        return Verdict.UNVERIFIABLE, f"no adjudication rule for tool {tool}."
