# Devpost write-up — Glass Box

## Inspiration
DFIR triage is being handed to AI agents, but an agent that can hallucinate a
finding, obey a planted instruction, or quietly modify evidence is worse than no
agent at all — it produces confident, unprovable, inadmissible conclusions. We
wanted an agent whose output you could put on a witness stand: one where trust
is a property of the *architecture*, not of a well-worded prompt.

## What it does
Glass Box triages a Windows disk + memory case and produces a report in which
**every sentence clicks through to the exact tool execution, artifact offset and
SHA-256 that produced it.** It cannot spoil evidence (its tool surface has no
write or shell primitive), it binds every finding to a real execution (unbound
claims auto-demote to "inference"), and an **independent Skeptic of a different
vendor re-derives every claim with a different tool** before it ships. It also
detects prompt injection planted in the evidence, quarantines it, and reports it
as an adversarial IOC.

## How we built it
- **Typed read-only tool surface** (`tools.py`, exposed over MCP): 14 forensic
  tools wrapping SIFT CLIs (Volatility 3, MFTECmd, RegRipper, YARA, …), each
  returning a parsed summary + provenance envelope. No `execute_shell`, no
  write/delete tool *exists*.
- **ClaimChain ledger** (`claimchain.py`): append-only hash-chained JSONL — the
  audit trail and the substrate for click-through provenance; tamper-evident.
- **Dual-model Investigator/Skeptic** (`llm.py`): Anthropic / OpenAI / Ollama
  backends, with a deterministic forensic engine so the demo is reproducible
  offline. The model reasons; code always owns the tool calls and provenance.
- **The gate** (`gate.py`): a hallucination firewall — unbound or skeptic-refuted
  claims can never reach "confirmed," regardless of what the model said.
- **Evidence sealing + canaries + integrity certificate** (`evidence.py`).
- **PromptArmor** (`promptarmor.py`): injection detection + quarantine, with a
  test corpus at full recall / zero false positives.
- **Glass Report** (`report.py`): one self-contained click-through HTML file.

## Challenges we ran into
- Isolating the Skeptic's context so it genuinely re-derives rather than echoes
  the Investigator — solved by giving it only claim text + evidence handles and
  forcing a *different* tool (asserted in the end-to-end test).
- Parsing messy forensic output into short summaries without overflowing context
  or smuggling injection — solved by returning parsed envelopes, never raw dumps.
- Making self-correction reliable on camera — solved by engineering a documented
  decoy that the Skeptic refutes deterministically.

## What we learned
Architectural guardrails beat prompt guardrails: a capability that doesn't exist
can't be misused. Contradiction is signal — a second model with a second tool
catches what one model rationalizes. And failure modes are data: we document
ours rather than hide them.

## What's next
More tools and OS coverage, multi-host correlation, cloud evidence, AI-operator
fingerprinting, and calibration tracking over many cases.

## Differentiators (call these out)
Spoliation impossible by construction · provenance gates findings · cross-vendor
adversarial verification · hostile-evidence defense · self-attested integrity
certificate · court-grade by design.
