# Demo Script (5:00) — mapped to judging criteria

Record a live terminal + the HTML report. Total 5:00. Buffer included.

**0:00–0:30 — The stakes.**
"Adversaries reach domain control in minutes. Here's a naive agent triaging this
host — and hallucinating a finding / obeying a planted instruction." (baseline
clip captured on the SIFT box.)

**0:30–1:15 — Seal (Criterion 4).**
Run `python run.py`. Narrate the `[seal]` line: evidence hashed, canaries seeded.
"The agent has **no write tool**." Live-prove it:
```bash
make surface     # write_tools: []   shell_tools: []
python -c "from glassbox.tools import ForensicTools; from glassbox.claimchain import ClaimChain; \
ForensicTools('cases/case01', ClaimChain('out/x.jsonl')).call('execute_shell', cmd='whoami')"
# -> ToolError: no such tool: 'execute_shell'
```

**1:15–2:45 — Investigate + self-correct (Criteria 1 & 2 — the tiebreaker).**
Watch the `[claim]/[skept]` pairs scroll. The Investigator claims `PSEXESVC.exe`
is a second-adversary implant. The Skeptic re-derives with a **different tool**,
finds it's signed Sysinternals PsExec installed by an admin, and **REFUTES**.
`[adjud] hypothesis killed`. `[gate] demoted: confirmed → inference`. A hypothesis
dies on screen; the false positive is caught — automatically.

**2:45–3:30 — Hostile evidence (the wow).**
`[armor] prompt injection detected in evidence — reported as adversarial IOC`.
"A naive agent obeyed this (clip). Glass Box quarantines it as inert data and
**reports it** — the evidence tried to manipulate the analyst, and that itself
is a finding."

**3:30–4:15 — Provenance (Criterion 5).**
Open `out/report.html`. Click any finding → the exact tool, args, output
excerpt, artifact offset, and SHA-256 expand inline, plus the Skeptic's
independent re-derivation. Click the demoted PsExec line → "inference —
unverified," with the refutation shown.

**4:15–4:45 — Proof (Criteria 2 & 3).**
The accuracy cards: **recall 1.0, precision 1.0, 0 hallucinations, 0 decoy
flags.** Scroll to the integrity certificate: objects + canaries intact, ledger
chain intact, self-signature shown. "Pre and post hashes match — provably no
spoliation."

**4:45–5:00 — Close.**
"Architectural guarantees, not prompts. Every claim provable. Hostile evidence
detected. The analyst you can put on the witness stand."

---

### One-liners to keep on a card
- "There is no shell tool to call. Not blocked — *nonexistent*."
- "Confirmed = bound to evidence **and** confirmed by a different model with a
  different tool. Everything else is visibly an inference."
- "The ledger is hash-chained — flip one byte and we tell you which line."
