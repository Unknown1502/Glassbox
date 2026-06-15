# Reference run — committed agent execution logs

These are the verbatim artifacts of one Glass Box run on `cases/case01`, committed
so judges can inspect the **agent execution logs and provenance without running
anything** (FIND EVIL! deliverable #8). Regenerate them any time with
`python3 run.py`.

| File | What it is |
|---|---|
| [`ledger.jsonl`](ledger.jsonl) | The hash-chained, append-only execution log — every tool execution, claim, skeptic verdict, gate decision, and the integrity certificate, in causal order. **Trace any finding here:** each `claim` record lists `supporting_exec_ids`, and each `exec` record has the `tool_exec_id`, `artifact_offset`, and `stdout_sha256` that produced it. |
| [`report.html`](report.html) | The self-contained Glass Report — open in a browser; every finding clicks through to its evidence. Demoted claims render as "inference — unverified." |
| [`integrity_certificate.json`](integrity_certificate.json) | Pre/post SHA-256 of every evidence object + canary attestation + ledger-chain status, self-signed. `overall_ok: true` = no spoliation. |
| [`accuracy.json`](accuracy.json) | Measured recall / precision / hallucinations / decoy-flags vs the ground-truth manifest. |

**How to trace a finding to its execution (example):**
1. Open `ledger.jsonl`, find a `"kind":"claim"` line — note its `supporting_exec_ids`.
2. Find the `"kind":"exec"` line whose `tool_exec_id` matches — that record names the
   tool, args, `artifact_offset`, and `stdout_sha256`.
3. Find the matching `"kind":"verdict"` line — the independent Skeptic's ruling, with
   its own (different-tool) `skeptic_exec_ids`.
4. The `"kind":"gate"` line shows the final confidence and why.

Verify the chain hasn't been tampered with:
```bash
python3 -c "from glassbox.claimchain import ClaimChain; print(ClaimChain('sample_run/ledger.jsonl').verify_chain())"
```
