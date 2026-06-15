# Glass Box — Architecture & Trust Boundaries

> Redraw the diagram below in draw.io / Excalidraw for the submission. Keep the
> two trust-boundary labels — judges require architectural-vs-prompt guardrails
> to be explicitly distinguished.

```
                     GLASS BOX ORCHESTRATOR
               (state machine, hard max-iteration cap)
        seal → scope → hypothesize → investigate → claim →
        challenge(skeptic) → correct → adjudicate → gate → verify → report
                               │
        ┌──────────────────────┼──────────────────────┐
        ▼                      ▼                      ▼
   INVESTIGATOR           THE SKEPTIC           HYPOTHESIS BOARD
   (Model A)              (Model B, other        (3 rival theories;
   forms claims           vendor; re-derives     killed only by a
   via typed tools        with a DIFFERENT       contradicting tool
                          tool; sees only        execution)
        │                 claim + handles)
        │                      │
        ▼                      ▼
  ╔══════════════════════════════════════════════════════╗
  ║   TYPED READ-ONLY TOOL SURFACE  (the core innovation) ║   ← exposed over MCP
  ║   get_mft_timeline get_prefetch get_amcache get_usn   ║
  ║   get_runkeys get_shimcache get_logfile_records       ║
  ║   list_event_logs vol_pslist vol_malfind vol_netscan  ║
  ║   vol_cmdline yara_scan hash_object   (14 tools)      ║
  ║   ── NO execute_shell. NO write/delete. By design. ── ║
  ╚════════════════╤═══════════════════════╤═════════════╝
                   │                       │
          PROMPTARMOR taint            parse → summarize → return
          + injection detector         (never raw dumps to the model)
                   │                       │
                   ▼                       ▼
        ╔══════════════════════════════════════════════╗
        ║  EVIDENCE (sealed; canaries seeded)           ║
        ║  SHA-256 pre/post; read-only by construction  ║
        ╚═══════════════════════╤══════════════════════╝
                                ▼
        ╔══════════════════════════════════════════════╗
        ║  CLAIMCHAIN LEDGER (hash-chained JSONL)       ║
        ║  claim → tool_exec_id → artifact_offset →     ║
        ║  raw_sha256 → confidence → skeptic_verdict     ║
        ╚═══════════════════════╤══════════════════════╝
                                ▼
        ╔══════════════════════════════════════════════╗
        ║  GATE (hallucination firewall)               ║
        ║  unbound OR refuted  →  demoted to inference  ║
        ╚═══════════════════════╤══════════════════════╝
                                ▼
        ╔══════════════════════════════════════════════╗
        ║  GLASS REPORT (HTML): every sentence clicks   ║
        ║  through to its evidence; demoted claims show ║
        ║  as "inference — unverified"                  ║
        ╚══════════════════════════════════════════════╝
```

## Trust-boundary legend (put this on the diagram)

**Architectural guardrails (HARD — hold even if the model misbehaves):**
- The tool surface contains **no write or shell primitive**. Spoliation is
  impossible because no tool capable of it exists (`tools.py`,
  `mcp_server.py --list` shows `write_tools: []`, `shell_tools: []`).
- Evidence is **SHA-256 sealed pre/post** and watched by **canary tripwires**;
  an integrity certificate attests both (`evidence.py`).
- The **gate** demotes any claim that is unbound or skeptic-refuted, regardless
  of what the model asserted (`gate.py`).
- The **hash-chained ledger** makes the audit trail tamper-evident
  (`claimchain.py`).

**Prompt guardrail (SOFT — label it as such):**
- The Investigator's system prompt asks it to cite evidence. This is **not
  relied upon**. The gate enforces citation *architecturally*, so even if the
  prompt is ignored, an unbound claim can never reach "confirmed."

## Why the Skeptic is genuinely independent
- Different vendor/model from the Investigator (identical models are refused).
- Receives **only** the claim text + evidence handles — never the
  Investigator's chain of reasoning.
- Must **re-derive with a different tool** than the one that produced the claim;
  the end-to-end test asserts the investigator/skeptic tool sets are disjoint.

## Data contract (frozen on hour 0)
`ToolExecution` (tool_exec_id, tool_name, args, evidence_path, artifact_offset,
stdout_sha256, parsed_summary, actor, tokens) → cited by `Claim`
(supporting_exec_ids, proposed/final confidence, skeptic_verdict,
skeptic_exec_ids) → grouped under `Hypothesis`. See `glassbox/schemas.py`.
