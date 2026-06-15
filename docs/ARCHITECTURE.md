# Glass Box — Architecture & Trust Boundaries

**Architectural pattern:** *Custom MCP Server* (FIND EVIL! brief, Approach #2) —
the pattern the organizers call "the most sound architecture in the evaluation"
— combined with a *multi-agent* Investigator/Skeptic loop. The agent reaches
evidence **only** through typed, read-only forensic functions; there is no
generic `execute_shell` and no write/delete tool in existence.

> The two diagrams below render natively on GitHub (Mermaid). The first is the
> system / trust-boundary diagram required for submission; the second shows the
> self-correction loop.

---

## 1. System diagram (trust boundaries labeled)

```mermaid
flowchart TB
    classDef hard fill:#0b3d2e,stroke:#2ea043,color:#e6edf3,stroke-width:2px;
    classDef soft fill:#3d2e0b,stroke:#d29922,color:#e6edf3,stroke-width:2px;
    classDef neutral fill:#161b22,stroke:#30363d,color:#e6edf3;
    classDef danger fill:#3d0b0b,stroke:#f85149,color:#e6edf3;

    %% subgraphs declared first so their ids are never parsed as plain nodes
    subgraph ORCH["ORCHESTRATOR — bounded state machine: max-iterations cap + HandoffPacket SITREP"]
        direction LR
        INV["INVESTIGATOR<br/>Model A"]:::soft
        SKEP["THE SKEPTIC<br/>Model B · different vendor<br/>sees only claim + evidence handles"]:::soft
        HYP["HYPOTHESIS BOARD<br/>up to 3 rival theories<br/>killed only by a contradicting execution"]:::neutral
    end

    subgraph SURF["TYPED READ-ONLY TOOL SURFACE · MCP — NO shell / write / delete tool exists"]
        direction LR
        D1["DISK<br/>get_runkeys · get_amcache · get_shimcache<br/>get_mft_timeline · get_prefetch<br/>get_usn · get_logfile_records · list_event_logs"]:::hard
        M1["MEMORY · Volatility 3<br/>vol_pslist · vol_malfind<br/>vol_netscan · vol_cmdline"]:::hard
        Y1["yara_scan · hash_object"]:::hard
    end

    subgraph EVID["EVIDENCE — sealed before and after the run"]
        direction LR
        SEAL["SHA-256 of every object, pre and post"]:::hard
        CAN["canary tripwires"]:::hard
    end

    OPER["Analyst / case scope"]:::neutral
    ARM["PROMPTARMOR<br/>scan attacker-controlled strings,<br/>quarantine injection as inert data,<br/>emit adversarial IOC"]:::hard
    ADP["SIFT CLI ADAPTERS<br/>Volatility3 -r json · analyzeMFT / MFTECmd<br/>RegRipper · YARA — or fixture fallback"]:::neutral
    LED["CLAIMCHAIN LEDGER<br/>hash-chained append-only JSONL<br/>claim to tool_exec_id to artifact_offset to output_hash to verdict"]:::hard
    GATE{"GATE · hallucination firewall<br/>bound to evidence AND skeptic-confirmed?"}:::hard
    CONF["CONFIRMED finding"]:::neutral
    DEMO["demoted to inference / unverifiable"]:::danger
    CERT["INTEGRITY CERTIFICATE<br/>pre/post hashes + canaries + chain"]:::hard
    REP["GLASS REPORT · self-contained HTML<br/>every sentence clicks through to its evidence;<br/>demoted claims shown as inference — unverified"]:::neutral

    OPER --> ORCH
    INV -->|"names a tool + args, cannot execute"| SURF
    SKEP -->|"must re-derive with a DIFFERENT tool"| SURF
    SURF --> ARM
    SURF --> ADP
    ADP --> EVID
    ARM --> LED
    EVID --> LED
    INV -.->|records exec| LED
    SKEP -.->|records verdict| LED
    LED --> GATE
    GATE -->|yes| CONF
    GATE -->|"no · unbound or refuted"| DEMO
    CONF --> REP
    DEMO --> REP
    EVID --> CERT
    CERT --> REP
```

**Legend**

| Style | Meaning |
|---|---|
| 🟩 green | **Architectural guardrail (HARD)** — holds even if the model misbehaves |
| 🟨 amber | **Prompt guardrail (SOFT)** — the model's instructions; *not relied upon* |
| 🟥 red | a claim the gate refused to confirm |

---

## 2. Where security boundaries are enforced

The brief requires architectural vs prompt guardrails to be distinguished. They are:

**Architectural guardrails (HARD — enforced by code/OS, survive a misbehaving model):**

| # | Guarantee | Enforced in | How to verify |
|---|---|---|---|
| A1 | No write/shell primitive exists in the tool surface | `tools.py`, `mcp_server.py` | `python -m glassbox.mcp_server --list` → `write_tools: []`, `shell_tools: []` |
| A2 | Evidence unchanged — SHA-256 sealed pre/post + canary tripwires | `evidence.py` | `out/integrity_certificate.json` (`overall_ok`) |
| A3 | Unbound or skeptic-refuted claims cannot be "confirmed" | `gate.py` | `tests/test_gate.py`; gate decisions in the ledger |
| A4 | Tamper-evident audit trail | `claimchain.py` | flip one byte → `verify_chain()` localizes the break |
| A5 | Skeptic must use a *different* tool than the Investigator | `agent.py`, `llm.py` | `tests/test_end_to_end.py` asserts disjoint tool sets |
| A6 | Evidence text is never executed as instruction | `promptarmor.py` | injection corpus self-test; quarantined as inert data |

**Prompt guardrail (SOFT — labeled as such, deliberately *not* trusted):**

- The Investigator's system prompt asks it to cite evidence and not over-flag.
  This is **not** the protection. The **gate (A3)** enforces citation
  structurally, so even if the prompt is ignored or the model hallucinates, an
  unbound claim can never reach the "confirmed" column. The prompt improves
  quality; the architecture provides the guarantee.

---

## 3. The self-correction loop (the autonomy tiebreaker)

```mermaid
sequenceDiagram
    participant I as Investigator · Model A
    participant T as Typed read-only tools
    participant L as ClaimChain ledger
    participant S as Skeptic · Model B, other vendor
    participant G as Gate

    I->>T: call get_* / vol_* (names tool; code executes it)
    T->>L: record ToolExecution (hash, offset, summary)
    I->>L: record Claim, citing tool_exec_id(s)
    Note over S: sees ONLY the claim text + which tools were used
    S->>T: re-derive with a DIFFERENT tool
    T->>L: record Skeptic ToolExecution
    S->>L: record Verdict (confirm / refute / unverifiable)
    L->>G: claim + binding + verdict
    alt bound AND skeptic-confirmed
        G-->>L: final = CONFIRMED
    else unbound OR refuted OR unverifiable
        G-->>L: demoted to inference / unverifiable
        Note over G: e.g. "PSEXESVC is malware" — Skeptic shows it is signed Sysinternals, REFUTE, hypothesis killed (live self-correction)
    end
```

---

## 4. Components

| Module | File | Responsibility |
|---|---|---|
| Schemas | `glassbox/schemas.py` | `ToolExecution`, `Claim`, `Hypothesis`, `Confidence`/`Verdict` enums (the frozen data contract) |
| Ledger | `glassbox/claimchain.py` | hash-chained append-only JSONL; `verify_chain`, `export_report_data` |
| Evidence | `glassbox/evidence.py` | seal/verify, canaries, self-signed integrity certificate |
| Tool surface | `glassbox/tools.py` | the 14 typed read-only tools; arg validation; provenance binding |
| SIFT adapters | `glassbox/sift_adapters.py` | drive live Volatility 3 / analyzeMFT / RegRipper / YARA; fixture fallback |
| MCP server | `glassbox/mcp_server.py` | expose the surface over MCP (`--list` proves 0 write/shell tools) |
| PromptArmor | `glassbox/promptarmor.py` | detect + quarantine injection in evidence; corpus self-test |
| Gate | `glassbox/gate.py` | the hallucination firewall (claim demotion) |
| Reasoners | `glassbox/llm.py` | Investigator/Skeptic; providers (Anthropic/OpenAI/Groq/Gemini/OpenRouter/Ollama) + deterministic engine |
| Agentic loop | `glassbox/agent.py` | real LLM drives the tools; independent Skeptic re-derives |
| Orchestrator | `glassbox/orchestrator.py` | the bounded state machine seal→…→report |
| Report | `glassbox/report.py` | self-contained click-through HTML |
| Scorer | `glassbox/scorer.py` | recall / precision / hallucinations vs ground truth |

---

## 5. Two run modes (same architecture)

| Mode | When | Reasoning | Accuracy on `case01` |
|---|---|---|---|
| **Deterministic engine** | default, no API keys | `glassbox/llm.py` fixed forensic logic | recall 1.0 / precision 1.0 / **0 hallucinations**, fully reproducible & offline |
| **Live agentic** | `.env` sets `GLASSBOX_INVESTIGATOR` + `GLASSBOX_SKEPTIC` | real different-vendor LLMs drive `glassbox/agent.py` | **0 hallucinations** in every run; recall scales with model quality / rate limits |

The gate, ledger, PromptArmor, sealing, and integrity certificate are **identical
in both modes** — only the reasoning changes. See `docs/ACCURACY.md` for the
measured numbers (run on the SIFT Workstation) and documented failure modes.

---

## 6. Invariant that ties it together

> **The model reasons; Glass Box owns the tools and the provenance.**

In both modes a model only ever *names* a tool and arguments. Glass Box executes
it, hashes the output, records the `tool_exec_id`, and binds the claim to it. A
model can never fabricate an execution, cite evidence it did not pull, or reach a
write/shell capability — because none exists to reach. That is why a Glass Box
finding is something you can put on a witness stand.
