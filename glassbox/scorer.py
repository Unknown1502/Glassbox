"""Scorer — turns a run into a measured accuracy report (Criterion 2/3).

Loads ``cases/<case>/groundtruth.json`` and compares the run's *confirmed*
claims against it:

  * **recall**    = matched non-decoy artifacts / total non-decoy artifacts
  * **precision** = confirmed claims that match a real artifact / all confirmed
                    claims (a confirmed decoy or unmatched claim costs precision)
  * **hallucinations** = confirmed claims matching no ground-truth artifact
  * **decoy_flagged** = did we wrongly confirm the benign decoy? (false positive)

Matching is keyword-based against each artifact's ``keywords`` plus its
detecting tool, which is robust to wording changes in the claim text. The
function also annotates each claim with the ground-truth id it matched, so the
report can show the mapping.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

from .schemas import Claim, Confidence, ClaimKind


def _load_groundtruth(case_dir: str) -> dict[str, Any]:
    path = os.path.join(case_dir, "groundtruth.json")
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


_IDENT = re.compile(r"[A-Za-z0-9_.\\:$-]*(?:\.exe|\.evtx|\.hve|\.pf)"        # filenames
                    r"|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?"          # IPv4[:port]
                    r"|\$[A-Za-z]+"                                          # $MFT, $UsnJrnl, $LogFile
                    r"|\bEID\s?\d{3,5}\b|\b\d{4}\b"                          # event ids
                    r"|pid\s?\d+", re.IGNORECASE)


def _identifiers(artifact: dict[str, Any]) -> set[str]:
    """Concrete, high-signal tokens (file/IP/key/PID/EID) from the artifact."""
    blob = f"{artifact.get('location','')} {artifact.get('artifact','')}"
    out = set()
    for m in _IDENT.findall(blob):
        t = m.strip().lower()
        if t and t not in {"2026", "2019"}:  # bare years are noise
            out.add(t)
    return out


def _matches(claim: Claim, artifact: dict[str, Any], claim_tools: list[str]) -> float:
    text = claim.assertion.lower()
    kws = [k.lower() for k in artifact.get("keywords", [])]
    # Kind gate: adversarial claims only match adversarial artifacts and v.v.
    if artifact.get("is_adversarial_ai") and claim.kind != ClaimKind.ADVERSARIAL:
        return -1.0
    if claim.kind == ClaimKind.ADVERSARIAL and not artifact.get("is_adversarial_ai"):
        return -1.0
    score = float(sum(1 for k in kws if k in text))
    # Concrete identifiers (an LLM naming the exact file/IP/PID/EID is strong signal).
    score += 3.0 * sum(1 for ident in _identifiers(artifact) if ident in text)
    if artifact.get("detecting_tool") and artifact["detecting_tool"] in claim_tools:
        score += 5.0
    if artifact.get("corroborating_tool") and artifact["corroborating_tool"] in claim_tools:
        score += 2.0
    return score


def score_run(case_dir: str, claims: list[Claim],
              exec_tool_index: dict[str, str] | None = None) -> dict[str, Any]:
    gt = _load_groundtruth(case_dir)
    artifacts = gt["artifacts"]
    non_decoy = [a for a in artifacts if not a.get("is_decoy")]

    confirmed = [c for c in claims if c.final_confidence == Confidence.CONFIRMED]

    def tools_for(c: Claim) -> list[str]:
        names: list[str] = []
        if exec_tool_index:
            names = [exec_tool_index.get(e, "") for e in c.supporting_exec_ids]
        if c.kind == ClaimKind.ADVERSARIAL:
            names.append("promptarmor")
        return names

    # One-to-one assignment: rank every (claim, artifact) pair by score, then
    # greedily bind the strongest pairs so two claims never grab one artifact.
    pairs = []
    for ci, c in enumerate(confirmed):
        tn = tools_for(c)
        for a in artifacts:
            s = _matches(c, a, tn)
            if s > 0:
                pairs.append((s, ci, a["id"], a.get("is_decoy", False)))
    pairs.sort(reverse=True)

    matched_ids: set[int] = set()
    claim_assigned: dict[int, int] = {}
    decoy_flags: list[str] = []
    for s, ci, aid, is_decoy in pairs:
        if ci in claim_assigned or aid in matched_ids:
            continue
        if is_decoy:
            decoy_flags.append(confirmed[ci].assertion[:80])
            claim_assigned[ci] = aid
            matched_ids.add(aid)
        else:
            claim_assigned[ci] = aid
            matched_ids.add(aid)
            confirmed[ci].groundtruth_id = aid

    decoy_ids = {a["id"] for a in artifacts if a.get("is_decoy")}
    matched_non_decoy = matched_ids - decoy_ids
    hallucinations = [c.assertion[:80] for ci, c in enumerate(confirmed)
                      if ci not in claim_assigned]

    recall = round(len(matched_non_decoy) / len(non_decoy), 3) if non_decoy else 0.0
    precision_denom = len(confirmed)
    precision = round((len(confirmed) - len(hallucinations) - len(decoy_flags))
                      / precision_denom, 3) if precision_denom else 0.0

    missed = [{"id": a["id"], "artifact": a["artifact"]}
              for a in non_decoy if a["id"] not in matched_non_decoy]

    return {
        "case_id": gt.get("case_id"),
        "artifacts_total": len(artifacts),
        "non_decoy_total": len(non_decoy),
        "confirmed_claims": len(confirmed),
        "matched": sorted(matched_non_decoy),
        "recall": recall,
        "precision": precision,
        "hallucinations": len(hallucinations),
        "hallucination_detail": hallucinations,
        "decoy_flagged": len(decoy_flags),
        "decoy_detail": decoy_flags,
        "missed": missed,
        "matched_count": len(matched_non_decoy),
    }


def write_accuracy(accuracy: dict[str, Any], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(accuracy, fh, indent=2)
