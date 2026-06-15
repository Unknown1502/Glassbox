"""The gate — Glass Box's hallucination firewall (Criterion 2).

Design principle #2 made mechanical: *an assertion that cannot be bound to a
tool execution is not a finding.* The gate is the single chokepoint every claim
passes through before it can appear as "confirmed." It does not trust the
Investigator's self-assigned confidence, and it does not trust the prompt that
asked the Investigator to cite evidence — it inspects the structural facts:

  * Is the claim bound to >=1 real ``ToolExecution``? If not -> ``inference``.
  * Did the independent Skeptic ``confirm`` it? If ``refute`` -> demote to
    ``inference``; if ``unverifiable`` -> ``unverifiable``.
  * ``confirmed`` is awarded *only* when both hold: bound evidence AND a Skeptic
    ``confirm``.

Because this runs regardless of what the model said, ignoring the cite-your-
evidence prompt cannot smuggle an unbound claim into the confirmed column.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .schemas import Claim, Confidence, Verdict


@dataclass
class GateDecision:
    claim_id: str
    before: Confidence
    after: Confidence
    reason: str


def _exec_ids_exist(claim: Claim, known_exec_ids: set[str]) -> bool:
    return bool(claim.supporting_exec_ids) and all(
        eid in known_exec_ids for eid in claim.supporting_exec_ids
    )


def apply_gate(claim: Claim, known_exec_ids: set[str]) -> GateDecision:
    """Compute and assign ``claim.final_confidence``. Returns the decision."""
    before = claim.proposed_confidence

    # 1. Unbound assertion -> never better than inference.
    if not _exec_ids_exist(claim, known_exec_ids):
        claim.final_confidence = Confidence.INFERENCE
        return GateDecision(claim.claim_id, before, Confidence.INFERENCE,
                            "no supporting tool execution bound to this claim")

    # 2. Skeptic ruling governs the ceiling.
    verdict = claim.skeptic_verdict
    if verdict == Verdict.REFUTE:
        claim.final_confidence = Confidence.INFERENCE
        return GateDecision(claim.claim_id, before, Confidence.INFERENCE,
                            f"skeptic refuted: {claim.skeptic_note or 'contradicting evidence'}")
    if verdict == Verdict.UNVERIFIABLE:
        claim.final_confidence = Confidence.UNVERIFIABLE
        return GateDecision(claim.claim_id, before, Confidence.UNVERIFIABLE,
                            "skeptic could not independently verify")
    if verdict == Verdict.PENDING:
        # Bound but never adjudicated -> cannot be confirmed.
        downgraded = Confidence.PROBABLE if before == Confidence.CONFIRMED else before
        claim.final_confidence = downgraded
        return GateDecision(claim.claim_id, before, downgraded,
                            "bound to evidence but not yet adjudicated by the skeptic")

    # 3. verdict == CONFIRM and evidence is bound.
    if verdict == Verdict.CONFIRM:
        claim.final_confidence = Confidence.CONFIRMED
        return GateDecision(claim.claim_id, before, Confidence.CONFIRMED,
                            "bound to evidence AND independently confirmed by the skeptic")

    # Fallback (should be unreachable).
    claim.final_confidence = Confidence.INFERENCE
    return GateDecision(claim.claim_id, before, Confidence.INFERENCE, "unhandled verdict")


def gate_all(claims: Iterable[Claim], known_exec_ids: set[str]) -> list[GateDecision]:
    return [apply_gate(c, known_exec_ids) for c in claims]
