"""Core data contracts shared by every Glass Box module.

These dataclasses are the *integration contract* frozen on hour 0 of the build:
the ledger, the orchestrator, the gate, the report and the scorer all speak in
terms of ``ToolExecution``, ``Claim`` and ``Hypothesis``. Keep them JSON-round-
trippable (``to_dict`` / ``from_dict``) because the ledger is plain JSONL.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def _now() -> float:
    return time.time()


class Confidence(str, Enum):
    """How much weight a finding may carry in the final report.

    ``CONFIRMED`` is reserved for claims that are both bound to evidence *and*
    independently confirmed by the Skeptic. The gate (see ``gate.py``) is the
    only component allowed to award it.
    """

    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    INFERENCE = "inference"
    UNVERIFIABLE = "unverifiable"


class Verdict(str, Enum):
    """The Skeptic's independent ruling on a claim."""

    CONFIRM = "confirm"
    REFUTE = "refute"
    UNVERIFIABLE = "unverifiable"
    PENDING = "pending"


class ClaimKind(str, Enum):
    """What category of thing the claim asserts."""

    FINDING = "finding"          # ordinary forensic finding
    ADVERSARIAL = "adversarial"  # injection / anti-analysis aimed at the AI
    BENIGN = "benign"            # explicitly-cleared item (decoy handling)


@dataclass
class ToolExecution:
    """One invocation of one typed read-only forensic tool.

    This is the atom of provenance: every ``Claim`` points back to the
    ``tool_exec_id`` of the executions that support it, and the ledger hashes
    the whole record so a finding can never silently drift from its evidence.
    """

    tool_name: str
    args: dict[str, Any]
    evidence_path: str
    artifact_offset: str            # human-readable locator inside the artifact
    stdout_sha256: str              # hash of the raw tool output
    parsed_summary: str             # short, context-safe summary (never a raw dump)
    actor: str = "investigator"     # investigator | skeptic
    duration_ms: float = 0.0
    tokens_in: int = 0
    tokens_out: int = 0
    source: str = "fixture"         # "cli" if a real SIFT binary ran, else "fixture"
    tool_exec_id: str = field(default_factory=lambda: _new_id("exec"))
    timestamp: float = field(default_factory=_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ToolExecution":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class Claim:
    """An assertion produced by the Investigator and judged by the Skeptic.

    ``proposed_confidence`` is what the Investigator wanted; ``final_confidence``
    is what the gate allowed after considering evidence binding and the Skeptic
    verdict. They differ exactly when the architecture caught an overreach.
    """

    assertion: str
    kind: ClaimKind = ClaimKind.FINDING
    supporting_exec_ids: list[str] = field(default_factory=list)
    proposed_confidence: Confidence = Confidence.PROBABLE
    final_confidence: Confidence | None = None
    skeptic_verdict: Verdict = Verdict.PENDING
    skeptic_note: str = ""
    skeptic_exec_ids: list[str] = field(default_factory=list)
    hypothesis_id: str | None = None
    mitre: str = ""                 # optional ATT&CK technique id, e.g. "T1547.001"
    groundtruth_id: int | None = None  # set by the scorer when matched, else None
    claim_id: str = field(default_factory=lambda: _new_id("claim"))
    timestamp: float = field(default_factory=_now)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["kind"] = self.kind.value
        d["proposed_confidence"] = self.proposed_confidence.value
        d["final_confidence"] = self.final_confidence.value if self.final_confidence else None
        d["skeptic_verdict"] = self.skeptic_verdict.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Claim":
        d = dict(d)
        if "kind" in d and d["kind"] is not None:
            d["kind"] = ClaimKind(d["kind"])
        if d.get("proposed_confidence") is not None:
            d["proposed_confidence"] = Confidence(d["proposed_confidence"])
        if d.get("final_confidence") is not None:
            d["final_confidence"] = Confidence(d["final_confidence"])
        if d.get("skeptic_verdict") is not None:
            d["skeptic_verdict"] = Verdict(d["skeptic_verdict"])
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class Hypothesis:
    """A rival theory of the case. Killed only by a contradicting execution."""

    statement: str
    status: str = "open"            # open | supported | killed
    killed_by_exec_id: str | None = None
    note: str = ""
    hypothesis_id: str = field(default_factory=lambda: _new_id("hypo"))
    timestamp: float = field(default_factory=_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Hypothesis":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class HandoffPacket:
    """Graceful SITREP emitted if the orchestrator hits its iteration cap.

    Glass Box degrades into a human-readable handoff rather than into false
    confidence: it states what it knows, what it could not resolve, and the
    exact next step a human analyst should take.
    """

    reason: str
    iterations_used: int
    confirmed_count: int
    open_questions: list[str] = field(default_factory=list)
    recommended_next_step: str = ""
    timestamp: float = field(default_factory=_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
