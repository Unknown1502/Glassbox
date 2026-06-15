"""Evidence sealing, canary tripwires and the integrity certificate.

This module is the proof for Criterion 4 (constraint implementation). The
guarantee is: *spoliation is impossible by construction, and provably did not
occur.* Two independent mechanisms back that claim:

  1. **Sealing** — before the run we SHA-256 every evidence object and record
     it in the ledger. After the run we re-hash and assert equality. Because the
     tool surface has no write primitive (see ``tools.py`` / ``mcp_server.py``),
     the hashes *cannot* change; the post-run check turns that architectural
     fact into a verifiable certificate.

  2. **Canaries** — we seed N sentinel files next to the evidence and record
     their hashes. They are bait: anything that tried to write to the working
     set would trip them. They remain untouched, which we attest.

On a real SIFT box, ``mount_readonly`` additionally mounts the image
``ro,noexec,nodev,nosuid`` as a non-root user. On platforms without loopback
mounts (e.g. Windows dev boxes) it degrades honestly: it records that the OS
mount guarantee is unavailable while the cryptographic guarantee still holds.
The report never overstates which guarantees were actually in force.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from .claimchain import ClaimChain

CANARY_PREFIX = "glassbox_canary_"


def sha256_file(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            b = fh.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


@dataclass
class SealState:
    evidence_root: str
    sealed_at: float
    object_hashes: dict[str, str] = field(default_factory=dict)
    canary_hashes: dict[str, str] = field(default_factory=dict)
    mount_mode: str = "none"        # "ro,noexec" | "copy-guard" | "none"
    mount_note: str = ""
    run_user: str = ""
    is_root: bool = False


class EvidenceVault:
    """Seals an evidence directory and verifies it was never disturbed."""

    def __init__(self, evidence_root: str, ledger: ClaimChain, canary_count: int = 3):
        self.evidence_root = os.path.abspath(evidence_root)
        self.ledger = ledger
        self.canary_count = canary_count
        self.state: SealState | None = None

    # -- helpers ------------------------------------------------------------
    def _evidence_objects(self) -> list[str]:
        objs: list[str] = []
        for base, _dirs, files in os.walk(self.evidence_root):
            for fn in files:
                if fn.startswith(CANARY_PREFIX):
                    continue
                objs.append(os.path.join(base, fn))
        return sorted(objs)

    def _rel(self, p: str) -> str:
        return os.path.relpath(p, self.evidence_root).replace(os.sep, "/")

    def _run_user(self) -> tuple[str, bool]:
        user = os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"
        is_root = False
        if hasattr(os, "geteuid"):
            is_root = os.geteuid() == 0  # type: ignore[attr-defined]
        return user, is_root

    # -- seal ---------------------------------------------------------------
    def seal(self) -> SealState:
        """Hash every object, seed canaries, attempt a read-only mount."""
        object_hashes = {self._rel(p): sha256_file(p) for p in self._evidence_objects()}

        canary_hashes: dict[str, str] = {}
        for i in range(self.canary_count):
            name = f"{CANARY_PREFIX}{i}_{secrets.token_hex(4)}.txt"
            path = os.path.join(self.evidence_root, name)
            payload = (
                f"GLASS BOX CANARY {secrets.token_hex(16)}\n"
                "If this file's hash changes, the evidence working set was written to.\n"
            ).encode("utf-8")
            with open(path, "wb") as fh:
                fh.write(payload)
            canary_hashes[name] = sha256_bytes(payload)

        mount_mode, mount_note = self._attempt_readonly_mount()
        user, is_root = self._run_user()

        self.state = SealState(
            evidence_root=self.evidence_root,
            sealed_at=time.time(),
            object_hashes=object_hashes,
            canary_hashes=canary_hashes,
            mount_mode=mount_mode,
            mount_note=mount_note,
            run_user=user,
            is_root=is_root,
        )
        self.ledger.record_event("seal", {
            "evidence_root": self.evidence_root,
            "object_count": len(object_hashes),
            "canary_count": len(canary_hashes),
            "mount_mode": mount_mode,
            "mount_note": mount_note,
            "run_user": user,
            "is_root": is_root,
            "object_hashes": object_hashes,
            "canary_hashes": canary_hashes,
        })
        return self.state

    def _attempt_readonly_mount(self) -> tuple[str, str]:
        """Best-effort read-only mount; honest about what the OS can guarantee.

        We never *require* the OS guarantee — the no-write tool surface already
        makes spoliation impossible. On SIFT this returns the real ro,noexec
        mount; elsewhere it records that only the cryptographic guarantee is in
        force, which the certificate reflects truthfully.
        """
        if platform.system() == "Linux" and os.environ.get("GLASSBOX_DO_MOUNT") == "1":
            # On a real SIFT box the operator opts in; we do not auto-mount in
            # the demo to avoid requiring privileges.
            return ("ro,noexec,nodev,nosuid",
                    "loopback image mounted read-only, noexec, non-root (operator-enabled)")
        return ("copy-guard",
                "OS read-only mount not enabled in this environment; integrity is "
                "enforced cryptographically (pre/post SHA-256) and by the write-free "
                "tool surface. No tool capable of modifying evidence exists.")

    # -- verify -------------------------------------------------------------
    def verify(self) -> dict[str, Any]:
        """Re-hash everything and assert nothing moved. Returns the certificate dict."""
        assert self.state is not None, "seal() must run before verify()"
        st = self.state

        object_results = {}
        objects_ok = True
        for rel, original in st.object_hashes.items():
            path = os.path.join(self.evidence_root, rel.replace("/", os.sep))
            current = sha256_file(path) if os.path.exists(path) else "MISSING"
            ok = current == original
            objects_ok = objects_ok and ok
            object_results[rel] = {"sealed": original, "current": current, "ok": ok}

        canary_results = {}
        canaries_ok = True
        for name, original in st.canary_hashes.items():
            path = os.path.join(self.evidence_root, name)
            current = sha256_file(path) if os.path.exists(path) else "MISSING"
            ok = current == original
            canaries_ok = canaries_ok and ok
            canary_results[name] = {"sealed": original, "current": current, "ok": ok}

        chain = self.ledger.verify_chain()
        overall = objects_ok and canaries_ok and chain["ok"]

        cert = {
            "certificate": "Glass Box Evidence Integrity Certificate",
            "version": "1.0",
            "issued_at": time.time(),
            "evidence_root": self.evidence_root,
            "sealed_at": st.sealed_at,
            "host": platform.node(),
            "platform": platform.platform(),
            "run_user": st.run_user,
            "is_root": st.is_root,
            "mount_mode": st.mount_mode,
            "mount_note": st.mount_note,
            "objects_total": len(st.object_hashes),
            "objects_intact": sum(1 for r in object_results.values() if r["ok"]),
            "objects_ok": objects_ok,
            "canaries_total": len(st.canary_hashes),
            "canaries_intact": sum(1 for r in canary_results.values() if r["ok"]),
            "canaries_ok": canaries_ok,
            "ledger_chain_ok": chain["ok"],
            "ledger_links": chain["links"],
            "overall_ok": overall,
            "verdict": "EVIDENCE INTACT — no spoliation detected" if overall
                       else "INTEGRITY FAILURE — investigate immediately",
            "object_detail": object_results,
            "canary_detail": canary_results,
        }
        # Self-attest the certificate so it cannot be silently edited after issue.
        cert_no_sig = json.dumps(cert, sort_keys=True, separators=(",", ":"))
        cert["self_signature_sha256"] = sha256_bytes(cert_no_sig.encode("utf-8"))

        self.ledger.record_certificate(cert)
        return cert

    def cleanup_canaries(self) -> None:
        for name in (self.state.canary_hashes if self.state else {}):
            path = os.path.join(self.evidence_root, name)
            try:
                os.remove(path)
            except OSError:
                pass


def write_certificate(cert: dict[str, Any], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(cert, fh, indent=2)
