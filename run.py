#!/usr/bin/env python3
"""One-command Glass Box investigation.

    python run.py                      # run the reference case, write out/report.html
    python run.py --open               # ...and open the report in a browser
    python run.py --case cases/case01  # explicit case

Runs the full pipeline: seal -> investigate -> skeptic challenge -> gate ->
verify -> score -> report. Works with zero API keys (deterministic engine).
Set GLASSBOX_INVESTIGATOR / GLASSBOX_SKEPTIC (e.g. anthropic:claude-fable-5 and
openai:gpt-4o) to run with real, different-vendor models.
"""

from __future__ import annotations

import argparse
import os
import sys
import webbrowser

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from glassbox.orchestrator import Orchestrator, RunConfig  # noqa: E402


def _load_dotenv(path: str) -> None:
    """Minimal .env loader (no dependency): KEY=value lines into os.environ."""
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    _load_dotenv(os.path.join(here, ".env"))
    p = argparse.ArgumentParser(description="Run a Glass Box investigation.")
    p.add_argument("--case", default=os.path.join(here, "cases", "case01"))
    p.add_argument("--out", default=os.path.join(here, "out"))
    p.add_argument("--evidence", default=None)
    p.add_argument("--investigator", default=None)
    p.add_argument("--skeptic", default=None)
    p.add_argument("--max-iterations", type=int, default=12)
    p.add_argument("--open", action="store_true", help="open the HTML report when done")
    args = p.parse_args()

    cfg = RunConfig(
        case_dir=args.case, out_dir=args.out, evidence_path=args.evidence,
        investigator_spec=args.investigator, skeptic_spec=args.skeptic,
        max_iterations=args.max_iterations,
    )
    result = Orchestrator(cfg).run()

    print("Artifacts:")
    print(f"  report      {result.report_path}")
    print(f"  ledger      {result.ledger_path}")
    print(f"  certificate {result.certificate_path}")
    print(f"  accuracy    {result.accuracy_path}")

    if args.open:
        webbrowser.open("file://" + os.path.abspath(result.report_path))

    ok = bool(result.certificate and result.certificate.get("overall_ok"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
