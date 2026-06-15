"""Glass Box — a self-correcting DFIR triage agent.

Trust is enforced by architecture, not prompts:
  * the tool surface is typed and read-only (no shell, no write primitive),
  * every finding is cryptographically bound to the execution that produced it,
  * an independent Skeptic re-derives every claim with a different tool.
"""

__version__ = "1.0.0"
