"""Glass Report — renders the ledger into one self-contained HTML file.

Every assertion is clickable and reveals exactly what produced it: the tool, its
arguments, the parsed output excerpt, the artifact offset, the SHA-256 of the
raw output, and the independent Skeptic's verdict. Claims the gate could not
confirm are rendered visually distinct ("inference — unverified"), so the reader
can never mistake a hunch for a finding. The integrity certificate and the
accuracy table are embedded inline. No external assets, no JS framework — just
HTML + a little CSS so it opens anywhere and survives archival.
"""

from __future__ import annotations

import html
import json
import time
from typing import Any

from .claimchain import ClaimChain

_CSS = """
:root{--bg:#0d1117;--panel:#161b22;--line:#30363d;--ink:#e6edf3;--muted:#8b949e;
--ok:#2ea043;--warn:#d29922;--bad:#f85149;--accent:#58a6ff;--adv:#bc8cff;}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;}
.wrap{max-width:1040px;margin:0 auto;padding:32px 20px 80px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:34px 0 12px;
border-bottom:1px solid var(--line);padding-bottom:6px}
.sub{color:var(--muted);margin:0 0 18px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.kpi{font-size:26px;font-weight:700}.kpi.ok{color:var(--ok)}.kpi.bad{color:var(--bad)}
.kpi.warn{color:var(--warn)}.lbl{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:600}
.b-confirmed{background:rgba(46,160,67,.16);color:#56d364;border:1px solid rgba(46,160,67,.4)}
.b-inference{background:rgba(210,153,34,.14);color:#e3b341;border:1px solid rgba(210,153,34,.4)}
.b-unverifiable{background:rgba(139,148,158,.14);color:#adbac7;border:1px solid rgba(139,148,158,.4)}
.b-probable{background:rgba(88,166,255,.14);color:#79c0ff;border:1px solid rgba(88,166,255,.4)}
.b-adv{background:rgba(188,140,255,.14);color:#d2a8ff;border:1px solid rgba(188,140,255,.45)}
details{background:var(--panel);border:1px solid var(--line);border-radius:10px;margin:10px 0;overflow:hidden}
details[data-final=inference],details[data-final=unverifiable]{border-style:dashed;opacity:.92}
summary{cursor:pointer;padding:14px 16px;list-style:none;display:flex;gap:10px;align-items:flex-start}
summary::-webkit-details-marker{display:none}
summary .assert{flex:1}summary .mitre{color:var(--muted);font-size:12px;font-family:ui-monospace,monospace}
.prov{padding:0 16px 16px;border-top:1px solid var(--line);margin-top:2px}
.exec{background:#0b0f14;border:1px solid var(--line);border-radius:8px;padding:10px 12px;margin:10px 0;
font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12.5px;color:#c9d1d9}
.exec .k{color:var(--accent)}.hash{color:var(--muted);word-break:break-all}
.verdict{margin-top:8px;padding:8px 10px;border-left:3px solid var(--line);background:#0b0f14;border-radius:0 8px 8px 0}
.v-confirm{border-left-color:var(--ok)}.v-refute{border-left-color:var(--bad)}.v-unverifiable{border-left-color:var(--warn)}
.hyp{padding:10px 14px;border-radius:8px;margin:8px 0;border:1px solid var(--line);background:var(--panel)}
.hyp.killed{border-left:4px solid var(--bad)}.hyp.supported{border-left:4px solid var(--ok)}
.hyp.open{border-left:4px solid var(--muted)}
.cert{border:1px solid var(--line);border-radius:10px;padding:16px;background:var(--panel)}
.cert.ok{border-color:rgba(46,160,67,.5)}.cert.bad{border-color:rgba(248,81,73,.5)}
table{width:100%;border-collapse:collapse;margin-top:8px}td,th{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);font-size:13px}
th{color:var(--muted);font-weight:600}.mono{font-family:ui-monospace,monospace;font-size:12px}
.legend{font-size:13px;color:var(--muted)}.legend b{color:var(--ink)}
a{color:var(--accent)}.foot{color:var(--muted);font-size:12px;margin-top:40px;border-top:1px solid var(--line);padding-top:14px}
"""


def _esc(s: Any) -> str:
    return html.escape(str(s))


def _conf_badge(final: str | None) -> str:
    final = final or "probable"
    cls = {"confirmed": "b-confirmed", "inference": "b-inference",
           "unverifiable": "b-unverifiable", "probable": "b-probable"}.get(final, "b-probable")
    label = {"confirmed": "CONFIRMED", "inference": "inference — unverified",
             "unverifiable": "unverifiable", "probable": "probable"}.get(final, final)
    return f'<span class="badge {cls}">{label}</span>'


def _exec_block(ex: dict) -> str:
    return f"""<div class="exec">
<div><span class="k">tool</span> {_esc(ex.get('tool_name'))} &nbsp; <span class="k">actor</span> {_esc(ex.get('actor'))} &nbsp; <span class="k">source</span> {_esc(ex.get('source'))}</div>
<div><span class="k">args</span> {_esc(json.dumps(ex.get('args', {})))}</div>
<div><span class="k">artifact</span> {_esc(ex.get('artifact_offset'))}</div>
<div><span class="k">summary</span> {_esc(ex.get('parsed_summary'))}</div>
<div class="hash"><span class="k">raw_sha256</span> {_esc(ex.get('stdout_sha256'))}</div>
<div class="hash"><span class="k">exec_id</span> {_esc(ex.get('tool_exec_id'))} &nbsp; <span class="k">dur</span> {_esc(ex.get('duration_ms'))}ms</div>
</div>"""


def render_report(ledger: ClaimChain, accuracy: dict, out_path: str) -> str:
    data = ledger.export_report_data()
    execs = data["executions"]
    claims = list(data["claims"].values())
    hypotheses = list(data["hypotheses"].values())
    cert = data["certificate"] or {}
    chain = data["chain"]
    start_event = next((e for e in data["events"] if e.get("label") == "run:start"), {})
    detail = start_event.get("detail", {})

    # order claims: confirmed first, then adversarial, then demoted
    order = {"confirmed": 0, "probable": 1, "unverifiable": 2, "inference": 3}
    claims.sort(key=lambda c: (c.get("kind") != "adversarial",
                               order.get(c.get("final_confidence") or "probable", 1)))

    # --- KPI cards ---
    rec = accuracy.get("recall", 0)
    prec = accuracy.get("precision", 0)
    hall = accuracy.get("hallucinations", 0)
    confirmed_n = accuracy.get("confirmed_claims", 0)
    kpis = f"""
    <div class="grid">
      <div class="card"><div class="lbl">Recall</div><div class="kpi ok">{rec}</div></div>
      <div class="card"><div class="lbl">Precision</div><div class="kpi ok">{prec}</div></div>
      <div class="card"><div class="lbl">Hallucinations</div><div class="kpi {'ok' if hall==0 else 'bad'}">{hall}</div></div>
      <div class="card"><div class="lbl">Decoy flagged</div><div class="kpi {'ok' if accuracy.get('decoy_flagged',0)==0 else 'bad'}">{accuracy.get('decoy_flagged',0)}</div></div>
      <div class="card"><div class="lbl">Confirmed findings</div><div class="kpi">{confirmed_n}</div></div>
    </div>"""

    # --- integrity certificate ---
    ok = cert.get("overall_ok")
    cert_html = f"""
    <div class="cert {'ok' if ok else 'bad'}">
      <div style="font-size:17px;font-weight:700">{'✓ ' if ok else '✗ '}{_esc(cert.get('verdict','(no certificate)'))}</div>
      <table>
        <tr><th>Evidence objects intact</th><td>{cert.get('objects_intact','?')}/{cert.get('objects_total','?')}</td>
            <th>Canaries intact</th><td>{cert.get('canaries_intact','?')}/{cert.get('canaries_total','?')}</td></tr>
        <tr><th>Ledger chain</th><td>{'intact' if cert.get('ledger_chain_ok') else 'BROKEN'} ({cert.get('ledger_links','?')} links)</td>
            <th>Mount mode</th><td class="mono">{_esc(cert.get('mount_mode','?'))}</td></tr>
        <tr><th>Run user / root</th><td>{_esc(cert.get('run_user','?'))} / {_esc(cert.get('is_root'))}</td>
            <th>Host</th><td class="mono">{_esc(cert.get('host','?'))}</td></tr>
      </table>
      <div class="legend" style="margin-top:10px">{_esc(cert.get('mount_note',''))}</div>
      <div class="hash" style="margin-top:6px;font-family:ui-monospace,monospace;font-size:11px">self_signature_sha256: {_esc(cert.get('self_signature_sha256',''))}</div>
    </div>"""

    # --- hypotheses ---
    hyp_html = ""
    for h in hypotheses:
        st = h.get("status", "open")
        note = f' — <span class="legend">{_esc(h.get("note",""))}</span>' if h.get("note") else ""
        kb = f' <span class="mono">(killed by {_esc(h.get("killed_by_exec_id"))})</span>' if h.get("killed_by_exec_id") else ""
        hyp_html += f'<div class="hyp {st}"><b>{st.upper()}</b> — {_esc(h.get("statement"))}{note}{kb}</div>'

    # --- claims ---
    claims_html = ""
    for c in claims:
        final = c.get("final_confidence") or "probable"
        is_adv = c.get("kind") == "adversarial"
        badge = '<span class="badge b-adv">ADVERSARIAL IOC</span>' if is_adv else _conf_badge(final)
        mitre = f'<span class="mitre">{_esc(c.get("mitre"))}</span>' if c.get("mitre") else ""
        prov = ""
        for eid in c.get("supporting_exec_ids", []):
            ex = execs.get(eid)
            if ex:
                prov += _exec_block(ex)
        # skeptic
        sv = c.get("skeptic_verdict", "pending")
        vcls = {"confirm": "v-confirm", "refute": "v-refute",
                "unverifiable": "v-unverifiable"}.get(sv, "")
        sk_execs = "".join(_exec_block(execs[e]) for e in c.get("skeptic_exec_ids", []) if e in execs)
        verdict_html = f"""<div class="verdict {vcls}">
          <b>Skeptic ({_esc(detail.get('skeptic','independent'))}) verdict: {_esc(sv).upper()}</b><br>
          {_esc(c.get('skeptic_note',''))}
          {('<div style="margin-top:6px"><span class="legend">Independent re-derivation (different tool):</span>'+sk_execs+'</div>') if sk_execs else ''}
        </div>"""
        claims_html += f"""
        <details data-final="{_esc(final)}">
          <summary><span class="assert">{_esc(c.get('assertion'))}</span>{mitre} {badge}</summary>
          <div class="prov">
            <div class="legend" style="margin:8px 0">Provenance — the execution(s) this claim is cryptographically bound to:</div>
            {prov or '<div class="legend">No supporting execution — auto-demoted to inference.</div>'}
            {verdict_html}
          </div>
        </details>"""

    # --- accuracy detail table ---
    missed_rows = "".join(
        f"<tr><td>{m['id']}</td><td>{_esc(m['artifact'])}</td></tr>" for m in accuracy.get("missed", []))
    missed_table = f"<table><tr><th>id</th><th>missed artifact</th></tr>{missed_rows}</table>" if missed_rows else '<div class="legend">No missed artifacts.</div>'

    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Glass Box — Investigation Report</title><style>{_CSS}</style></head>
<body><div class="wrap">
  <h1>Glass Box — Investigation Report</h1>
  <p class="sub">Case <b>{_esc(accuracy.get('case_id'))}</b> &nbsp;•&nbsp;
     Investigator <b>{_esc(detail.get('investigator','deterministic'))}</b> &nbsp;•&nbsp;
     Skeptic <b>{_esc(detail.get('skeptic','deterministic'))}</b> &nbsp;•&nbsp;
     independent: <b>{_esc(detail.get('independent'))}</b><br>
     Generated {_esc(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()))}</p>

  <h2>Accuracy (measured vs ground truth)</h2>
  {kpis}

  <h2>Evidence Integrity Certificate</h2>
  {cert_html}

  <h2>Hypothesis board</h2>
  {hyp_html}

  <h2>Findings — click any claim to reveal its evidence</h2>
  <p class="legend">Solid border = <b>confirmed</b> (bound to evidence AND independently confirmed).
     Dashed/faded = <b>inference / unverifiable</b> (the gate refused to confirm it). Purple = adversarial IOC.</p>
  {claims_html}

  <h2>Missed artifacts</h2>
  {missed_table}

  <h2>Trust boundaries</h2>
  <div class="card legend">
    <p><b>Architectural guardrails (hard):</b> read-only typed MCP surface with
       <b>no write or shell tool in existence</b>; pre/post SHA-256 sealing; canary tripwires;
       hash-chained ledger; the gate that demotes any unbound or skeptic-refuted claim.</p>
    <p><b>Prompt guardrail (soft):</b> the Investigator is asked to cite evidence. This is
       <b>not relied upon</b> — the gate enforces citation architecturally, so ignoring the
       prompt cannot promote an unbound claim to "confirmed."</p>
    <p>Ledger hash chain: <b>{'INTACT' if chain.get('ok') else 'BROKEN'}</b> ({chain.get('links')} links).
       This report was reconstructed entirely from that tamper-evident ledger.</p>
  </div>

  <div class="foot">Glass Box • self-correcting DFIR triage • every finding provable, every demotion explained.</div>
</div></body></html>"""

    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(page)
    return out_path
