---
name: strix-orchestration
description: >-
  Orchestrate MoonMCP (fast, scope-first recon + detection) together with Strix
  (autonomous, sandboxed validation that produces working PoCs) as two MCP tools
  of the SAME agent — no separate window. Use when a lead needs to be VALIDATED
  with a proof-of-concept, when you want deep autonomous testing of a specific
  in-scope target, or when combining cheap recon with expensive confirmation.
  Triggers: "validate this", "prove the bug", "run a deep test", "PoC", "confirm
  the finding", "Strix".
---

# Orchestrating MoonMCP + Strix

You drive **two complementary offensive tools** that are both exposed to you over
MCP — you never leave your agent (opencode / hermes / Claude):

- **MoonMCP** — fast, cheap, **scope-first** recon & detection. Maps the attack
  surface and finds *leads* (headers, IDOR signals, injection reflections,
  takeovers, secrets, redirects, GraphQL, desync indicators). Deterministic,
  stdlib, rate-limited, refuses out-of-scope targets.
- **Strix** — an **autonomous** AI pentester in a Docker sandbox that **proves**
  a lead by generating a working PoC (Caido proxy + browser + exploit runtime).
  Powerful but heavy: it runs its own LLM loop, costs real tokens/time, and
  exploits — so you delegate to it deliberately, not reflexively.

Think of it as: **MoonMCP finds, Strix confirms.**

## The pipeline (find → decide → validate → merge)

1. **Recon & detect with MoonMCP** (cheap first). Use the operator prompts already
   built in (`bug_bounty_operator`, `deep_recon`, `injection_hunt`): set
   `scope_add` / a `program`, sweep passive → light active, and collect leads with
   `add_finding`. Confirm what you can cheaply *inside MoonMCP* — differential
   `passive_scan`, `http_repeater`, `intruder`, and blind-vuln `oast_*` callbacks.
2. **Decide what deserves Strix.** Only delegate leads that are (a) in scope, (b)
   high-value (RCE/SSRF/IDOR/auth/injection/logic), and (c) not already confirmed
   or refuted cheaply. Do **not** send Strix "test everything" — hand it a
   focused, evidence-backed task.
3. **Delegate to Strix as a tool.** Call the Strix tool (e.g. `strix_run`) with:
   - the exact in-scope `target`,
   - a tight `instruction` that carries the **rules of engagement** and the
     concrete lead(s) MoonMCP found (see the instruction recipe below).
4. **Consume & merge.** Take Strix's validated findings + PoCs, record them with
   MoonMCP `add_finding` (severity + evidence), then `triage_findings` to dedupe
   and rank, and `report` / `export_findings` for the writeup. Strix's PoC is your
   "confirmed" gate; a MoonMCP lead Strix could not reproduce stays `unconfirmed`.

## Instruction recipe for Strix (reuse the prompt base)

MoonMCP already ships a curated prompt base (`moonmcp/prompts.py`, documented in
`docs/SYSTEM_PROMPTS.md`): rules of engagement, the OODA operating loop, false-
positive discipline and the PoC gate. **Reuse it** — do not write Strix a fresh
persona each time. Build its `--instruction` from three parts:

1. **RoE preamble** — the shared `RULES_OF_ENGAGEMENT` (authorised only, scope is
   ground truth, no destructive/DoS/exfil, least-intrusive PoC, stop at proof).
2. **The lead** — exactly what MoonMCP observed, with evidence: the URL/parameter,
   the signal (e.g. "reflected `{{7*7}}` renders 49 → likely SSTI on `name`"), and
   the auth context.
3. **The objective** — "validate with a minimal, non-destructive PoC and stop;
   report reproduction steps + impact." (This mirrors `triage_and_report`'s PoC
   gate.)

Tight, evidence-backed instructions make Strix fast and on-target; open-ended ones
burn budget and wander.

## When NOT to call Strix

- The check is cheap and MoonMCP already answers it (headers, CORS, takeover,
  fingerprint, a single differential probe).
- The target is out of scope or authorisation is unclear — **stop and ask**.
- A human decision is needed before exploiting (production impact, sensitive data).
- You only need a lead, not a proof — leads are cheaper from MoonMCP.

## Safety (both tools, always)

Authorised testing only. MoonMCP's scope guard gates its own tools **and** the
Strix wrapper (the wrapper scope-checks the target before launching). Strix
exploits, so: least-intrusive PoC, no data exfiltration or destruction, and
surface every Strix finding for **human confirmation** before it is submitted to a
program. No pirated tooling — Strix is open-source (Apache-2.0) and uses Caido
(open-source), which is exactly the legal path.

## Bidirectional — Strix can also reach into MoonMCP

The link runs both ways. Strix has no MCP client, but it has a shell + Python
runtime, so it can call MoonMCP through the **CLI bridge** for the things it lacks
— curated knowledge, the shared memory hub, scope, cheap recon:

```
moonmcp call injection_info --json '{"injection_class":"ssti"}'
moonmcp call memory_search  --arg query=idor --arg trust=curated
moonmcp tools               # discover what's callable
```

Hand Strix a **curated slice**, not everything (it already has scanners/proxy/
browser): set `MOONMCP_PROFILE=strix` so only knowledge + memory + recon +
findings are exposed. This makes MoonMCP the shared brain/memory/guard that both
your agent and Strix talk to.

## Setup

See `docs/STRIX_INTEGRATION.md` — how to register Strix as an MCP tool for
**opencode** and **hermes** (a thin wrapper around `strix -n --target … --instruction …`
that reuses MoonMCP's `ScopeManager`), the required env (`STRIX_LLM`,
`LLM_API_KEY`, Docker), the reference wrapper in `examples/strix_mcp/`, and the
**reverse direction** (giving Strix a curated MoonMCP via the CLI bridge +
`MOONMCP_PROFILE`).
