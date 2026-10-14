"""Reporting tool family. Public signatures and payloads remain compatible."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .. import __version__
from .. import cvss as cvssmod
from .. import leadpipe as leadpipemod
from .. import metrics as metricsmod
from .. import obsidian as obsidianmod
from .. import strix_adapted as sa
from ..context import AppContext, to_dict
from ..reporting import format_sarif
from ..scope import normalize_target
from . import local_registration


def register(mcp: Any, safe_tool: Callable, get_context: Callable[[], AppContext], _host_key: Callable[[str], str]) -> dict[str, Callable]:
    """Bind tools to this server; imports do not register or create context."""
    exported: dict[str, Callable] = {}
    local = local_registration(mcp, safe_tool, exported)

    @local
    async def add_finding(target: str, severity: str, title: str, detail: str = "",
                          evidence: str = "", type: str = "manual", run_id: str = "") -> dict:
        """Record a finding in the persistent findings store (severity: critical/high/
        medium/low/info). Findings are also readable via the `findings://current`
        resource and summarised by `report`. Survives restarts when state storage is configured.
        Managed execution associates the current run automatically.
        """

        from datetime import datetime, timezone

        ctx = get_context()
        from ..execution import current_execution, target_in_run

        execution = current_execution()
        if execution is not None and execution.ctx is ctx:
            if run_id and run_id != execution.run_id:
                raise ValueError("finding run must match the executing run")
            run_id = execution.run_id
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        tgt = target.strip() if "://" in target else target.strip().lower()
        if run_id:
            if not target_in_run(target, ctx.runs.get(run_id)["target"]):
                raise ValueError("finding target must match its run target")
        # Audit the recording of a finding — findings carry evidence/PII, and the
        # evidentiary trail must show what was recorded, when, and at what severity.
        # (Audit 2026-07-27, SV5: add_finding was the one evidence-bearing op with
        # no audit trail.)
        ctx.audit.record("add_finding", tool="add_finding", target=tgt,
                         decision="record", severity=severity, title=title[:120])
        f = ctx.findings.add(target=tgt, severity=severity, title=title,
                             detail=detail, evidence=evidence, type=type, source="manual",
                             created_at=ts, run_id=run_id or None)
        # Mirror into the shared persistent memory hub as a CURATED item — a finding
        # is an asserted conclusion, not raw scraped content.
        mid = ctx.memory.add(kind="finding", title=title, body=(detail or evidence or ""),
                             target=tgt, severity=f.severity, source=type,
                             trust="curated", provenance="manual", tags="finding", created_at=ts)
        # Auto-link into the knowledge graph: a curated finding AFFECTS its host, and
        # (when the target is a URL) is ON a specific endpoint. This turns flat findings
        # into a queryable structure (memory_graph / memory_brief) without extra calls.
        host = _host_key(tgt)
        if host:
            ctx.memory.add_entity(kind="host", name=host, target=host, trust="curated")
            ctx.memory.add_relation(f"finding:{mid}", "affects", f"host:{host}", target=host)
            if "://" in tgt:
                from urllib.parse import urlsplit
                path = urlsplit(tgt).path or "/"
                ctx.memory.add_entity(kind="endpoint", name=path, target=host, trust="curated")
                ctx.memory.add_relation(f"finding:{mid}", "on", f"endpoint:{path}", target=host)
        return {"recorded": to_dict(f), "memory_id": mid, "summary": ctx.findings.summary()}

    @local
    async def promote_lead(target: str, kind: str, detail: str = "", evidence: str = "",
                           severity: str = "medium", record: bool = True) -> dict:
        """**Lead → PoC pipeline.** Turn an edge-probe's `review` lead into a confirmation
        plan: classifies the lead by `kind` (e.g. `multistep_bola`, `step_skip`,
        `value_tampering`, `race`, `path_bypass`, `cache_deception`, `sqli`, `ssrf`, …),
        routes it (**confirm_finding** for injection classes, **side-effect
        re-observation** for logic/authz/financial, a **Strix** PoC brief for smuggling),
        and states exactly what "confirmed" looks like. With `record`, files the lead into
        the findings store + shared memory so it's tracked and shared across agents. This is
        the bridge that converts the honest `review` leads into proven findings. Offline; no
        traffic. See `business_logic_hunt` for the hunting side.
        """

        from datetime import datetime, timezone

        ctx = get_context()
        tgt = target.strip()
        plan = leadpipemod.confirmation_plan(kind, tgt, detail)
        out: dict = {"target": tgt, **plan}
        if record:
            ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            store_target = normalize_target(tgt) if "://" in tgt else tgt.lower()
            f = ctx.findings.add(target=store_target, severity=severity,
                                 title=f"Lead ({plan['family']}): {plan['kind']} on {tgt}",
                                 type="lead", detail=detail, evidence=evidence,
                                 source="promote_lead", created_at=ts)
            # A lead is observed/asserted-by-a-tool, not a vetted conclusion → untrusted.
            mid = ctx.memory.add(kind="lead", title=f"{plan['kind']} on {tgt}",
                                 body=(detail or evidence or plan["confirmed_when"]),
                                 target=store_target, severity=severity, source="promote_lead",
                                 trust="untrusted", provenance="tool", tags=f"lead,{plan['family']}",
                                 created_at=ts)
            out["recorded"] = {"finding_id": f.id, "memory_id": mid}
        return out

    @local
    async def label_finding(finding_id: int, outcome: str) -> dict:
        """Label a recorded finding's real-world **outcome** — `true_positive`,
        `false_positive`, `duplicate`, `wont_fix`, or `unknown` — so `metrics` can compute
        detection precision on the live target. Use it after you verify (or refute) a lead
        on a real app. Offline; no traffic.
        """

        f = get_context().findings.set_outcome(finding_id, outcome)
        if f is None:
            return {"error": "not_found", "finding_id": finding_id,
                    "hint": "call list_findings to see recorded ids"}
        return {"labelled": to_dict(f)}

    @local
    async def metrics(known_positives: int | None = None) -> dict:
        """**Detection scorecard** for this session — measure how the probes actually do
        on a real target. Aggregates recorded findings by type / severity / source tool /
        outcome, computes **precision** (overall + per source tool) from the outcomes you
        set with `label_finding`, and reports per-tool run counts. Pass `known_positives`
        (your count of real bugs on the target) for a recall figure. Offline; no traffic.
        """

        ctx = get_context()
        runs: dict[str, int] = {}
        for e in ctx.audit.recent(0):  # a gated tool logs an allow'd scope_check per run
            if e.get("decision") == "allow" and e.get("tool"):
                runs[e["tool"]] = runs.get(e["tool"], 0) + 1
        return metricsmod.compute_metrics(ctx.findings.list(), runs=runs,
                                          known_positives=known_positives)

    @local
    async def list_findings(target: str | None = None, severity: str | None = None,
                            run_id: str | None = None) -> dict:
        """List recorded findings (optionally filtered by target or severity),
        severity-ranked, with a summary count. Reads the session findings store.
        """

        return get_context().findings.as_dict(target=target, severity=severity, run_id=run_id)

    @local
    async def clear_findings(target: str | None = None) -> dict:
        """Clear recorded findings — all of them, or just those for one target."""

        removed = get_context().findings.clear(target=target)
        return {"removed": removed, "summary": get_context().findings.summary()}

    @local
    async def triage_findings(apply: bool = False) -> dict:
        """**Deduplicate and prioritise** the session findings — the triage step before
        you write a report.

        Collapses exact-duplicate findings (same type + target + title), ranks the
        unique ones by severity then frequency, and surfaces **systemic** issues (the
        same finding across multiple targets — usually the highest-value report). Returns
        a triage view without changing anything; pass `apply=true` to actually collapse
        the duplicates in the store (evidence/sources are merged into the survivor).
        Feed the result to `report` / `export_findings` / `export_obsidian`.
        """

        ctx = get_context()
        out: dict[str, Any] = {"triage": ctx.findings.triage()}
        if apply:
            out["deduped"] = ctx.findings.dedupe()
            out["triage"] = ctx.findings.triage()
        return out

    @local
    async def cvss_score(vector: str | None = None, av: str | None = None, ac: str | None = None,
                         pr: str | None = None, ui: str | None = None, s: str | None = None,
                         c: str | None = None, i: str | None = None, a: str | None = None) -> dict:
        """Compute a **CVSS 3.1 base score** + severity band from a `vector`
        (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) and/or individual metrics
        (`av`/`ac`/`pr`/`ui`/`s`/`c`/`i`/`a`), so a confirmed finding carries a
        defensible standard severity. Metrics you omit default to a conservative
        low-impact base (C/I/A = None). Offline — pure calculation.
        """

        metrics = {k: v for k, v in (("AV", av), ("AC", ac), ("PR", pr), ("UI", ui),
                                     ("S", s), ("C", c), ("I", i), ("A", a)) if v}
        return cvssmod.base_score(metrics or None, vector=vector)

    @local
    async def export_obsidian(out_dir: str | None = None, include_kb: bool = True,
                              canvas: bool = True, engagement: str = "engagement",
                              dedupe: bool = True) -> dict:
        """Export the session into an **Obsidian vault** as a navigable knowledge
        graph: a Home MOC, one note per asset and finding (cross-linked, tagged by
        severity), and — with `include_kb` — the knowledge bases as a linked web
        (each vulnerability `[[wikilinks]]` to its **root cause**), plus an Obsidian
        **Canvas** (`.canvas`) graph. Also emits a Graphify-style `graph.json`
        (NetworkX node-link, provenance-tagged edges) and a `GRAPH_REPORT.md`
        ("god nodes"). By default `dedupe` collapses duplicate findings first so the
        graph stays clean. Open the folder as a vault and use the graph view. Writes to
        `out_dir` (or MOONMCP_VAULT_DIR, else ./moonmcp-vault); pure files, no network.
        """

        import os

        ctx = get_context()
        root = out_dir or os.environ.get("MOONMCP_VAULT_DIR") or os.path.join(os.getcwd(), "moonmcp-vault")
        src = ctx.findings.unique() if dedupe else ctx.findings.list()
        findings = [
            {"id": f.id, "target": f.target, "severity": f.severity, "title": f.title,
             "type": f.type, "detail": f.detail, "evidence": f.evidence, "created_at": f.created_at}
            for f in src
        ]
        inj: list[dict] | None = None
        vulns: list[dict] | None = None
        rc: list[dict] | None = None
        tech: list[dict] | None = None
        if include_kb:
            from ..knowledge.injections_data import INJECTIONS
            from ..knowledge.techniques_data import TECHNIQUES
            from ..knowledge.vulns_data import ROOT_CAUSES, SERVER_SIDE_VULNS

            inj, tech, rc, vulns = INJECTIONS, TECHNIQUES, ROOT_CAUSES, SERVER_SIDE_VULNS
        manifest = obsidianmod.build_vault(
            root, engagement=engagement, findings=findings, injections=inj, vulns=vulns,
            root_causes=rc, techniques=tech, want_canvas=canvas,
        )
        if dedupe:
            manifest["duplicates_folded"] = len(ctx.findings.list()) - len(src)
        ctx.audit.record("export_obsidian", tool="export_obsidian", target=root, decision="write")
        return manifest

    @local
    async def surface_diff(name: str, items: list[str]) -> dict:
        """Track how the attack surface **changes** over time. Pass a snapshot `name`
        (e.g. `acme-subdomains`) and the current list of `items` (subdomains, live
        hosts, endpoints, params). The first call sets the baseline; every later call
        returns only what was **added** / **removed** since last time — the fresh,
        under-competed surface. Persists across runs if MOONMCP_STATE_DIR is set.
        """

        return get_context().snapshots.diff(name, items)

    @local
    async def surface_snapshots(clear: str | None = None) -> dict:
        """List the tracked surface snapshots (name → item count), or clear one by
        name (or all with `clear="*"`).
        """

        ctx = get_context()
        if clear is not None:
            removed = ctx.snapshots.clear(None if clear == "*" else clear)
            return {"cleared": removed, "snapshots": ctx.snapshots.names()}
        return {"snapshots": ctx.snapshots.names()}

    @local
    async def export_findings(format: str = "sarif", target: str | None = None,
                              severity: str | None = None,
                              enhanced: bool = True) -> dict:
        """Export the recorded findings in a machine-readable format for CI / triage.

        `format`: `sarif` (SARIF 2.1.0 — GitHub code-scanning / most DAST pipelines)
        or `json` (the raw findings + summary). Optionally filter by `target` /
        `severity`. Returns the document inline; no network.

        `enhanced=True` (default) uses the Strix-derived SARIF format with DAST
        support (CWE-based rules, logicalLocations for endpoints, fixes array,
        security-severity for GitHub code-scanning ranking). Set `enhanced=False`
        for the basic SARIF format.
        """

        ctx = get_context()
        fmt = format.strip().lower()
        findings = [
            {"id": f.id, "target": f.target, "severity": f.severity, "title": f.title,
             "type": f.type, "detail": f.detail, "evidence": f.evidence,
             "source": f.source, "created_at": f.created_at}
            for f in ctx.findings.list(target=target, severity=severity)
        ]
        if fmt == "json":
            return {"format": "json", "summary": ctx.findings.summary(), "findings": findings}
        if fmt == "sarif":
            if enhanced:
                sarif_doc = sa.format_sarif_enhanced(findings, version=__version__)
            else:
                sarif_doc = format_sarif(findings, version=__version__)
            return {"format": "sarif", "enhanced": enhanced, "sarif": sarif_doc}
        return {"error": "invalid_input", "detail": f"unknown format '{format}' (use sarif or json)"}

    return exported
