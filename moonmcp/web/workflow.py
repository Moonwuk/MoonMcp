"""Workflow / step-skipping abuse — multi-step business-flow bypass.

Another thing a stateless template scanner cannot express: a business flow is an
*ordered* sequence (cart → address → payment → confirm; register → verify → access;
reset-request → verify-token → set-password) whose security depends on the server
enforcing the order. The classic logic bug is **force-browsing to a later step**:
jump straight to the "confirm"/"success"/"download" step without completing the
earlier ones — order confirmed without payment, account activated without email
verification, password set without the token.

Detection (safe): fetch each *later* step directly, without having driven the prior
ones. A flow that enforces its sequence answers with a redirect back / a "complete
the previous step" error / a 4xx; a broken one hands you the step's success content.
The agent supplies the ordered steps (it understands the app); this drives the
mechanical check and returns ``review`` leads (confirm the business effect).
"""

from __future__ import annotations

from collections.abc import Callable

# Body language that means the flow REJECTED an out-of-order jump (i.e. it is enforced).
_ENFORCE_MARKERS = (
    "complete the previous", "must complete", "previous step", "start over",
    "session expired", "invalid step", "out of order", "not allowed", "begin the",
    "please log in", "no items in", "empty cart", "step 1", "restart",
)


def normalize_steps(steps) -> list[dict]:
    """Coerce a flow spec (list of URL strings and/or step dicts) into step dicts.

    Each step: ``{name, url, method, body, success}`` — ``success`` is an optional
    marker string that positively identifies that step's completed content."""

    out: list[dict] = []
    for i, s in enumerate(steps or []):
        if isinstance(s, str):
            s = {"url": s}
        if not isinstance(s, dict) or not s.get("url"):
            continue
        out.append({
            "name": s.get("name") or f"step{i + 1}",
            "url": s["url"],
            "method": (s.get("method") or "GET").upper(),
            "body": s.get("body"),
            "success": s.get("success") or s.get("success_marker"),
        })
    return out


def assess_step_skip(status: int | None, body_text: str, *, success_marker: str | None = None) -> bool:
    """Was a later step reached cold? True = 2xx and the flow did NOT enforce order."""

    if status is None or not (200 <= status < 300):
        return False  # redirect / 4xx / 5xx → the sequence was enforced
    low = (body_text or "").lower()
    if any(m in low for m in _ENFORCE_MARKERS):
        return False  # 2xx but the body says "finish the previous step"
    if success_marker:
        return success_marker.lower() in low
    return True  # 2xx, no enforcement language → the step was served cold


async def probe_workflow_skip(client, steps, *, scope_check: Callable[[str], bool] | None = None) -> dict:
    """Fetch each step after the first *cold* (without completing the prior steps)
    and flag the ones the server serves anyway — workflow step-skipping."""

    norm = normalize_steps(steps)
    n = len(norm)
    findings: list[dict] = []
    for k, step in enumerate(norm):
        if k == 0:
            continue  # the entry step is always reachable
        body = step["body"].encode() if isinstance(step["body"], str) else step["body"]
        r = await client.fetch(step["url"], method=step["method"], body=body,
                               follow_redirects=False, timeout=12.0, scope_check=scope_check)
        text = r.text(limit=50_000) if r.status is not None else ""
        if assess_step_skip(r.status, text, success_marker=step["success"]):
            terminal = k == n - 1
            findings.append({
                "step": step["name"], "position": f"{k + 1}/{n}", "url": step["url"],
                "status": r.status, "terminal": terminal,
                "severity": "high" if terminal else "medium", "verdict": "review",
                "detail": (f"reached '{step['name']}' ({k + 1}/{n}) cold — without completing the "
                           f"prior {k} step(s) — workflow step-skipping / broken sequence enforcement"
                           + ("; this is the terminal/success step — confirm the business effect "
                              "(e.g. order confirmed without payment, account activated without "
                              "verification)" if terminal else "")),
            })
    return {
        "steps": [s["name"] for s in norm], "step_count": n, "findings": findings,
        "verdict": "review" if findings else "no_step_skip",
    }
