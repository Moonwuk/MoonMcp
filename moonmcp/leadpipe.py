"""Lead → PoC pipeline — turn an edge-probe's ``review`` lead into a confirmation plan.

Every MoonMCP edge probe (authz_probe, workflow_probe, race_probe,
path_bypass_probe, cache_deception_probe, the injection probes, …) emits *leads*, not
confirmations. That is honest, but the bug-bounty value only materializes if a lead is
driven to a proven finding — the coverage audit calls this pipeline the real deliverable.

This module is that bridge. It classifies a lead by its ``kind``, routes it to the right
confirmation path — ``confirm_finding`` for the mechanically-differential injection
classes, direct **side-effect re-observation** for the logic/authz/financial classes, or
an autonomous **Strix** PoC (under human confirmation) for smuggling — and states exactly
what "confirmed" looks like. Pure/offline; the ``promote_lead`` tool records the lead to
findings + shared memory and returns this plan.
"""

from __future__ import annotations

# kind -> (family, route, confirmed_when). route ∈ {confirm_finding, observe, strix}.
_ROUTES: dict[str, tuple[str, str, str]] = {
    # ── injection classes → confirm_finding (differential + OAST) ──
    "sqli": ("injection", "confirm_finding",
             "a payload-only response/timing change or a DB/OAST signal absent from the baseline"),
    "xss": ("injection", "confirm_finding",
            "the payload executes in browser_open/browser_eval (alert/DOM change), not just reflects"),
    "ssti": ("injection", "confirm_finding",
             "a template-evaluated result (e.g. 49 from {{7*7}}) appears in the response"),
    "crlf": ("injection", "confirm_finding",
             "the injected header/cookie surfaces as a real response header, not body text"),
    "ssrf": ("injection", "confirm_finding",
             "an OAST callback from the target (oast_poll) or a cloud-metadata credential signature"),
    "open_redirect": ("injection", "confirm_finding",
                      "a 3xx Location to the attacker origin carrying the victim context"),
    "xxe": ("injection", "confirm_finding", "an OAST callback or out-of-band file content"),
    # ── authorization / IDOR → re-observe as the other identity ──
    "direct_bola": ("authorization", "observe",
                    "the second/anon identity retrieves the SAME private object as the owner"),
    "sibling_idor": ("authorization", "observe",
                     "the identity reads a neighbouring object that is provably another user's data"),
    "multistep_bola": ("authorization", "observe",
                       "an object id the owner exposed is retrievable as a different identity"),
    "mass_assignment": ("authorization", "observe",
                        "the privileged field persists — re-read the object shows role/balance changed"),
    # ── workflow ──
    "step_skip": ("workflow", "observe",
                  "the terminal step's side effect occurs without the prerequisites "
                  "(e.g. order placed without payment, account activated without verification)"),
    # ── financial / value ──
    "value_tampering": ("financial", "observe",
                        "the transaction commits with the tampered value (wrong amount charged/credited)"),
    "parameter_tampering": ("financial", "observe",
                            "the server accepts the invalid value in the committed transaction"),
    "currency_swap": ("financial", "observe",
                      "the transaction is charged in the swapped currency at the original amount"),
    "coupon_reuse": ("financial", "observe",
                     "the single-use code applies its discount/credit more than once"),
    # ── race ──
    "race": ("race", "observe",
             "the one-time action's side effect happened more than once (balance/coupon/vote count)"),
    # ── account takeover ──
    "secret_in_body": ("ato", "observe",
                       "the in-band OTP/reset token actually authenticates or resets the account"),
    "reset_link_in_body": ("ato", "observe", "the leaked reset link resets the account password"),
    "reset_poison": ("ato", "observe",
                     "the reset email/token is delivered to the attacker-controlled host"),
    # ── cache / authz bypass ──
    "cache_deception": ("cache", "observe",
                        "a cookieless client retrieves the cached private page (private content + cache-HIT)"),
    "path_bypass": ("authz-bypass", "observe",
                    "the 2xx normalization twin returns the REAL protected content, not a generic page"),
    # ── smuggling → Strix (never auto-weaponized) ──
    "desync": ("smuggling", "strix",
               "a smuggled request reaches a second victim connection — hand to Strix / Turbo Intruder"),
}

_NEXT_STEP: dict[str, str] = {
    "confirm_finding": "run confirm_finding with the payload/param to prove it differentially (+ OAST)",
    "observe": "re-drive the flow and directly observe the side effect (Strix can automate this)",
    "strix": "hand off to Strix for autonomous PoC under human confirmation",
}


def classify_lead(kind: str) -> dict:
    """Map a lead ``kind`` to its confirmation family / route / success criterion."""

    k = (kind or "").strip().lower()
    fam, route, when = _ROUTES.get(
        k, ("general", "observe", "reproduce the reported behaviour and demonstrate concrete impact"))
    return {"kind": k, "family": fam, "route": route, "confirmed_when": when,
            "needs_strix": route == "strix"}


def strix_brief(kind: str, target: str, detail: str = "") -> str:
    """A ready-to-run, safety-bounded Strix task that reproduces + proves the lead."""

    info = classify_lead(kind)
    d = (detail or "").strip() or "n/a"
    return (f"Reproduce and produce a MINIMAL, non-destructive proof-of-concept for a "
            f"{info['family']} finding ({info['kind']}) on {target}. Lead detail: {d}. "
            f"Confirmed when: {info['confirmed_when']}. Constraints: stay in scope; stop at proof; "
            f"cause no data loss, account damage, or denial of service; report the exact request(s) "
            f"and the observed side effect.")


def confirmation_plan(kind: str, target: str, detail: str = "") -> dict:
    """The full plan: family, route, next concrete step, success criterion, Strix brief."""

    info = classify_lead(kind)
    return {**info, "target": target, "next_step": _NEXT_STEP[info["route"]],
            "strix_brief": strix_brief(kind, target, detail)}
