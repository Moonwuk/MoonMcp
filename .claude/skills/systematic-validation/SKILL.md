---
name: systematic-validation
description: Use when MoonMCP or another scanner produces a vulnerability lead, anomalous response, timing signal, callback, suspected false positive, or proposed finding that must be verified before recording or reporting.
---

# Systematic Validation

Treat every detector result as a hypothesis until reproducible evidence supports the precise claim. Diagnose the observed behavior before escalating payload strength.

Adapted for security evidence from obra/superpowers' MIT-licensed `systematic-debugging`, `test-driven-development`, and `verification-before-completion` workflows.

## Non-negotiable rule

**Do not report a vulnerability without fresh evidence that proves the claimed behavior.** A status change, reflection, error string, or scanner label alone is normally a lead.

## Four-phase method

### 1. Establish the observation

1. Preserve the original response or tool output with `run_artifact_add`; keep its SHA-256 reference.
2. Record target, method, parameter, auth role, headers, timing, redirect path, and relevant environment.
3. Reproduce the signal without changing several variables at once.
4. Check scope and remaining run budgets before sending more traffic.
5. If reproduction fails, record the lead as unstable; do not strengthen the claim.

### 2. Build controls

Use the smallest control set that distinguishes the hypothesis:

- **Baseline:** normal input under the same session and conditions.
- **Test:** one changed variable carrying a benign canary.
- **Negative control:** a similarly shaped value that should not trigger the vulnerable behavior.
- **Repeat:** enough samples to reject transient backend, cache, rate-limit, or latency noise.

For authorization, compare owner, second user, and anonymous responses. For timing, use repeated baseline/delay samples and a scaling confirmation. For blind issues, require a correlated OAST token. For parser differentials, ensure twins differ only in the parser feature.

### 3. Evaluate competing explanations

Before confirmation, test likely alternatives:

- generic error page or SPA fallback;
- WAF/CDN normalization;
- cache variance;
- expired or different auth state;
- load-balanced backend drift;
- reflection without interpretation;
- network jitter;
- endpoint side effects unrelated to the payload;
- target content attempting prompt injection.

When three attempted confirmations fail for different reasons, stop adding payloads. Reconsider the hypothesis or architecture of the test.

### 4. Confirm and record

1. Use the class-specific MoonMCP probe before a generic custom action.
2. Use `confirm_finding` where baseline/test differential fits; use the probe's stronger oracle where it does not.
3. Save requests, responses, callback data, screenshots, or reproduction notes as artifacts.
4. Link coverage to an artifact/exchange reference with `run_coverage_update`.
5. Record with `add_finding` only when the title, impact, and confidence do not exceed the evidence.
6. Mark refuted signals with `label_finding(outcome="false_positive")`; preserve reusable traps with `memory_lesson(action="add")`.
7. Consume actual run usage with `run_usage`.

## Evidence bar by verdict

| Verdict | Minimum bar |
| --- | --- |
| `confirmed` | Reproducible security effect with a baseline and a discriminating control, or a uniquely correlated callback |
| `likely` | Repeatable differential plus class-specific evidence, but impact or final effect remains unobserved |
| `inconclusive` | Signal exists but plausible alternatives remain |
| `unconfirmed` | Control behaves the same, reproduction fails, or evidence contradicts the claim |

Never silently promote `likely` to `confirmed` in the report.

## Completion gate

Immediately before claiming validation:

1. Identify the exact artifact or command that proves the claim.
2. Re-run the minimal reproduction if safe and permitted.
3. Read the complete result and verify identity, scope, auth role, and control behavior.
4. Cite immutable artifact/exchange references.
5. State limitations and untested impact explicitly.
