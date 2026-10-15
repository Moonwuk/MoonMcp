"""Bounded private-object read verification under a caller-declared policy.

This adapter supports flat JSON identity/object endpoints on one origin. It does
not discover policy or authenticate users. The existing HTTP client supplies
scope enforcement, actual-send accounting and durable execution cancellation.
"""

from __future__ import annotations

import hashlib
import json
from urllib.parse import urlsplit

from .checks import ProbeChecks


def _digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode()).hexdigest()


def _origin(url: str) -> tuple:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Proof URLs must be HTTP(S) URLs without embedded credentials.")
    return parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)


def _validate(target: str, spec: dict, second_headers: dict | None, owner_headers: dict | None) -> None:
    if spec.get("version") != 1:
        raise ValueError("proof.version must be 1")
    for key in ("owner", "observer", "resource", "policy"):
        if not isinstance(spec.get(key), dict):
            raise ValueError(f"proof.{key} must be an object")
    for key, expected in (("owner", {"subject", "tenant"}),
                          ("observer", {"subject", "tenant"}),
                          ("resource", {"id", "type", "owner", "tenant"}),
                          ("policy", {"id", "source", "visibility", "allowed_subjects"})):
        if set(spec[key]) != expected:
            raise ValueError(f"proof.{key} has missing or unsupported fields")
    for key in ("owner", "observer"):
        if not all(isinstance(spec[key].get(k), str) and spec[key][k].strip()
                   for k in ("subject", "tenant")):
            raise ValueError(f"proof.{key} requires nonempty subject and tenant strings")
    if spec["owner"]["subject"] == spec["observer"]["subject"]:
        raise ValueError("Proof requires distinct owner and observer subjects")
    resource = spec["resource"]
    if not all(isinstance(resource.get(k), str) and resource[k].strip()
               for k in ("id", "type", "owner", "tenant")):
        raise ValueError("proof.resource requires id, type, owner and tenant strings")
    if resource["owner"] != spec["owner"]["subject"] or resource["tenant"] != spec["owner"]["tenant"]:
        raise ValueError("Resource ownership must match the declared owner identity")
    policy = spec["policy"]
    if not all(isinstance(policy.get(k), str) and policy[k].strip() for k in ("id", "source")):
        raise ValueError("proof.policy requires an id and declared source")
    if policy.get("visibility") not in {"private", "public", "shared"}:
        raise ValueError("proof.policy.visibility must be private, public or shared")
    subjects = policy.get("allowed_subjects")
    if not isinstance(subjects, list) or not subjects or not all(isinstance(s, str) and s for s in subjects):
        raise ValueError("proof.policy.allowed_subjects must be a nonempty string list")
    if spec["owner"]["subject"] not in subjects:
        raise ValueError("Declared policy must allow the owner to read the resource")
    fields = spec.get("protected_fields")
    if (not isinstance(fields, list) or not 1 <= len(fields) <= 16
            or not all(isinstance(k, str) and k and k not in {"id", "type", "owner", "tenant"} for k in fields)
            or len(set(fields)) != len(fields)):
        raise ValueError("proof.protected_fields must contain 1–16 distinct non-metadata JSON field names")
    origin = _origin(target)
    for key in ("identity_url", "control_url"):
        url = spec.get(key)
        if not isinstance(url, str) or _origin(url) != origin:
            raise ValueError(f"proof.{key} must be on the target origin")
    if len({target, spec["identity_url"], spec["control_url"]}) != 3:
        raise ValueError("Object, identity and known-missing control URLs must differ")
    if not owner_headers or not second_headers:
        raise ValueError("Proof requires engagement owner auth and explicit second_headers")
    if {k.lower(): v for k, v in owner_headers.items()} == {k.lower(): v for k, v in second_headers.items()}:
        raise ValueError("Owner and observer credentials must differ")


async def verify_private_read(client, target: str, spec: dict, *, owner_headers: dict,
                              second_headers: dict | None, scope_check=None) -> dict:
    """Observe live identities, bound object fields and controls, then recheck stability.

    No raw response bodies, protected values or authentication headers are returned.
    A second invocation with a new key is required for a fresh independent replay.
    """
    _validate(target, spec, second_headers, owner_headers)
    checks = ProbeChecks()
    policy = spec["policy"]
    result: dict = {"target": target, "findings": [], "proof": {
        "version": 1, "claim": "private_object_read", "verified": False,
        "policy_id": policy["id"], "policy_sha256": _digest(policy),
        "manifest_sha256": _digest(spec), "resource": spec["resource"],
        "owner": spec["owner"], "observer": spec["observer"],
        "limitations": ["Policy and known-missing control are caller-declared, not inferred.",
                        "Flat JSON fields on one origin only; no general session/role discovery.",
                        "A fresh independently prepared replay is required before external reporting."],
    }}
    if policy["visibility"] != "private" or spec["observer"]["subject"] in policy["allowed_subjects"]:
        result.update(result_version=2, ok=True, state="completed", verdict="not_applicable",
                      reason="Declared policy does not prohibit this observer's read.")
        return result

    async def fetch(url: str, check: str, identity: str):
        headers = owner_headers if identity == "owner" else second_headers
        response = await checks.fetch(client, url, check=check, identity=identity,
                                       headers=headers, suppress_auth=True, method="GET",
                                       follow_redirects=False, timeout=12, max_body=512 * 1024,
                                       scope_check=scope_check)
        if response is not None:
            checks.items[-1]["body_sha256"] = hashlib.sha256(response.body).hexdigest()
        return response

    def read_json(response, check: str) -> dict | None:
        if response is None:
            return None
        try:
            data = json.loads(response.body) if 200 <= response.status < 300 else None
            if not isinstance(data, dict):
                raise ValueError()
            # Canonicalisation rejects nonstandard NaN/Infinity values too.
            _digest(data)
            return data
        except (ValueError, UnicodeError, RecursionError):
            checks.missing(check, "expected_complete_json_object")
            return None

    def finished():
        return checks.finish(result, negative="not_verified")

    async def live(identity: str, phase: str) -> bool:
        check = f"{identity}_identity_{phase}"
        body = read_json(await fetch(spec["identity_url"], check, identity), check)
        expected = spec[identity]
        if body is None:
            return False
        if any(body.get(k) != expected[k] for k in ("subject", "tenant")):
            checks.missing(check, "identity_mismatch", identity=identity)
            return False
        return True

    for identity in ("owner", "observer"):
        if not await live(identity, "before"):
            return finished()
    owned = read_json(await fetch(target, "owner_object", "owner"), "owner_object")
    if owned is None:
        return finished()
    if any(owned.get(k) != value for k, value in spec["resource"].items()):
        checks.missing("owner_object", "resource_binding_mismatch")
        return finished()
    fields = spec["protected_fields"]
    if any(owned.get(k) in (None, "", [], {}) for k in fields):
        checks.missing("owner_object", "protected_fields_unavailable")
        return finished()

    observed_response = await fetch(target, "observer_object", "observer")
    if observed_response is None:
        return finished()
    denied = observed_response.status in {401, 403, 404}
    if denied:
        # An error status does not undo a leak in the response body. Ordinary
        # non-JSON denials remain valid negative observations, not parse failures.
        try:
            data = json.loads(observed_response.body)
            _digest(data)
            observed = data if isinstance(data, dict) else None
        except (ValueError, UnicodeError, RecursionError):
            observed = None
    else:
        observed = read_json(observed_response, "observer_object")
    if not denied and observed is None:
        return finished()
    control = await fetch(spec["control_url"], "missing_object_control", "observer")
    if control is None:
        return finished()
    if control.status != 404:
        checks.missing("missing_object_control", "control_not_missing")
        return finished()
    for identity in ("owner", "observer"):
        if not await live(identity, "after"):
            return finished()
    stable = read_json(await fetch(target, "owner_object_after", "owner"), "owner_object_after")
    if stable is None:
        return finished()
    compared_fields = [*spec["resource"], *fields]
    expected_fields = _digest({k: owned[k] for k in compared_fields})
    if _digest({k: stable.get(k) for k in compared_fields}) != expected_fields:
        checks.missing("owner_object_after", "resource_changed_during_check")
        return finished()
    verified = observed is not None and _digest({k: observed.get(k) for k in compared_fields}) == expected_fields
    result["proof"]["verified"] = verified
    if verified:
        result["proof"]["matched_protected_fields"] = fields
        result["findings"] = [{"kind": "verified_private_read", "verdict": "verified",
                               "severity": "high", "url": target,
                               "detail": "The live observer received the bound private object and protected fields contrary to the declared policy."}]
    final = finished()
    if verified and final["ok"]:
        final["verdict"] = "verified"
    return final
