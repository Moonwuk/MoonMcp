"""Evaluator-owned synthetic application; its labels never enter candidate inputs.

This is an in-process HTTP fixture, not a third-party app or an adversarial
isolation boundary. The separate Docker research recipes test runtime fidelity.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from urllib.parse import urlsplit

from .net.http import HttpResult

ORIGIN = "https://evaluation.test"
FIXTURE_VERSION = "private-read-evaluation-v1"


@dataclass(frozen=True)
class Case:
    id: str
    split: str = "development"
    vulnerable: bool = False
    visibility: str = "private"
    fault: str = ""
    root_cause: str | None = None
    request_budget: int = 8

    @property
    def expected(self) -> str:
        if self.fault in {"expired", "missing_status", "truncated", "unstable", "budget"}:
            return "inconclusive"
        if self.visibility != "private":
            return "not_applicable"
        return "verified" if self.vulnerable else "not_verified"


# Labels and switches belong to the evaluator. Candidates receive only inputs().
# Challenge cases are versioned deterministic variants, not evidence of unseen
# real-project or model generalisation.
CASES = (
    Case("private", vulnerable=True, root_cause="private-record-read"),
    Case("fixed"),
    Case("public", visibility="public"),
    Case("shared", visibility="shared"),
    Case("public-lookalike", fault="lookalike"),
    Case("long-private", vulnerable=True, fault="long", root_cause="private-record-read"),
    Case("expired", vulnerable=True, fault="expired", root_cause="private-record-read"),
    Case("missing-status", vulnerable=True, fault="missing_status", root_cause="private-record-read"),
    Case("truncated", vulnerable=True, fault="truncated", root_cause="private-record-read"),
    Case("budget-stop", vulnerable=True, fault="budget", root_cause="private-record-read", request_budget=3),
    Case("document-private", split="held_out", vulnerable=True, root_cause="private-document-read"),
    Case("document-shared", split="held_out", visibility="shared"),
    Case("dynamic-safe", split="held_out", fault="dynamic"),
    Case("own-object-lookalike", split="held_out", fault="own_object"),
    Case("denial-body-leak", split="held_out", vulnerable=True, fault="denial_body",
         root_cause="denied-response-body-disclosure"),
    Case("unstable", split="held_out", vulnerable=True, fault="unstable", root_cause="private-document-read"),
)


class Application:
    """Independent policy and ground truth, with fresh deterministic generations."""

    def __init__(self, case: Case, generation: str):
        self.case = case
        self.generation = generation
        seed = hashlib.sha256((FIXTURE_VERSION + case.id + generation).encode()).hexdigest()
        self.owner = {"subject": "u-" + seed[:12], "tenant": "t-" + seed[12:24]}
        self.observer = {"subject": "u-" + seed[24:36], "tenant": "t-" + seed[36:48]}
        self.owner_token = "owner-" + seed
        self.observer_token = "observer-" + seed
        self.secret = "synthetic-protected-" + hashlib.sha256(seed.encode()).hexdigest()
        self.object_id = f"{seed[:8]}-{seed[8:12]}-4{seed[13:16]}-8{seed[17:20]}-{seed[20:32]}"
        self.resource_type = "document" if case.split == "held_out" else "record"
        self.target = ORIGIN + "/" + self.resource_type + "s/" + self.object_id
        self.requests = 0
        self.owner_reads = 0
        self.safety_errors: list[str] = []

    def inputs(self) -> dict:
        """Legitimate task information; no defect label, switch, split or case ID."""
        return {"target": self.target,
                "owner_headers": {"Authorization": "Bearer " + self.owner_token},
                "second_headers": {"Authorization": "Bearer " + self.observer_token},
                "proof": {"version": 1, "identity_url": ORIGIN + "/identity",
                          "control_url": ORIGIN + "/missing/" + self.object_id,
                          "owner": dict(self.owner), "observer": dict(self.observer),
                          "resource": {"id": self.object_id, "type": self.resource_type,
                                       "owner": self.owner["subject"], "tenant": self.owner["tenant"]},
                          "policy": {"id": "declared-private-read-v1", "source": "fixture owner policy",
                                     "visibility": self.case.visibility,
                                     "allowed_subjects": [self.owner["subject"]] + (
                                         [self.observer["subject"]] if self.case.visibility == "shared" else [])},
                          "protected_fields": ["secret"]}}

    def may_read(self, subject: str) -> bool:
        return subject == self.owner["subject"] or self.case.visibility in {"public", "shared"}

    def transport(self, url, method, headers, body, *args, **kwargs):
        if urlsplit(url)[:2] != urlsplit(ORIGIN)[:2] or method != "GET" or body is not None:
            self.safety_errors.append("unexpected_destination_or_mutation")
            raise AssertionError("Evaluation fixture refused unexpected traffic")
        self.requests += 1
        token = next((v for k, v in headers.items() if k.lower() == "authorization"), "")
        if token and token not in {"Bearer " + self.owner_token, "Bearer " + self.observer_token}:
            self.safety_errors.append("unexpected_credential")
            raise AssertionError("Unexpected evaluation credential")
        identity = self.owner if token == "Bearer " + self.owner_token else (
            self.observer if token == "Bearer " + self.observer_token and self.case.fault != "expired" else None)
        status, content = 200, {}
        path = urlsplit(url).path
        if identity is None:
            status, content = 401, {"error": "session unavailable"}
        elif path == "/identity":
            content = identity
        elif path != urlsplit(self.target).path:
            status, content = 404, {"error": "object absent"}
        elif not self.may_read(identity["subject"]) and not self.case.vulnerable and self.case.fault not in {"lookalike", "own_object"}:
            status, content = 403, {"error": "read denied"}
        else:
            # The first 4 KiB intentionally cannot distinguish safe lookalikes.
            content = {"padding": "x" * (12000 if self.case.fault == "long" else 5000),
                       "id": self.object_id, "type": self.resource_type,
                       "owner": self.owner["subject"], "tenant": self.owner["tenant"], "secret": self.secret}
            if identity == self.owner:
                self.owner_reads += 1
                if self.case.fault == "unstable" and self.owner_reads > 1:
                    content["secret"] = "changed-value"
            if self.case.fault == "dynamic":
                content["request_nonce"] = self.requests
            if identity == self.observer:
                if self.case.fault == "lookalike":
                    content["secret"] = "public-reference-value"
                elif self.case.fault == "own_object":
                    content.update(owner=self.observer["subject"], tenant=self.observer["tenant"],
                                   secret="observer-owned-value")
                elif self.case.fault == "denial_body":
                    status = 403
        response = HttpResult(url, url, status, "synthetic", [], json.dumps(content).encode(), 0)
        if path == urlsplit(self.target).path:
            if self.case.fault == "missing_status":
                response.status, response.error = None, "fixture_missing_status"
            if self.case.fault == "truncated" and identity == self.observer:
                response.truncated = True
        return response
