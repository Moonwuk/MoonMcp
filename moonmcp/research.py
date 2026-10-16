"""Opt-in, single-recipe HTTP replay with durable intent and checked cleanup.

This controller prepares a synthetic fixture. It is not an autonomous discovery
agent or an arbitrary project runner. Portable capsules are data, never code.
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
import secrets
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from .execution import current_execution
from .net.http import HttpClient
from .net.ratelimit import Governor
from .research_runtime import APP, IMAGE, HTTPRelay, ResearchSandbox
from .runs import RunBudget, RunStore
from .web.bola_proof import verify_private_read

CASES = {"private_vulnerable", "private_fixed", "public", "shared"}
RECIPE = "sqlite-orders-v1"


def capsule(case: str) -> dict:
    if case not in CASES:
        raise ValueError("Unsupported recipe case")
    return {"version": 1, "recipe": RECIPE, "case": case, "image": IMAGE,
            "application_sha256": hashlib.sha256(APP.read_bytes()).hexdigest(),
            "entrypoint": "normal_http", "storage": "sqlite"}


def validate_capsule(value: dict) -> dict:
    if not isinstance(value, dict) or not isinstance(value.get("case"), str):
        raise ValueError("Capsule must identify a supported case")
    expected = capsule(value["case"])
    if (set(value) != set(expected) or type(value.get("version")) is not int
            or value != expected):
        raise ValueError("Capsule does not match the installed trusted recipe")
    return expected


def describe() -> dict:
    return {"ok": True, "recipe": RECIPE, "cases": sorted(CASES),
            "capsules": [capsule(case) for case in sorted(CASES)],
            "requires": ["execute=true", "persistent MOONMCP_STATE_DIR", "local Linux Docker",
                         f"preloaded image: {IMAGE}"],
            "limits": {"concurrent_per_state_dir": 1, "wall_seconds": 180,
                       "requests": 32, "docker_output_bytes": 32768},
            "fidelity": "Separate HTTP process and SQLite; setup through registration/login/create routes.",
            "limitations": ["Synthetic known cases; no autonomous discovery benchmark.",
                            "No arbitrary projects, images, commands, mounts or outbound networking.",
                            "Docker shares the host kernel; this is not a VM security boundary."]}


def _root(store: RunStore) -> Path:
    if store.path == ":memory:":
        raise ValueError("Research execution requires persistent MOONMCP_STATE_DIR")
    return Path(store.path).resolve().parent / "research"


@contextlib.contextmanager
def _exclusive(root: Path):
    # A host lock supplements task leases: an expired worker must actually release
    # the controller before recovery can remove its resources. Survives SIGKILL.
    import fcntl
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if root.is_symlink() or root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o077:
        raise ValueError("Research state directory must be private and owned by this user")
    fd = os.open(root / ".controller.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("Another research controller is active; do not replay") from None
        yield
    finally:
        os.close(fd)  # retain the lock inode to avoid unlock/unlink races


def _artifact(store: RunStore, run_id: str, kind: str, value: dict) -> dict:
    return store.add_artifact(run_id, kind, kind + ".json", json.dumps(value, sort_keys=True))


async def _settle(task: asyncio.Task, on_cancel=None):
    """Do not abandon a worker that can still create resources during cancellation."""
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            if on_cancel is not None:
                on_cancel()
            continue
    return task.result()


async def replay(store: RunStore, manifest: dict, *, execute: bool = False) -> dict:
    manifest = validate_capsule(manifest)
    if not execute:
        return {"ok": True, "executed": False, "capsule": manifest, "requirements": describe()["requires"]}
    if current_execution() is not None:
        raise ValueError("Use research_environment directly, outside run_execute")
    root = _root(store)
    run = store.create("127.0.0.1", focus="synthetic HTTP replay", budget=RunBudget(32, 2, 0))
    run_id = run["id"]
    task = store.add_task(run_id, "Prepare and independently replay SQLite recipe", role="validator")
    owner = uuid.uuid4().hex
    claim = store.claim_task(run_id, owner, task_id=task["id"], lease_seconds=60)
    assert claim is not None
    lease = {"owner": owner, "claim_token": claim["claim_token"]}
    ident = uuid.uuid4().hex
    resource = {"version": 1, "id": ident, "container": f"moonmcp-lab-{ident}",
                "variant": "vulnerable" if manifest["case"] == "private_vulnerable" else "fixed",
                "task_id": task["id"], "recipe": RECIPE}
    # Commit the resource identity BEFORE mkdir, Docker, relay or application I/O.
    ref = _artifact(store, run_id, "research_resource", resource)
    capsule_ref = _artifact(store, run_id, "research_capsule", manifest)
    sandbox = ResearchSandbox(resource, root)
    result = {"ok": False, "executed": True, "state": "unknown", "run_id": run_id,
              "resource": ref, "capsule_artifact": capsule_ref, "capsule": manifest,
              "retryable": False}
    relay = None
    phase_id = ""
    metrics: dict = {}

    def admit(url: str):
        if relay is None or urlsplit(url)[:2] != urlsplit(relay.base_url)[:2]:
            raise ValueError("Recipe HTTP request left its loopback origin")
        store.consume_invocation_request(phase_id)

    http = HttpClient(Governor(rate=0, max_concurrency=2), user_agent="MoonMCP-research/1",
                      connect_pin=lambda host: (None, "127.0.0.1"), before_send=admit, direct=True)
    prepared: dict = {}

    async def request(path, *, method="GET", payload=None, token=None, status=200):
        assert relay is not None
        response = await http.fetch(relay.base_url + path, method=method,
                                    headers={"Content-Type": "application/json", **(
                                        {"Authorization": "Bearer " + token} if token else {})},
                                    body=json.dumps(payload).encode() if payload is not None else None,
                                    timeout=5, max_body=16384, follow_redirects=False,
                                    suppress_auth=True)
        if response.status != status or response.truncated or response.error:
            raise ValueError("Normal HTTP workflow did not meet its contract")
        return json.loads(response.body)

    async def prepare():
        # Readiness is bounded and counts actual HTTP dispatches, including failures.
        for attempt in range(10):
            try:
                if await request("/health") == {"ready": True, "storage": "sqlite"}:
                    break
            except ValueError:
                if attempt == 9:
                    raise
            await asyncio.sleep(.1)
        else:
            raise ValueError("Application readiness was not established")
        identities, tokens = [], []
        for _ in range(2):
            identity = {"subject": secrets.token_hex(12), "tenant": secrets.token_hex(12)}
            password = secrets.token_urlsafe(32)
            await request("/register", method="POST", payload={**identity, "password": password}, status=201)
            logged = await request("/login", method="POST", payload={"subject": identity["subject"], "password": password})
            identities.append(identity)
            tokens.append(logged["token"])
        visibility = manifest["case"] if manifest["case"] in {"public", "shared"} else "private"
        secret = secrets.token_urlsafe(32)
        created = await request("/orders", method="POST", token=tokens[0], status=201,
                                payload={"secret": secret, "visibility": visibility,
                                         "shared_with": identities[1]["subject"] if visibility == "shared" else ""})
        path = "/orders/" + created["id"]
        normal = await request(path, token=tokens[0])
        expected = {"id": created["id"], "type": "order", "owner": identities[0]["subject"],
                    "tenant": identities[0]["tenant"]}
        if any(normal.get(k) != v for k, v in {**expected, "secret": secret}.items()):
            raise ValueError("Normal create/read did not preserve the bound object")
        await request(path, status=401)  # middleware is exercised, never bypassed
        if visibility != "private":
            allowed = await request(path, token=tokens[1])
            if allowed.get("secret") != secret:
                raise ValueError("Permitted observer cannot read the shared/public object")
        prepared.update(tokens=tokens, identities=identities, path=path, resource=expected,
                        visibility=visibility)
        return {"ok": True, "state": "completed", "normal_create_read": True,
                "anonymous_denied": True, "setup_entrypoint": "normal_http",
                "database": "sqlite", "credentials_persisted": False}

    async def verify():
        assert relay is not None
        a, b = prepared["identities"]
        spec = {"version": 1, "owner": a, "observer": b, "resource": prepared["resource"],
                "identity_url": relay.base_url + "/me",
                "control_url": relay.base_url + "/orders/missing-" + secrets.token_hex(12),
                "protected_fields": ["secret"],
                "policy": {"id": RECIPE, "source": "builtin recipe: owner-only private reads",
                           "visibility": prepared["visibility"], "allowed_subjects": [a["subject"]] + (
                               [b["subject"]] if prepared["visibility"] == "shared" else [])}}
        value = await verify_private_read(http, relay.base_url + prepared["path"], spec,
                                          owner_headers={"Authorization": "Bearer " + prepared["tokens"][0]},
                                          second_headers={"Authorization": "Bearer " + prepared["tokens"][1]},
                                          scope_check=lambda url: urlsplit(url)[:2] == urlsplit(relay.base_url)[:2])
        return value

    async def phase(name, call):
        nonlocal phase_id
        record = store.begin_invocation(run_id, "research_environment", hashlib.sha256(
            (name + json.dumps(manifest, sort_keys=True)).encode()).hexdigest(), task_id=task["id"], **lease)
        phase_id = record["id"]
        started = time.monotonic()
        try:
            value = await call()
            state = "completed" if value.get("ok") else "unknown"
            evidence = _artifact(store, run_id, "research_" + name, value)
            receipt = {"ok": state == "completed", "state": state, "evidence": evidence}
            store.finish_invocation(phase_id, state, receipt)
            if state != "completed":
                raise ValueError("Recipe phase incomplete; inspect evidence")
            return value
        except BaseException:
            if store.get_invocation(phase_id)["state"] == "running":
                store.finish_invocation(phase_id, "unknown", {"ok": False, "state": "unknown",
                                        "error": "research_phase_interrupted", "retryable": False})
            raise
        finally:
            metrics[name] = {"requests": store.get_invocation(phase_id)["requests_used"],
                             "elapsed_seconds": round(time.monotonic() - started, 3)}

    async def work():
        nonlocal relay
        start = asyncio.create_task(asyncio.to_thread(sandbox.start))
        try:
            settings = await asyncio.shield(start)
        finally:
            # A cancelled await does not stop a Docker CLI thread.
            await _settle(start)
        result["runtime"] = settings
        relay = HTTPRelay(sandbox.directory / "app.sock")
        await phase("prepare", prepare)
        proof = await phase("verify", verify)
        result["verification"] = proof
        expected = "verified" if manifest["case"] == "private_vulnerable" else (
            "not_verified" if manifest["case"] == "private_fixed" else "not_applicable")
        result["evaluation"] = {"expected_verdict": expected, "observed_verdict": proof["verdict"],
                                "matched": proof["verdict"] == expected,
                                "kind": "known synthetic regression case"}
        result.update(ok=proof["verdict"] == expected,
                      state="completed" if proof["verdict"] == expected else "failed")

    interrupted = False

    def mark_interrupted():
        nonlocal interrupted
        interrupted = True
        result.update(ok=False, state="unknown", error="research_interrupted")

    try:
        with _exclusive(root):
            worker = asyncio.create_task(work())
            deadline = time.monotonic() + 180
            try:
                while not worker.done():
                    await asyncio.wait({worker}, timeout=1)
                    store.heartbeat(task["id"], **lease, lease_seconds=60)
                    if time.monotonic() > deadline:
                        raise TimeoutError("Research wall limit reached")
                await worker
            except BaseException as exc:
                interrupted = isinstance(exc, asyncio.CancelledError)
                sandbox.cancelled.set()
                worker.cancel()
                with contextlib.suppress(BaseException):
                    await _settle(worker)
                result.update(ok=False, state="unknown", error="research_interrupted",
                              failure_type=type(exc).__name__)
            finally:
                if relay is not None:
                    relay.close()
                cleanup_task = asyncio.create_task(asyncio.to_thread(ResearchSandbox(resource, root).cleanup))
                cleanup_result = await _settle(cleanup_task, mark_interrupted)
                result["cleanup"] = cleanup_result
                result["cleanup_artifact"] = _artifact(store, run_id, "research_cleanup", cleanup_result)
                if not cleanup_result["ok"]:
                    result.update(ok=False, state="unknown", error="cleanup_unconfirmed")
    except (OSError, ValueError) as exc:
        result.update(ok=False, state="unknown", error="research_admission_failed", failure_type=type(exc).__name__)
    finally:
        result["metrics"] = metrics
        # Task result links to provisional finalization evidence. Only publish
        # the authoritative assessment after the fenced task/run transitions:
        # cancellation can race with either transition through another store.
        pending = _artifact(store, run_id, "research_finalization", {
            "ok": False, "state": "unknown", "error": "research_finalization_pending",
            "retryable": False,
        })
        result["finalization_artifact"] = pending
        try:
            store.heartbeat(task["id"], **lease, lease_seconds=60)
            store.update_task(task["id"], "completed" if result["ok"] else "blocked",
                              result=pending["uri"], **lease)
            if result["ok"]:
                completion = store.finish(run_id)
                if not completion["completed"]:
                    result.update(ok=False, state="unknown", error="research_finalization_incomplete",
                                  blockers=completion["blockers"])
        except ValueError:
            # Cleanup may outlive a lease or a user may cancel the run. Keep its
            # evidence, but do not call an unfenced assessment completed.
            result.update(ok=False, state="unknown", error="research_lease_lost")
            store.recover_expired_tasks(run_id)
        summary = _artifact(store, run_id, "research_result", result)
        result["result_artifact"] = summary
    if interrupted:
        raise asyncio.CancelledError()
    return result


async def cleanup(store: RunStore, run_id: str, artifact_id: int) -> dict:
    if current_execution() is not None:
        raise ValueError("Use research_environment directly, outside run_execute")
    root = _root(store)
    artifact = store.get_artifact(run_id, artifact_id)
    if artifact["kind"] != "research_resource":
        raise ValueError("Expected a research_resource artifact")
    resource = json.loads(artifact["content"])
    if resource.get("version") != 1 or resource.get("recipe") != RECIPE:
        raise ValueError("Unsupported resource record")
    task = store.task(resource["task_id"])
    if task["run_id"] != run_id:
        raise ValueError("Resource task belongs to another run")
    if task["lease_until"] is not None and task["lease_until"] > time.time():
        raise ValueError("Resource worker still holds an active lease")
    with _exclusive(root):
        store.recover_expired_tasks(run_id)
        worker = asyncio.create_task(asyncio.to_thread(ResearchSandbox(resource, root).cleanup))
        interrupted = False

        def mark_interrupted():
            nonlocal interrupted
            interrupted = True

        result = await _settle(worker, mark_interrupted)
        ref = _artifact(store, run_id, "research_cleanup", result)
    if interrupted:
        raise asyncio.CancelledError()
    return {**result, "run_id": run_id, "evidence": ref,
            "recovery": "Cleanup does not resolve unknown HTTP effects or replay the assessment."}
