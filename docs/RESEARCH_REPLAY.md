# Reproducible local HTTP research recipe

`research_environment` adds one opt-in, synthetic SQLite orders application. It
prepares fresh accounts and objects through HTTP, exercises the private-read
verifier, saves evidence, and removes the environment. It implements a bounded
part of IP-06/IP-07 in PR #21; it does not complete the general research environment
roadmap or measure autonomous vulnerability discovery (IP-08).

## Agent workflow

1. Call `research_environment(action="describe")`. This is local, side-effect-free
   discovery. Select one of the returned capsules: `private_vulnerable`,
   `private_fixed`, `public`, or `shared`.
2. Prepare local Linux Docker and persistent `MOONMCP_STATE_DIR`. Explicitly preload
   the image shown below. The tool never pulls images or runs an arbitrary project.
3. Call `research_environment(action="replay", capsule=<returned object>, execute=true)`
   directly, outside `run_execute`. Omitting `execute` only previews requirements.
4. Read `ok`, `state`, `cleanup`, `evaluation`, and `verification`. `ok=true` means
   the known regression case behaved as expected **and** cleanup was confirmed.
   The fixed case should return `not_verified`; public/shared cases should return
   `not_applicable`, with the permitted read checked during preparation.
5. Use `run_artifacts` / `run_artifact_read` for durable evidence. Copy only the
   `research_capsule` JSON into another server's replay call to prepare a new
   instance with new users, passwords, tokens, tenants, object IDs and private data.
   The capsule contains no old host paths, addresses, credentials or commands.
6. Keep each run's receipts and compare results. A repeat using a capsule is a new
   experiment. An earlier successful fixture run does not confirm a real target
   finding, and these results never automatically promote findings or reports.

Explicit image preparation (the adapter pins the same local daemon endpoint):

```sh
env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS \
    -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
    docker --host=unix:///var/run/docker.sock pull \
    python@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
```

Docker credentials/proxy configuration remain available to this explicit preparation
command. The runtime does not mount them or the Docker socket into the application.

## Fidelity and independent repetition

The application runs as a separate process in Docker and uses real SQLite storage.
The controller sends normal HTTP requests through registration, login, creation,
owner read, anonymous denial, and (where applicable) permitted observer read routes.
The assessed observer has distinct credentials and a separate tenant. Setup never
writes the database directly, substitutes an internal function call for HTTP, or
removes authentication middleware. The private-read proof checks both live identities,
exact object ownership, protected fields beyond 4 KiB, a missing-object control, and
stable repeated owner reads using the existing verifier.

Expected labels come from the builtin case definition, separately from the observed
HTTP verdict. They are deliberately known synthetic cases, not a hidden discovery
benchmark. An identical capsule can be repeated in another persistent store, without
reusing state from the original run. The installed recipe validates every capsule
field, including the application source SHA-256 and image digest. A changed recipe
requires a newly generated capsule; unsupported fields are refused before side effects.
The recipe's HTTP client also ignores ambient proxy and impersonation settings, so
its temporary credentials stay on the local application connection.

Preparation and verification have separate durable invocation receipts, request counts
and elapsed times. Every actual HTTP dispatch reserves budget through the common
`HttpClient` boundary. Readiness failures count too. Per replay: 32 HTTP dispatches,
two phases, and 180 seconds for preparation plus verification. Cleanup has separate
bounded command deadlines and remains available when that budget is exhausted.
The running controller checks its task/run lease each second, so pausing/cancelling
its run also stops work and initiates cleanup.

## Runtime constraints and cleanup

- One active controller per persistent state directory, protected by a process lock
  as well as existing task leases. A resource artifact is committed before any
  environment-side effect. This reuses RunStore; there is no second coordinator DB.
- Local Docker endpoint only; pinned, preloaded image; UID/GID 65532; read-only root;
  all capabilities dropped; no-new-privileges; 32 PIDs; 128 MiB RAM; 0.5 CPU;
  16 MiB temporary database filesystem; Docker logging disabled.
- `network=none`: the container has no IP route to the host or internet. The only
  application connection is a Unix HTTP socket in a fresh directory under a private
  runner-owned parent, exposed by a byte-preserving TCP relay on **127.0.0.1 only**.
  The relay has eight connection slots, 16 KiB chunks and a five-second idle timeout.
  Normal HTTP parsing and application middleware still execute in the container.
- Docker CLI output has a combined 32 KiB limit and finite timeouts. On failure the
  CLI is killed and reaped, then a separate cleanup adapter removes the container.
  Killing the CLI alone is never treated as child/container termination evidence.
- Cancellation waits for the startup thread to settle before cleanup, avoiding a
  late container creation after purported cleanup. Removal checks the recorded
  container name and ownership label, then requires a successful inventory query
  proving absence. Unexpected host files or ownership mismatches are retained and
  reported as `unknown`, not recursively removed.

After a process crash, locate the run with `run_list`, then its `research_resource`
artifact with `run_artifacts`. Stop the old worker if it still exists and allow its
60-second lease to expire. Call:

```text
research_environment(action="cleanup", run_id="...", artifact_id=RESOURCE_ARTIFACT_ID)
```

An active lease or held host lock refuses recovery. Expired work becomes blocked;
cleanup neither reruns HTTP actions nor converts an unknown assessment into success.
Repeated cleanup is safe for an already absent owned resource. The private controller
lock file and immutable journal remain as state; application sockets and containers
are removed. A failed cleanup retains the resource record for later reconciliation.

Docker shares the host kernel: these constraints do not make arbitrary hostile
projects safe. The writable socket directory is narrowly exposed to this trusted
fixture, not a general filesystem sandbox. Only the builtin recipe is admitted.
There is no persistent service, arbitrary command tool, production credential import,
general project deployment, browser-based workflow, or automatic agent benchmark.
Legacy `sandbox_exec` remains outside managed execution; its configurable Python
adapter has not acquired the stricter recipe's guarantees.

## Validation

`tests/test_research.py` covers capsule rejection, side-effect-free previews, durable
intent, output/time bounds, ownership failures, cancellation/startup ordering, lease
and host-lock recovery, request budget exhaustion, and the managed-dispatch boundary.
`tests/test_research_live.py` runs real Docker/HTTP/SQLite cases, independently repeats a
capsule with fresh state, checks denied egress and root writes, checks output overflow,
and kills a worker process after startup to exercise orphan cleanup. Enable it with:

```sh
MOONMCP_TEST_DOCKER=1 pytest -q tests/test_research_live.py
```

CI has a dedicated job which preloads the pinned image and runs those tests. The normal
suite explicitly skips live Docker tests unless enabled. It still checks all ordinary
contracts, types, lint and coverage. These checks establish recipe correctness; they
do not establish improved agent precision, recall, time to discovery or cost.
