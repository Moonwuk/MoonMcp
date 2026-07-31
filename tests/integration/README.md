# Integration tests

These validate MoonMCP's detectors against **real services**, not the synthetic fakes
the unit suite uses. They are **skipped by default** (module-level `skipif`) and never
run in CI — they only execute when `MOONMCP_INTEGRATION=1` is set and the services in
`docker-compose.yml` are up.

## Run

```bash
docker compose -f tests/integration/docker-compose.yml up -d
# give the services a few seconds to become ready (Elasticsearch is the slowest)
MOONMCP_INTEGRATION=1 pytest -m integration tests/integration -q
docker compose -f tests/integration/docker-compose.yml down
```

Each test also **skips** (rather than fails) if its specific service isn't reachable,
so a partially-started stack still runs whatever it can.

## What they cover

- Raw-TCP probes (`redis`, `mongodb`, `memcached`) correctly flag an **unauthenticated**
  store as `exposed`.
- The HTTP interpreters against **real banners**: CouchDB's root welcome and InfluxDB's
  `/ping` are reported as info-level version disclosure (not a false "exposed"), while a
  security-disabled Elasticsearch root genuinely reads as `exposed`.

## Safety

Every service in the compose file is intentionally unauthenticated and bound to
`127.0.0.1` only. **Never** start it on a shared or internet-exposed host.
