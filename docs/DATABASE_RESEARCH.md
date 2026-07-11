# MoonMCP — Database Attack Surface Research (multi-language, detection-only)

A large-scale synthesis of **database attack tools, skills and techniques** mined from
national security communities in their own languages — 🇨🇳 China (FreeBuf / Seebug /
AnQuanKe / y4er / gm7), 🇷🇺 Russia-CIS (Habr / Xakep / Wiz), 🇯🇵🇰🇷 Japan-Korea (JVN /
IPA / Tokumaru / eGovFrame), 🇻🇳🇮🇳 Vietnam-India-SEA (Viblo / WhiteHat), plus global
cutting-edge research (PortSwigger / Claroty Team82 / elttam / HackTricks /
PayloadsAllTheThings / Datadog / Wiz / HiddenLayer) and the offensive-DB **tooling
landscape** (sqlmap / ghauri / odat / msdat / impacket / NoSQLMap / gopherus / nuclei).

Companion to `docs/RESEARCH_GAPS.md` and `docs/NUCLEI_COVERAGE.md`; same house rules:

- **Detection-only.** Every entry is a read-only fetch, a benign two-request
  differential, an error-string match, or an OAST reachability callback. **No probe in
  the detection path writes data, changes config, sleeps as a DoS, loads a module, or
  runs a command.** Weaponization (dump, `--os-shell`, `CONFIG SET`/`SLAVEOF`/`MODULE
  LOAD`, UDF, painless/Groovy RCE, ChromaToast model-load, gadget/JNDI chains,
  credential brute-force) is handed to **sqlmap / Strix** under human confirmation.
- **Don't reinvent nuclei/sqlmap.** The entire "exploit the DB once found" lane is
  saturated by mature CLIs. MoonMCP **delegates** commodity single-request detection and
  all extraction, and spends native effort only on the **stateful / differential /
  cross-request / OAST-correlated / context-placement** probes that a stateless
  per-template engine structurally cannot express — those survive the nuclei crowd on
  already-scanned targets.

Legend: **Status** = ❌ not covered · 🟡 partial · ✅ covered.

## What MoonMCP already ships (do NOT rebuild)

- `sqli_probe` (`web/probes.py`) — **only** a single-quote error trigger + a boolean
  pair `'1'='1'`/`'1'='2'`. No union / stacked / time-based / ORDER-BY / multibyte /
  JSON-operator / OOB / header-placement / second-order.
- SQLi error-signature DB (`knowledge/injections_data.py`) — MySQL / PostgreSQL /
  Oracle `ORA-` / DB2 `SQLSTATE` / MSSQL. **No Tibero / CUBRID / Altibase / CQL /
  InfluxDB.**
- `stack_probe` (`web/stacks.py`) — HTTP-only passive fingerprint + unauth reads for
  ClickHouse (`/?query=SELECT 1`), Druid (`/druid/index.html` exposed), Nacos, ThinkPHP,
  Shiro, 1C-Bitrix. CN/RU web stacks only.
- `ssrf_metadata_probe` (`web/ssrf_meta.py`) — cloud-metadata credential theft.
- `analyze_config` (`recon/config_audit.py`) — DB creds + framework signing-secret
  forge classifier from config text.
- `debug_exposure` (`web/debugpanel.py`) — Adminer / phpMyAdmin **panel** signatures.
- `extract_secrets` (`recon/secrets.py`) — generic secret regexes incl. Databricks `dapi…`.
- Injection KB classes present: `nosqli`, `graphql-injection`, `cypher-injection`,
  `orm-injection`, `prototype-pollution`, `ssrf`.
- `net/ports.py` banner grab is **passive-read only** — it reads what the server
  volunteers and sends *nothing*, so silent DB services (Redis, Mongo binary wire,
  memcached) yield no banner today. Real detection gap.
- `run_scanner` → **sqlmap already bridged** (`external/cli.py`); OAST stack
  (`oast_selfhost`/`oast_generate`/`oast_poll`); `confirm.evaluate(reflected,
  status_changed, length_delta, injection_hits, oast_count, timing_delta_ms)`;
  `promote_lead` → `leadpipe.py` → Strix handoff — all reusable primitives.

---

## Priority build order (highest ROI first, all safe-detection)

| # | Capability | New/extends | Lane | Why first |
|---|---|---|---|---|
| 1 | `nosqli_probe` — Mongo operator (`$ne/$gt/$in`) auth-bypass + `$where` boolean | ✅ **SHIPPED** `web/nosqli.py` | native edge | `nosqli` existed only in the KB, never as a probe; lives on real login/search endpoints; nuclei can't express the object-injection differential; consensus #1 across 3 agents |
| 2 | `db_exposure` — raw-socket + HTTP unauth datastore sweep | 🟡 **SHIPPED** `recon/datastores.py` | native edge | `port_scan` sent no protocol probe; now covers Redis/Mongo/memcached/ES/CouchDB/InfluxDB/YARN/TiDB in one scope-gated fan-out (Zookeeper/Kafka/vector-DB still to add) |
| 3 | `sqli_probe` sharpenings: OOB/OAST, JSON-operator WAF-bypass, time-based, ORDER-BY/context, multibyte, header/cookie | ✅ **SHIPPED** `web/probes.py` + `sqli_probe` | native edge | six structurally-nuclei-blind lanes bolted onto the existing reproducible-differential harness |
| 4 | `second_order_sqli_probe` — write-then-read stateful SQLi | ✅ **SHIPPED** `web/secondorder.py` | native edge | the sink is a *different* endpoint; impossible for any stateless matcher |
| 5 | `orm_leak_probe` — Django/Prisma/Rails relational-lookup + mass-assignment | ✅ **SHIPPED** `web/ormleak.py` | native edge | hot 2023-25 class (elttam ORM Leak); fully nuclei-blind; mass-assignment half already in `logic_probe` |
| 6 | `db_credential_scan` — managed-DB DSN + warehouse-token classifier | ✅ **SHIPPED** `secrets.py` + `config_audit.py` | offline classifier | highest-confidence net-new; PlanetScale/Neon/Turso/Atlas-srv/Snowflake/Redis-Cloud/BigQuery = direct DB, zero traffic |
| 7 | `firebase_exposure` + `supabase_exposure` (RLS-off anon-key) | **new** `recon/{firebase,supabase}.py` | passive active-GET | epidemic in vibe-coded apps; one safe GET with the app's own public key |
| 8 | `fastjson_oast_probe` — benign `@type` → OAST DNS callback | **new**, reuse OAST | native edge | #1 CN Java-stack bug; KB describes it, nothing detects it |
| 9 | `stack_probe` family extensions: Druid session-leak, CouchDB, ES, InfluxDB, vector-DB | extend `web/stacks.py` | native edge | reuse the `_probe_clickhouse` template; ChromaToast CVE-2026-45829 (CVSS 10, unpatched) auto-routes to Strix |
| 10 | `ssrf_protocol_probe` — gopher/dict OAST canary → Redis/memcached + DNS-rebinding | extend `web/ssrf_meta.py` | native edge | turns blind SSRF into confirmed internal-datastore reach, detection-only |
| 11 | `sspp_probe` — server-side prototype-pollution → Mongo operator injection | **new** `web/sspp.py` | native edge | stateful gadget chain; escalates to NoSQLi/RCE (Silent Spring) |
| 12 | Regional fingerprint/KB packs: domestic DBMS + default creds, CQL/Cypher KB, Adminer CVE, DB panels, backup-dump keys, APAC WAFs | extend fingerprint/KB/buckets/debugpanel | KB + delegate | cheap table edits that light up 信创 / eGovFrame / APAC populations English tools skip |

---

## Theme A — NoSQL & operator injection (native edge) 🌐🇻🇳🇮🇳

`web/graphql.py` is introspection-only and there is **no active NoSQLi probe** — the
biggest single gap. All signals below are benign two/three-request differentials; blind
regex/`sleep` *extraction* is delegated to **NoSQLMap** or Strix.

### A.1 MongoDB operator-injection auth bypass (`$ne`/`$gt`/`$in`/`$nin`) ✅ (SHIPPED) — RANK 1
Implemented in `moonmcp/web/nosqli.py` + the `nosqli_probe` tool (intrusive): sends the
bracket (`param[$ne]=x`) and JSON (`{"param":{"$ne":null}}`) operator twins twice each and
flags a *reproducible* flip vs a plain-`CONTROL` baseline (status change / new session
`Set-Cookie` / materially more body), plus a `$where` boolean oracle and `nosqli`
error-signature matching. Detection-only; `$regex` char-extraction / `sleep()` → NoSQLMap/Strix.

When an app forwards `req.body`/`req.query` straight into a Mongo/Mongoose filter, an
attacker sends an *object* where a *string* is expected: `{"$ne":null}` matches any
value, `{"$gt":""}` any non-empty string, `{"$in":[...]}` enumerates admins → on
`find({user,pass})` this is an auth bypass.
- Exact payloads (PayloadsAllTheThings): bracket `username[$ne]=x&password[$ne]=x`,
  `login[$nin][]=admin&pass[$ne]=x`; JSON `{"username":{"$ne":null},"password":{"$ne":null}}`,
  `{"username":{"$in":["admin","root"]},"password":{"$gt":""}}`.
- **SAFE signal:** three variants of the same request — (a) literal baseline, (b)
  bracket operator twin, (c) JSON twin with `Content-Type: application/json`. Confirmed
  when (b)/(c) flip the outcome vs (a): a login-success indicator (302 / Set-Cookie /
  token) or strictly-more records appears only with the operator. Reuse
  `confirm_finding` baseline-vs-payload similarity. No extraction.
- Source: https://portswigger.net/web-security/nosql-injection · https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/NoSQL%20Injection/README.md · https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection
- **Mapping:** **new `nosqli_probe`** (`web/nosqli.py`, model on `stacks.py`; `web/inject.py:with_param` + a JSON-body variant). Register **light_active** (benign/differential). Deep boolean/regex extraction → NoSQLMap / Strix.

### A.2 MongoDB `$where` server-side JS injection (boolean) ✅ (SHIPPED) — RANK 4
Folded into `nosqli_probe` — `{"$where":"return true"}` vs `{"$where":"return false"}`
reproducible boolean differential (never `sleep()`).

`$where` evaluates a JS expression server-side (still default-enabled in many deploys).
- **SAFE signal:** boolean-only — `{"$where":"return true"}` vs `{"$where":"return false"}`;
  compare response / record count. **Avoid `sleep()`** in detection (DoS-adjacent);
  timing extraction → NoSQLMap/Strix.
- Source: https://www.acunetix.com/vulnerabilities/web/mongodb-where-operator-javascript-injection/ · https://www.objectrocket.com/blog/mongodb/code-injection-in-mongodb/
- **Mapping:** fold into `nosqli_probe` as a distinct payload family; enrich KB `nosqli` with `$where` signatures.

### A.3 GraphQL / ORM → NoSQL operator injection ❌ — RANK 2
GraphQL resolvers and ODM layers (Mongoose `populate()`/filter) pass client-controlled
objects into Mongo filters. Live ODM CVEs: Mongoose **CVE-2024-53900** (<8.8.3) and its
bypass **CVE-2025-23061** (<8.9.5).
- **SAFE signal:** after `graphql_check` confirms an endpoint, re-send a query/mutation
  arg once as a nested operator object (`{"$ne":null}`) vs the literal; confirm on a
  benign differential (auth/count change, or a `"$ne"` type-coercion error in
  `errors[]`). No extraction; hidden-schema case → lead → Strix.
- Source: https://appsecco.com/blog/hacking-apps-using-nosql-injection · https://security.snyk.io/vuln/SNYK-JS-MONGOOSE-8172732 · https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/GraphQL%20Injection/README.md
- **Mapping:** extend `web/graphql.py` with a post-introspection operator-injection pass; feed `discover_parameters` results into `nosqli_probe`. Nuclei `-dast` does not cover object-shaped operator injection → native edge.

### A.4 Server-side prototype pollution → Mongo operator injection ❌ — RANK 11
A merge/`Object.assign` of attacker JSON with `__proto__`/`constructor.prototype` can
inject a Mongo operator (`$where`,`$gt`) into a *later* query the attacker never
directly controls ("Silent Spring").
- **SAFE signal:** reflected/ephemeral gadgets only — `{"__proto__":{"<gadget>":"<marker>"}}`
  where the gadget benignly alters *this* response (Express `json spaces` → extra
  whitespace; a status/`content-type` gadget), confirm the marker appears **and is gone
  on the next clean request**. No persistent DoS gadget; SSPP persistence caveat in the
  docstring; confirmation → Strix.
- Source: https://arxiv.org/pdf/2207.11171 · https://portswigger.net/web-security/prototype-pollution/server-side
- **Mapping:** **new `sspp_probe`** (light_active, reflected-gadget only). Add a server-side subsection under KB `prototype-pollution` cross-linking `nosqli`.

---

## Theme B — Unauthenticated datastore exposure sweep (the flagship new probe) 🇨🇳🇷🇺🌐

The consensus flagship: a **raw-socket + HTTP** fan-out that speaks the *minimal
read-only handshake* for each service and returns an unauth verdict from a clean
protocol differential. `port_scan` sends no protocol probe today; `stack_probe` is
HTTP-only. This is squarely native-edge (stateful protocol read), does not overlap
`stack_probe`, and reuses `net/ports.py` + `net/http.py`.

> ✅ **SHIPPED** — `moonmcp/recon/datastores.py` + the `db_exposure` tool (intrusive):
> raw-TCP handshakes for **Redis** (`PING`→`+PONG`, then `INFO` for version/role vs
> `-NOAUTH`), **Memcached** (`version`), **MongoDB** (a hand-built `listDatabases`
> OP_MSG wire query → unauth database-list vs an auth-required error), and HTTP metadata
> reads for **Elasticsearch/OpenSearch**, **CouchDB**, **InfluxDB** (`/ping` +
> `X-Influxdb-Version`), **Hadoop YARN** (`/ws/v1/cluster/info`) and **TiDB status**
> (`/status`). Scope-gated, non-destructive, concurrency+rate-limited. Remaining below:
> Zookeeper/Kafka handshakes and the vector-DB fingerprint family (B.7).

### B.1 Redis unauthenticated access ❌ — RANK 2/10
Redis bound `0.0.0.0:6379` with no `requirepass` → full command access (→ SSH-key/cron
write, master-replica `MODULE LOAD` RCE, Lua sandbox escape). Actively farmed
(Datadog RedisRaider).
- **SAFE signal:** open a TCP socket, send inline `PING\r\n` → `+PONG` (unauth) vs
  `-NOAUTH Authentication required.` (protected); follow with read-only `INFO\r\n` — the
  `redis_version` / `role:master` block also reveals RCE feasibility. **Never** send
  `CONFIG`/`SLAVEOF`/`MODULE`/`SET`/`EVAL`.
- Redis CVEs to fingerprint (version→CVE, don't exploit): **CVE-2022-0543** (Debian Lua
  sandbox escape, pre-auth if unauth, CISA KEV), **CVE-2024-31449** (Lua `bit` stack
  overflow, authed).
- Source: https://paper.seebug.org/977/ · https://securitylabs.datadoghq.com/articles/redisraider-weaponizing-misconfigured-redis/ · https://www.exploit-db.com/exploits/47195 · https://www.ubercomp.com/posts/2022-01-20_redis_on_debian_rce
- **Mapping:** primary case for `db_exposure` (raw-TCP, scope+intrusive gated). Verdict = unauth banner diff; version→CVE feeds `cve_lookup`. All RCE → Strix.

### B.2 MongoDB unauthenticated instance (27017) ❌ — RANK 2/17
`--auth` off → anyone lists DBs / dumps collections (mass-ransom target). Modern
defaults are localhost+auth, but Atlas network-access `0.0.0.0/0` re-exposes it.
- **SAFE signal:** speak the wire protocol — `listDatabases:1` on `admin.$cmd` (or
  `isMaster`/`hello`). `ok:1` + a `databases[]` array with `sizeOnDisk` = unauth; error
  code 13 (`Unauthorized`) = secured. Read-only enumeration, no collection dump.
- Source: https://www.verylazytech.com/mongodb-port-27017-27018 · https://www.mongodb.com/docs/cloud-manager/reference/alerts/host-exposed/
- **Mapping:** wire-protocol case in `db_exposure`. (Atlas `0.0.0.0/0` also caught by the exposed-port classifier, Theme E.)

### B.3 Elasticsearch / OpenSearch unauth cluster + `_search` dump ❌ — RANK 8
Auth-off by default. `GET /` → `"tagline":"You Know, for Search"` + version;
`_cat/indices`, `_nodes`, `_river/_search` leak all data + creds. Legacy RCE:
MVEL CVE-2014-3120, Groovy CVE-2015-1427.
- **SAFE signal:** metadata not documents — `GET /_cat/indices?format=json` (200 + index
  list) or `GET /_cluster/health`; `GET /_search?size=0` returns counts only. Parse the
  version to flag CVE-2015-1427 without sending any `script` payload.
- Source: https://blkstone.github.io/2017/09/27/elasticsearch-unauthorized-access/ · https://www.elastic.co/guide/en/elasticsearch/reference/current/cluster-health.html · https://www.wiz.io/blog/wiz-research-uncovers-exposed-deepseek-database-leak
- **Mapping:** HTTP case in `db_exposure` (and/or `_probe_elasticsearch` in `stack_probe`, mirroring `_probe_clickhouse`). RCE → nuclei/Strix.

### B.4 CouchDB duplicate-roles admin bypass (CVE-2017-12635) + `_config` RCE ❌ — RANK 6
Erlang vs JS JSON parsers disagree on duplicate keys → an anonymous `PUT /_users` with
two `roles` arrays becomes `_admin` (CVSS 9.8); chained with `_config query_server` → RCE
(CVE-2017-12636). Modern CouchDB `_all_dbs` unauth still common; CVE-2022-24706
(Erlang-cookie RCE) < 3.2.2.
- **SAFE signal:** version fingerprint only — `GET /` → `{"couchdb":"Welcome","version":…}`
  → affected-range map; `GET /_all_dbs` unauth confirms exposure (read-only). The
  duplicate-roles PUT *creates a user* (side effect) → **Strix PoC brief, never an
  in-scan action**.
- Source: https://docs.couchdb.org/en/stable/cve/2017-12635.html · https://docs.couchdb.org/en/stable/cve/2022-24706.html · https://github.com/vulhub/vulhub/tree/master/couchdb/CVE-2017-12636
- **Mapping:** `_probe_couchdb` in `stack_probe` / HTTP case in `db_exposure`. Full exploit → nuclei/Strix.

### B.5 Hadoop YARN ResourceManager unauth REST RCE (8088) ❌ — RANK A
YARN RM REST on 8088 open by default lets anyone submit an app with an arbitrary launch
command → pre-auth RCE (Kinsing/h2Miner farm it).
- **SAFE signal:** `GET /ws/v1/cluster/info` → 200 JSON with `hadoopVersion`/
  `resourceManagerVersion` and no auth = exposed. **Do not** POST a launch spec.
- Source: https://github.com/Al1ex/Hadoop-Yarn-ResourceManager-RCE · https://www.alibabacloud.com/blog/598248
- **Mapping:** HTTP case in `db_exposure`. App-submit RCE → Strix/nuclei.

### B.6 InfluxDB empty-secret JWT auth bypass (CVE-2019-20933) ❌ — RANK 9
InfluxDB <1.7.6 `authenticate()` accepts a JWT signed with an **empty** shared secret →
forge any-user token → full read/write (CVSS 9.8).
- **SAFE signal:** clean forged-token differential — anon `GET /query?q=SHOW+DATABASES`
  → 401, then the same with `Authorization: Bearer <HS256 JWT signed with "">` (payload
  `{"username":"admin","exp":<future>}`) → 200 with a `results` DB list. Read-only; the
  401→200 flip is the confirmation.
- Source: https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-20933 · https://github.com/LorenzoTullini/InfluxDB-Exploit-CVE-2019-20933
- **Mapping:** `_probe_influxdb` in `stack_probe` (fingerprint via `GET /ping` →
  `X-Influxdb-Version`, then the empty-secret differential). Reuses `web/jwt.py`.

### B.7 Vector-DB unauthenticated exposure sweep 🟡 (SHIPPED via stack_probe) — RANK 11
Implemented in `web/stacks.py` (`_probe_chroma`/`_probe_weaviate`/`_probe_qdrant` + passive
signatures): read-only fingerprints — Chroma `/api/v2/heartbeat`+`/api/v2/version` (flags
ChromaToast CVE-2026-45829, CVSS 10, all versions → critical lead → Strix), Weaviate
`/v1/meta`, Qdrant `/collections`. Milvus (gRPC-heavy) still to add.

Standalone vector stores (Weaviate/Milvus/Qdrant/Chroma) ship with no auth and bind
publicly; 3,000+ unauth instances found in 2025; embeddings invert to PII. `pgvector` is
just Postgres (ordinary SQLi) — the vector-specific risk is *exposure*.
- **SAFE signal:** read-only fingerprint per product — Weaviate `GET /v1/meta` +
  `/v1/.well-known/ready`; Qdrant `GET /collections` + `/healthz`; Milvus health; Chroma
  `GET /api/v2/heartbeat` → `{"nanosecond heartbeat":…}`. 200 + product-shaped JSON =
  unauth. **ChromaToast — CVE-2026-45829** (HiddenLayer, May 2026, CVSS 10.0, **unpatched**,
  ~73% of exposed Chroma): pre-auth RCE via a client-supplied model id processed before
  auth. Fingerprint via heartbeat + `GET /api/v2/version` — **never** trigger the
  model-load (Strix only).
- Source: https://orca.security/resources/blog/vector-database-security-risks/ · https://labs.cloudsecurityalliance.org/research/csa-research-note-chromadb-rce-ai-vector-database-20260520-c/ · https://www.securityweek.com/unpatched-chromadb-vulnerability-can-lead-to-server-takeover/
- **Mapping:** new `vectordb` fingerprint family in `stack_probe`; Chroma flagged
  `critical-lead` → auto-`promote_lead` → Strix. Weaviate GraphQL also reachable by the
  extended `graphql_check`.

### B.8 Memcached / Zookeeper / Kafka unauth ❌ — RANK C/16
- **Memcached (11211):** no auth by design — `version\r\n`/`stats\r\n` → `VERSION`/`STAT`
  = exposed (info leak + amplification pivot). Also reachable via SSRF `dict://…/stat`.
- **Zookeeper (2181):** 4-letter words `ruok`→`imok`, then read-only `envi`/`stat`.
- **Kafka (9092):** an `ApiVersions` read-only handshake succeeding without SASL = unauth
  broker.
- **TiDB:** `GET :10080/status` → version JSON unauth; PD `:2379` etcd unauth.
- Source: https://hackviser.com/tactics/pentesting/services/memcached · https://tidb.net/blog/c1c55601
- **Mapping:** raw-TCP/HTTP read-only handshakes in `db_exposure`.

---

## Theme C — SQLi beyond the boolean pair (sqli_probe sharpenings + stateful) 🌐🇷🇺🇯🇵🇰🇷

`sqli_probe` today sends only a quote-error + `'1'='1'`/`'1'='2'`. Six structurally-
nuclei-blind lanes bolt onto its existing reproducible-differential harness. Full
extraction stays **delegated to sqlmap**.

> ✅ **SHIPPED** — `sqli_probe` now takes opt-in lanes (default behaviour unchanged):
> `context=value|order_by|limit` (CASE twins for non-parameterizable positions),
> `placement=param|header|cookie` (with `name`), `oob` (per-DBMS DNS/HTTP OAST callback,
> reusing the `ssrf_probe` OAST plumbing), `time_based` (per-DBMS sleep confirmed only
> when the delay is proportional to `delay_s` — monotonic guard), `waf_bypass`
> (JSON-operator + comment twins → flags "SQLi reachable only when the plain boolean is
> blocked"), and `multibyte` (Shift-JIS/EUC-KR/GBK lead-byte charset bypass via raw
> injection). Payloads/analysers in `web/probes.py`; verdict via `confirm.evaluate`.

### C.1 Out-of-band / OAST SQLi (per-DBMS DNS/HTTP) ✅ (SHIPPED) — RANK 3/HIGH
When there's no in-band result and timing is unreliable, force the DB to make an
outbound DNS/HTTP request to a MoonMCP OAST canary: MSSQL `xp_dirtree`/`xp_fileexist` →
UNC → DNS; Oracle `UTL_HTTP`/`UTL_INADDR`/`DBMS_LDAP`; MySQL `LOAD_FILE('\\\\<oast>\\x')`;
PostgreSQL `dblink`/`COPY … PROGRAM`. DNS egress is almost always open → the most
reliable blind-confirm channel.
- **SAFE signal:** inject a per-DBMS OOB payload whose only effect is a lookup to a
  **unique** OAST subdomain; an inbound interaction bound to that token = confirmed
  blind SQLi. Zero data exfil in the detection step (the subdomain is a fixed canary,
  not a `SELECT`-encoded value).
- Source: https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band-data-exfiltration · https://herish.me/blog/sqli-blind-oob-exfiltration/
- **Mapping:** add `oob=True` to `sqli_probe` — `oast_generate` a token, send the four
  per-DBMS canary payloads, `oast_poll` after a short wait. Exactly the `ssrf_probe`
  pattern applied to SQL; `confirm.evaluate(oast_count=…)`. DNS **data** exfil →
  sqlmap `--dns-domain`.

### C.2 JSON-based SQLi — WAF bypass via JSON operators (Claroty Team82) ✅ (SHIPPED) — RANK 3/HIGH
Team82 showed all five leading WAFs fail to tokenize JSON SQL syntax, so appending JSON
operators/casts blinds the WAF while PG/MySQL/MSSQL/SQLite still execute: PG `@>`,`->`,
`::jsonb`,`?|`; MySQL `JSON_EXTRACT`,`->>`; MSSQL `JSON_VALUE`.
- **SAFE signal:** double-differential — run the plain boolean pair **and** a
  JSON-operator-wrapped pair. If the plain pair is **blocked** (403/challenge) but the
  JSON-wrapped pair reproduces the same true/false DB differential
  (`'{"a":1}'::jsonb @> '{"a":1}'` true-twin vs a contradiction), you've confirmed SQLi
  **and** the WAF bypass. Benign tautology/contradiction, no extraction.
- Source: https://claroty.com/team82/research/js-on-security-off-abusing-json-based-sql-to-bypass-waf · https://portswigger.net/daily-swig/json-syntax-hack-allowed-sql-injection-payloads-to-be-smuggled-past-wafs
- **Mapping:** per-DBMS `SQLI_TRUE_JSON`/`SQLI_FALSE_JSON` twin sets in `web/probes.py`;
  when `waf_detect` reports a WAF, `sqli_probe` runs both lanes and flags "SQLi reachable
  only via JSON-operator encoding (WAF bypass)". Extraction → sqlmap JSON tamper.

### C.3 Boolean/time-blind + non-fuzzable positions (ORDER BY / LIMIT / identifier) ✅ (SHIPPED) — RANK 3/MED-HIGH
Identifier positions can't be parameterized, so they're disproportionately vulnerable
*and* missed by value-only fuzzers. This is the **top JP/KR pick**: Korean gov/finance
runs on **eGovFramework (전자정부 표준프레임워크)** = MyBatis, and `mybatis-generator` emits
`ORDER BY ${orderByClause}` by default — the systemic `${}` sink. A quote in ORDER BY
often doesn't error and the `'1'='1'` pair is meaningless there, so `sqli_probe` returns
"no signal" on a genuinely injectable `?sort=`/`?orderBy=`/`?sidx=`.
- **SAFE signal:** row-order differential — `col ASC` vs `col DESC` confirms the param
  reaches ORDER BY (length-stable, order-flipped); then `(CASE WHEN 1=1 THEN 1 ELSE 2 END)`
  vs `(CASE WHEN 1=2 …)` — a stable reproducible ordering difference = the expression is
  evaluated = injectable. Time-blind confirmed only when delay is **monotonic across
  N∈{0,5,10}s** (the KB's `generic-timing` signature). Purely reorders rows; nothing
  written.
- Source: https://vulncat.fortify.com/en/detail?id=desc.config.java.sql_injection_mybatis_mapper · https://jvndb.jvn.jp/ja/contents/2022/JVNDB-2022-015952.html · https://portswigger.net/web-security/sql-injection/blind
- **Mapping:** `context` param (`value`|`order_by`|`limit`|`identifier`) selecting
  placement-specific twins; time-blind mode via `confirm.evaluate(timing_delta_ms)` with
  the monotonic-across-N guard. Deep extraction → sqlmap `--technique T -p sort`.

### C.4 Multibyte charset-mismatch SQLi (Shift-JIS 0x5C / EUC-KR CP949 / GBK) ✅ (SHIPPED) — RANK 3/JP-KR
The signature Japanese technique (Tokumaru/IPA `安全なSQLの呼び出し方`). When the DB
connection charset ≠ the app charset, `addslashes`/quote-doubling is bypassed because a
multibyte lead byte swallows the escaping backslash — SJIS `ソ`(0x95 0x5C), EUC-KR/CP949
lead bytes 0x81–0xFE, GBK `%bf%27`. A target that correctly escapes `%27` but is
charset-mismatched looks safe to `sqli_probe` yet is fully injectable via the multibyte
twin.
- **SAFE signal:** paired differential — plain `%27` (control, expected escaped) vs a
  lead-byte twin (SJIS `%82%27`, EUC-KR `%a1%27`, GBK `%bf%27`); if the multibyte twin
  produces a SQL error / boolean differential where plain `%27` was neutralized, the
  escaping is charset-bypassable. One extra probe pair per param.
- Source: https://t-komura.hatenadiary.org/entry/20060122/1137944280 · https://www.ipa.go.jp/security/vuln/websecurity/ug65p900000196e2-att/000017320.pdf · https://dev.classmethod.jp/articles/secpolo20-reports-vulnerability-by-character-code2/
- **Mapping:** multibyte payload set in `sqli_probe` using `web/inject.py:inject_raw`
  (so raw `%bf%27` bytes aren't re-encoded) + the existing reproducible differential vs a
  plain-`%27` control.

### C.5 Header / cookie SQLi + WAF-bypass encodings ✅ (SHIPPED) — RANK 7/9
`User-Agent`/`Referer`/`X-Forwarded-For`/`Cookie` values logged or queried unsafely — a
documented bounty seam (DoD blind SQLi via UA; XFF SQLi) that value fuzzers skip.
WAF-bypass encoding twins (versioned comments `/*!50000UNION*/`, inline `/**/`,
scientific notation, hex literals, unicode) restore a blocked differential.
- **SAFE signal:** replay `sqli_probe`'s error + reproducible-boolean twins placed in the
  chosen header/cookie instead of the param; same `match_signatures` verdict. For WAF
  bypass: when `waf_detect` reports a WAF and the plain twin is blocked, replay a small
  deduped encoding set — the encoding that restores the DB differential while the plain
  twin stays blocked is the confirmed bypass.
- Source: https://hackerone.com/reports/297478 · https://www.outpost24.com/blog/X-forwarded-for-SQL-injection · https://blog.stratumsecurity.com/2023/05/16/sqli-waf-detection-bypass-techniques-that-still-work-in-2023/
- **Mapping:** add a `placement` param (header/cookie) to `web/inject.py`/`sqli_probe`;
  add a thin **encoding-differential flag** ("SQLi blocked plainly but reachable via
  `<encoding>`"). Deep per-header fuzzing / tamper-chaining → sqlmap `--level 3-5 --tamper`.

### C.6 Second-order / stored SQLi (write in request 1, fires in request N) ✅ (SHIPPED) — RANK 4/TOP
Implemented in `moonmcp/web/secondorder.py` + the `second_order_sqli_probe` tool
(self-scoped, intrusive): seeds a uniquely-tagged control/error/boolean/OOB value at a
`write` endpoint, drives the `read` endpoint(s), and flags a SQL error signature absent
for the benign control, a reflected-tag boolean differential (equal-length twins), or an
OAST callback — all correlated by the tag, away from the write. Extraction → sqlmap
`--second-url`.

Input stored safely in request 1, then re-read and concatenated into a *different* query
in request N — the sink is never on the injection endpoint, so any stateless matcher
(nuclei, `-dast`, even sqlmap against endpoint 1) sees nothing. Emphasized in VN
(Viblo/WhiteHat) and IN/SEA fintech write-ups (stored username/address/wallet-note re-
rendered in admin/receipt/report views).
- **SAFE signal:** two-phase differential — (1) seed a benign uniquely-tagged marker
  (`moon2o_<rand>' -- ` + a boolean twin) into a *write* endpoint (profile/address/
  ticket); (2) drive candidate *read/render* endpoints and diff for a SQL error
  signature or boolean/length differential that only appears after the seed. The unique
  tag ties phase-2 evidence to the phase-1 write. Best variant: seed an OAST payload,
  drive the reader, `oast_poll` — an inbound callback = confirmed blind second-order.
- Source: https://portswigger.net/kb/issues/00100210_sql-injection-second-order · https://www.netspi.com/blog/technical-blog/web-application-pentesting/second-order-sql-injection-with-stored-procedures-dns-based-egress/ · https://viblo.asia/p/cac-ky-thuat-khai-thac-sql-injection-gDVK2J8jKLj
- **Mapping:** **new `second_order_sqli_probe`** modeled directly on `workflow_probe(steps)`
  (the stateful multi-step engine already exists); feed phase-2 responses into
  `match_signatures(class_id="sqli")` + `confirm.evaluate`. Extraction → sqlmap
  `--second-url`/`--second-req` or Strix.

---

## Theme D — ORM leak, mass-assignment & Java-stack → DB 🌐🇨🇳🇷🇺

### D.1 ORM leak / relational-filter injection (Django/Prisma/Rails) ✅ (SHIPPED) — RANK 5/TOP
Implemented in `moonmcp/web/ormleak.py` + the `orm_leak_probe` tool (intrusive): injects
each ORM lookup as a new kwarg — Django `<field>__startswith` / `<rel>__<field>__startswith`,
Prisma `<base>[<field>][startsWith]`, Ransack `<base>[<field>_start]` — with an empty prefix
(matches all) vs an unlikely prefix (matches none), and flags a reproducible differential
(the lookup is applied ⇒ the hidden field is queryable). Detection-only; char-by-char
extraction / the mass-assignment→privilege spread (already in `logic_probe`) → Strix.

Apps spread untrusted params straight into an ORM filter (Django
`filter(**request.data)`, Prisma `where: req.query.filter`, Rails/Ransack). With no raw
SQL and zero classic SQLi, an attacker injects ORM lookups/relational traversals to
filter records by fields they can't see (`password`,`reset_token`,`role`) and exfiltrate
char-by-char (elttam "Leaking More Than You Joined For"). Distinct sub-case:
mass-assignment-to-privilege (`role=ADMIN` spread into a create/update). RU scene: 1C-
Bitrix ORM/`filter[]` injection.
- **SAFE signal:** differential oracle, no data taken — Django `?password__startswith=a`
  vs `?password__startswith=<unlikely>` → row-count/length differential = injectable
  lookup; relational twin `?created_by__password__startswith=a`; a ReDoS `__regex` →
  500/timeout proves the field is queryable. Prisma `filter[createdBy][resetToken][startsWith]=0`;
  Ransack `q[user_reset_password_token_start]=0`. The signal is a stable true/false
  differential on an injected relational lookup, never the leaked value.
- Source: https://www.elttam.com/blog/leaking-more-than-you-joined-for · https://swisskyrepo.github.io/PayloadsAllTheThings/ORM%20Leak/ · https://pentesterlab.com/glossary/django-orm-leak · https://hacktricks.wiki/en/pentesting-web/orm-injection.html
- **Mapping:** **new `orm_leak_probe`** (`web/ormleak.py`) with a per-ORM lookup-suffix
  table; reuse `sqli_probe`'s reproducible true/false differential (double-send noise
  rejection) + `confirm.evaluate(length_delta,status_changed,timing_delta_ms)`. Add the
  mass-assignment→privilege check to `logic_probe`. Fingerprint fuel:
  `recover_sourcemaps`/`stack_probe` reveal Django/Prisma/Rails/Bitrix to pick the suffix set.

### D.2 Fastjson / Jackson autoType → JNDI (pre-auth RCE) ✅ (SHIPPED) — RANK 8/CN-S
Implemented in `web/fastjson.py` + the `fastjson_oast_probe` tool (intrusive, OAST-correlated):
POSTs benign `@type` OAST canaries (`java.net.Inet4Address`/`java.net.URL` fastjson forms +
the Jackson array form) whose only effect is a DNS/HTTP lookup, then polls OAST — a callback
= the endpoint deserializes attacker-controlled `@type` (vuln class confirmed), no JNDI
gadget named. Weaponization → Strix.

The #1 CN Java-stack bug. JSON binders that embed `@type` instantiate the class and fire
setters during parse; `JdbcRowSetImpl`/`BasicDataSource` turn a setter into a JNDI lookup
→ LDAP/RMI → RCE (CVE-2017-18349, CVE-2022-25845, 1.2.24/47/68 chains). Documented
conceptually in `docs/TECHNIQUES.md` but **no active detector**.
- **SAFE signal (OAST, no RCE):** the community's standard *probe* payloads use benign
  non-gadget types that only trigger a DNS resolve — `{"@type":"java.net.Inet4Address","val":"<oast>"}`
  or `{"@type":"java.net.URL","val":"http://<oast>/"}`. A DNS/HTTP callback = the
  endpoint deserializes attacker-controlled `@type` (vuln confirmed) without ever naming
  a JNDI gadget or landing code. `InetAddress`-family works regardless of JDK/autoType state.
- Source: https://github.com/safe6Sec/Fastjson · https://www.yaklang.com/products/article/yakit-technical-study/fast-Json/ · https://github.com/wyzxxz/jndi_tool
- **Mapping:** **new `fastjson_oast_probe`** (differential + OAST lane). Reuse `intel/oast`
  + `oast_generate/oast_poll`; POST the benign `Inet4Address`/`URL` type into JSON
  params/body; confirm via OAST hit. Gadget selection + JNDI server → Strix.

### D.3 Druid monitor → session hijack (`/druid/websession.json`) ✅ (SHIPPED) — RANK CN-S
Implemented — `stack_probe._probe_druid` now reads `/druid/websession.json` after `/druid/index.html` and upgrades the verdict to `high` (session hijack) when live session objects (SESSIONID + principal) are present.
Beyond the `/druid/index.html` "exposed" tell already flagged, `/druid/websession.json`
leaks **live session objects** (SESSIONID, principal, last-access) → copy the freshest
cookie → authenticated backend access; `/druid/sql.json` leaks the literal server SQL
(confirms MyBatis `${}` concat points).
- **SAFE signal:** `GET /druid/websession.json` → 200 JSON with a session array
  (`SESSIONID`,`Principal`,`LastAccessTime`) = session-hijack. Read-only; no cookie replayed.
- Source: https://developer.aliyun.com/article/1260382 · https://cn-sec.com/archives/937808.html
- **Mapping:** extend `stack_probe._probe_druid` — after `/druid/index.html` hits, read
  `websession.json`/`weburi.json`/`sql.json` and upgrade the verdict to `high`
  (session-hijack / SQL-disclosure). Cookie replay → Strix.

### D.4 MyBatis `${}` injection (ORDER BY) 🟡 — RANK CN-C
`${}` string-concatenates into SQL (vs safe `#{}`); classic sinks are non-parameterizable
positions (`ORDER BY ${col}`, `IN (${ids})`, dynamic table names). Covered by C.3's
ORDER-BY differential; if Druid monitor is open (D.3) `/druid/sql.json` leaks the concat
point directly.
- Source: https://github.com/bfchengnuo/MyRecord (MyBatis 注入) · https://s31k31.github.io/2020/05/01/JavaSpringBootCodeAudit-3-SQL-Injection/
- **Mapping:** the C.3 ORDER-BY extension + the D.3 Druid SQL-monitor cross-reference. Extraction → sqlmap.

---

## Theme E — Cloud / managed DBaaS (safe GET, offline classifier) ☁️🌐

Biggest net-new wins: an in-scope HTTPS GET or offline regex, epidemic, thin nuclei
coverage. Deliberately NOT duplicated: `ssrf_metadata_probe`, `analyze_config`,
`dependency_confusion`, bucket enumeration, Adminer/phpMyAdmin panels.

### E.1 Firebase RTDB / Firestore open rules ✅ (SHIPPED) — RANK 7/1
Implemented in `recon/firebase.py` + the `firebase_exposure` tool (self-scoped): harvests
`databaseURL`/`projectId` from the page + JS `firebaseConfig`, then one unauth
`GET <databaseURL>/.json?shallow=true` — 200 with JSON (not Permission denied) = open
rules. The RTDB backend host is scope-checked; a `projectId` is reported as a Firestore lead.

Security Rules with `if true`/`.read:true`; the project id sits in the app's
`firebaseConfig`. Comparitech attributes 100M+ leaked records/year. RTDB and Firestore
use different endpoints — probe both.
- **SAFE signal:** harvest `databaseURL`/`projectId` from page/JS, then one unauth
  `GET https://<project>.firebaseio.com/.json?shallow=true` — 200 with a JSON object (not
  `{"error":"Permission denied"}`) = open read. Firestore:
  `GET https://firestore.googleapis.com/v1/projects/<id>/databases/(default)/documents/<collection>`.
  `shallow=true` returns only top-level keys (no bulk pull).
- Source: https://firebase.google.com/docs/rules/insecure-rules · https://www.legba.app/adversary/exposures/exposed-firebase-database
- **Mapping:** new passive `recon/firebase.py` + `firebase_exposure`; reuse
  `secrets.py`/`crawl.py` JS extraction. Bulk dump/write → Strix via `leadpipe` kind `firebase_open`.

### E.2 Supabase RLS-off / anon-key full-table read ✅ (SHIPPED) — RANK 7/2
Implemented in `recon/supabase.py` + the `supabase_exposure` tool (self-scoped): harvests
the project URL + `anon` key (a JWT with `role:anon`) from the app JS, reads the PostgREST
schema at `/rest/v1/?apikey=`, then a per-table `?select=*&limit=1` read — a returned row =
RLS off. Rows are not surfaced; the backend host is scope-checked.

Supabase tables have Row-Level Security **off by default**; the `anon` key is public-by-
design (ships in the frontend) → full CRUD on every PostgREST-exposed table. CVE-2025-48757;
10.3% of analyzed Lovable apps shipped anon-readable tables.
- **SAFE signal:** harvest the project URL + `anon` JWT from the app JS
  (`supabase.createClient(...)`); `GET https://<ref>.supabase.co/rest/v1/?apikey=<anon>`
  enumerates tables; `GET /rest/v1/<table>?select=*&limit=1&apikey=<anon>` → a 200 row =
  RLS off. `limit=1` avoids bulk pull; using the app's own public key against its own API.
- Source: https://supabase.com/docs/guides/database/database-advisors?lint=0013_rls_disabled_in_public · https://modernpentest.com/blog/supabase-security-misconfigurations
- **Mapping:** new passive `recon/supabase.py` + `supabase_exposure`; the anon key is a
  JWT → reuse `web/jwt.py` to confirm `role:"anon"`. Native-edge (key-discovery → schema
  → per-table differential). Redact rows.

### E.3 Managed-DB DSN + warehouse-token classifier ✅ (SHIPPED) — RANK 6/3 (highest-confidence net-new)
Implemented offline in `recon/secrets.py` (`_RAW_PATTERNS`: PlanetScale `pscale_pw_`/`pscale_tkn_`,
Neon/Atlas-srv/Upstash/Redis-Cloud DSNs-with-creds, Turso libSQL) and `recon/config_audit.py`
(a `_MANAGED_DB` value-pattern table + `classify_managed_db`, surfaced in
`analyze_config` `summary.managed_db`; adds Snowflake/Databricks/Elastic-Cloud endpoints +
BigQuery service-account JSON). Zero traffic; DSN-with-creds/token = `critical`, bare
endpoint = `high`/`medium`. FP-guarded (a plain local/RDS DSN does not match).

Serverless/managed connection strings and warehouse tokens leak in JS/`.env`/`.git`/
sourcemaps → a direct path to the data with no exploit. Snowflake's 2024 UNC5537
mega-breach (AT&T, Ticketmaster, 165 orgs) was *entirely* stolen-credential + no-MFA.
- **SAFE signal:** offline regex over already-fetched bytes (zero traffic), redacted:
  PlanetScale (`pscale_pw_…`/`pscale_tkn_…`, `*.psdb.cloud`), Neon (`@ep-*.neon.tech`),
  Turso (`libsql://*.turso.io` + `TURSO_AUTH_TOKEN`), Atlas (`mongodb+srv://…@*.mongodb.net`),
  Upstash/Redis-Cloud (`rediss://…@*.upstash.io`), Snowflake (`*.snowflakecomputing.com`
  + PAT), BigQuery (service-account JSON `"private_key":"-----BEGIN PRIVATE KEY-----"`),
  Databricks (`*.cloud.databricks.com` + `dapi…`), Elastic Cloud (`*.found.io` + API key).
- Source: https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion · https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/generics/generic_database_assignment
- **Mapping:** add prefix-anchored patterns to `recon/secrets.py:_RAW_PATTERNS` **and** a
  `_MANAGED_DB` table in `config_audit.py` (mirror `_SIGNING_SECRETS`) — each hit
  classified `(service, "direct DB read/write with these creds", "critical")` and
  surfaced in `summary`. Offline, safe, highest confidence.

### E.4 Exposed managed-DB port classifier (RDS/CloudSQL/Redis/Mongo/Elastic) ❌ — RANK 4
A managed DB with a public IP + permissive security group (`0.0.0.0/0`). Datadog CSA
treats "publicly accessible RDS/CloudSQL" and "SG exposes risky ports" as distinct highs.
- **SAFE signal:** for each resolved in-scope IP, `internetdb_lookup` (already
  implemented, keyless) → flag DB ports/CPEs/tags: 3306, 5432, 1433, 27017, 6379,
  9200/9300, 8123/9000, 5984, 9042, 11211. Passive w.r.t. the target (queries Shodan
  InternetDB, not the DB). Escalate on managed-DB rDNS/CPE (`rds.amazonaws.com`,`cloudsql`).
- Source: https://securitylabs.datadoghq.com/cloud-security-atlas/vulnerabilities/rds-instance-publicly-accessible/ · https://securitylabs.datadoghq.com/cloud-security-atlas/vulnerabilities/security-group-open-to-internet/
- **Mapping:** `DB_PORT_MAP`/`classify_db_exposure(host)` in `intel/shodan.py` + an
  `exposed_db_probe` tool. Reachability confirm (not auth) → `leadpipe` kind `exposed_db` → Strix.

### E.5 DB admin dashboards reachable (Mongo-Express/pgAdmin/RedisInsight/ClickHouse `/play`) ✅ (SHIPPED) — RANK 5
Implemented — added Mongo-Express (`/db/admin`), pgAdmin (`/browser/`), ClickHouse `/play`, RedisInsight to `debug_exposure`'s `_PANELS` (path→signature engine).
Web DB consoles left in prod; Mongo-Express in particular ships with no auth
(`ME_CONFIG_BASICAUTH` unset) → full browse/query/delete. `debug_exposure` already
covers Adminer/phpMyAdmin with the same path→signature engine — one-line additions.
- **SAFE signal:** GET each path, confirm by a distinctive signature a soft-404 wouldn't
  contain: `/db/admin` + `mongo-express`, `/browser/` + `pgAdmin`, RedisInsight root,
  `/play` + `clickhouse`. GET-only, never a mutating query.
- Source: https://www.helpnetsecurity.com/2019/04/26/securing-mongo-express-web-administrative-interfaces/ · https://www.wiz.io/blog/wiz-research-uncovers-exposed-deepseek-database-leak
- **Mapping:** add entries to `web/debugpanel.py:_PANELS`. Cross-link to Theme F (these
  panels are prime SSRF targets).

### E.6 Backup/dump artifacts (`.sql`/`.bak`/mongodump) in object storage ✅ (SHIPPED) — RANK 6
Implemented — `recon/buckets.py` now parses a public-listable bucket's XML listing (`<Key>`/`<Name>`) for DB dump/backup keys (`extract_dump_keys`) and flags them `critical`; added `-dump`/`-sql`/`-database` name permutations.
DB dumps written to S3/GCS/Azure Blob that are public. GrayHatWarfare indexes ~470k open
buckets by extension — `.sql`/`.bak`/`.dump`/mongodump = a one-search data breach.
`recon/buckets.py` finds buckets but doesn't hunt dump keys.
- **SAFE signal:** for a `public-listable` bucket, parse the XML listing for keys matching
  `\.(sql|bak|dump|gz|tar|bson)$` and `mongodump|dump|backup|snapshot|db[-_]?export` —
  report key name + size only (HEAD, no body GET). RU/CIS scene documents
  `.sql`/`dump.sql`/`pg_dump` left in webroot too.
- Source: https://buckets.grayhatwarfare.com/ · https://fortwatch.ai/blog/public-cloud-buckets-s3-gcs-azure-leak-data
- **Mapping:** extend `recon/buckets.py` (`_BACKUP_KEY_RE`, dump-key listing; add
  `-dump`/`-backup`/`-sql` to `_SUFFIXES`); also probe found webroots via `content.py`.

### E.7 SSRF → IMDS → RDS-IAM / Secrets-Manager → DB (methodology + routing) ❌ — RANK 9
The end-to-end chain: `ssrf_metadata_probe` steals IAM creds from `169.254.169.254`, then
those creds mint an RDS IAM token / `GetSecretValue` / `rds-data` call to reach the DB.
- **SAFE signal:** stop at credential capture (already the `ssrf_metadata_probe` verdict)
  + **enumerate not use** — `sts:GetCallerIdentity`, `secretsmanager:ListSecrets`,
  `rds:DescribeDBInstances` (read-only) prove the creds reach the DB tier; never
  `GetSecretValue` on a live secret or open a DB session (Strix under human confirmation).
- Source: https://hackingthe.cloud/aws/exploitation/ec2-metadata-ssrf/ · https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-services/aws-secrets-manager-enum
- **Mapping:** no new probe (would duplicate `ssrf_metadata_probe`) — a
  `knowledge/privesc_data.py` entry + a `leadpipe` route kind `cloud_cred_to_db` (family
  `cloud`, route `strix`). Public RDS/Aurora/EBS snapshots (creds-gated `Describe*`) →
  **delegate to Prowler/CSPM**, not a web-recon MCP.

---

## Theme F — SSRF → internal datastore protocols 🌐🇨🇳

`ssrf_metadata_probe` turns *full-read* SSRF into cloud-cred theft; the gap is
**protocol-level** reach into internal DBs. Detection-only; weaponization → Strix
(matches the shipped `desync→strix` precedent).

### F.1 gopher:// / dict:// smuggling to Redis/Memcached/MySQL/Postgres ✅ (SHIPPED) — RANK 10/7
Implemented in `web/ssrf_protocol.py` + the `ssrf_protocol_probe` tool (intrusive): a
scheme-deref lane (per-scheme `gopher`/`dict`/`ftp` OAST canaries + an `http` control, each
with its own token for attribution — gopher/dict/ftp callbacks need a DNS/TCP OAST via
`oast_configure`, the built-in HTTP catcher sees only the http control) and an internal-port
reachability differential (`http://127.0.0.1:<db_port>/` vs a closed-port control). No
payload bytes delivered; the gopher `SET`/`CONFIG` weaponization → Strix.

An SSRF sink that accepts arbitrary schemes sends raw bytes to a TCP port — enough to
speak Redis RESP (`CONFIG SET dir` → cron RCE), memcached, or a MySQL/Postgres handshake.
Gopherus generates payloads for 3306/11211/6379/9000. The classic blind-SSRF-to-RCE
escalation; also the CN Redis-未授权 chain.
- **SAFE signal (no payload delivery):** (1) scheme-acceptance — inject
  `gopher://<oast>:80/_test` and `dict://<oast>:11211/stat` into the SSRF param; an OAST
  TCP/DNS hit proves the sink dereferences non-HTTP schemes (capability, not
  exploitation). (2) internal-port reachability via a response/timing differential to
  `http://127.0.0.1:6379/` vs a closed port. **Never** send a real `SET`/`CONFIG` — Strix's job.
- Source: https://github.com/tarunkant/Gopherus · https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf
- **Mapping:** new `ssrf_protocol_probe` reusing `web/inject.py` + `intel/oast.py`: a
  `SCHEME_TARGETS` list (gopher/dict/file/ftp against an OAST canary) + internal-DB-port
  timing twins; verdict = OAST callback or open/closed timing delta. Templated gopher
  payloads go in the injection KB (per Gopherus), not a bridged interactive generator.
  `leadpipe` kind `ssrf_protocol` → Strix.

### F.2 DNS-rebinding to internal DB (TOCTOU SSRF-guard bypass) 🟡 (needs a DNS-capable OAST) — RANK 10 (companion)
> Deferred: the built-in OAST catcher is HTTP-only, so serving a rebinding A-record needs `intel/oast_server.py` to gain a DNS listener (or a configured interactsh). Tracked as a follow-up; the methodology below stands.
An SSRF allowlist that validates the hostname then re-resolves at fetch time is defeated
by a rebinding domain (public IP first, then `169.254.169.254`/`127.0.0.1`/internal DB).
Live 2026 CVEs (CVE-2026-27826 MCP-Atlassian TOCTOU; Burp MCP DNS-rebinding SSRF H1
#3176157).
- **SAFE signal:** point the SSRF param at a MoonMCP rebinding canary (A-record flips
  public→`127.0.0.1` after 1s TTL); an inbound request to the rebind listener = the guard
  re-resolves without pinning = vulnerable. The canary rebinds to loopback, not a live DB.
- Source: https://unit42.paloaltonetworks.com/dns-rebinding/ · https://www.nccgroup.com/research/state-of-dns-rebinding-in-2023/
- **Mapping:** extend `intel/oast_server.py` to optionally serve a rebinding A-record for
  a minted canary; `ssrf_protocol_probe` correlates the hit. If self-hosting a rebinder
  is out of budget → KB + Strix delegate (Singularity).

### F.3 Neo4j Cypher injection + APOC SSRF/LFI 🟡 (KB exists) — RANK 13
Concatenated Cypher is injectable; the escalation is APOC — `apoc.load.jsonParams` issues
attacker-defined HTTP requests → internal SSRF (IMDS creds), `apoc.load.json('file:///etc/passwd')`
→ LFI, `LOAD CSV FROM '<url>'` → OOB exfil.
- **SAFE signal:** error-signature differential (`Neo.ClientError.Statement.SyntaxError`)
  + an OAST canary — inject a Cypher fragment calling `LOAD CSV FROM 'http://<oast>/…'` and
  confirm the callback. Real IMDS/`/etc/passwd` read → Strix.
- Source: https://book.hacktricks.xyz/pentesting-web/sql-injection/cypher-injection-neo4j · https://www.varonis.com/blog/neo4jection-secrets-data-and-cloud-exploits
- **Mapping:** enrich the existing KB `cypher-injection` class with APOC SSRF/LFI payloads
  + error signatures; add a Cypher-SSRF canary target to the SSRF/OAST probe set (F.1).

---

## Theme G — Regional DBMS fingerprints, default creds, WAFs & panels (cheap KB packs) 🇨🇳🇰🇷🇯🇵

Highest-ROI *net-new knowledge* — English tools don't fingerprint these at all. Detection
= port/banner/HTTP fingerprint + a "ships with known default" flag; the actual login is
**delegated** (never brute-forced by MoonMCP).

### G.1 Chinese domestic / 信创 DBMS fingerprint + default creds ❌ — RANK B
| DBMS | Port(s) | Default/weak cred (community-reported) | Safe signal |
|---|---|---|---|
| 达梦 DM | 5236 | `SYSDBA/SYSDBA` (≤v7) | TCP banner fingerprint |
| 人大金仓 KingbaseES | 54321 | `system` / era defaults | PG-wire-like banner |
| GBase 8a/8s | 5258 / 5432 | vendor defaults | banner |
| OceanBase | 2881/2882 | `root@sys` **empty password** | MySQL handshake, empty-pw tell |
| TiDB | 4000 / 10080 / PD 2379 | unauth **status**/PD (not creds) | `GET :10080/status` unauth |
| TDengine | 6041 / 6030 | `root/taosdata` | `GET :6041/` needs Auth → default-cred flag |
| Nebula Graph | 9669 | `root/nebula` | banner/dashboard |
| GaussDB | 8000 | vendor defaults | banner |
- Source: https://www.freebuf.com/articles/database/338011.html (Kingbase 等保) · https://ask.oceanbase.com/t/topic/13700367 (OceanBase empty root) · https://tidb.net/blog/c1c55601 (TiDB PD) · https://docs.taosdata.com/reference/connector/rest-api/ (TDengine 6041)
- **Mapping:** banners/ports/dashboards in `recon/fingerprint.py` + a
  `knowledge/vulns_data.py` default-cred KB; TiDB-status & PD-2379 unauth reads →
  `db_exposure`. Login attempt → Strix (agent lane: fingerprint → "try known default").

### G.2 Korean domestic DBMS error signatures + default creds ❌ — RANK KR-A
Korean public sector/finance runs **Tibero** (domestic Oracle-replacement), **CUBRID**
(gov portals), **Altibase** (telecom/finance). MoonMCP's SQLi error-signature DB has zero
coverage → a SQLi on a `.go.kr` Tibero/CUBRID backend reports "unknown DBMS".
- **SAFE signal (passive error-text match):** Tibero `TBR-\d{4,5}` + `com\.tmax\.tibero\.jdbc`
  (also emulates Oracle `ORA-` → tag ambiguous); CUBRID `cubrid\.jdbc\.driver\.CUBRIDException`;
  Altibase `Altibase\.jdbc\.driver`. Default creds: Tibero `SYS/tibero`, `SYSCAT/syscat`;
  **CUBRID `dba` has NO password** on fresh install (CWE-1392).
- Source: https://docs.tibero.com/en_tibero-technical-guides/topics/security/account-management · https://www.cubrid.org/manual/en/latest/security.html
- **Mapping:** add the three drivers' signatures to `injections_data.py` (sqli class) —
  zero new code path, `sqli_probe`/`match_injection_signatures` immediately gain
  domestic-DBMS fingerprinting; + a default-cred KB entry.

### G.3 Cassandra / ScyllaDB CQL injection ❌ — RANK 12
Concatenated CQL is injectable, constrained (drivers reject trailing comments/multi-
statements) → boolean conditions + `ALLOW FILTERING`. KB has no `cql-injection` class.
- **SAFE signal:** SQLi-style boolean differential + error-signature match
  (`SyntaxException`, `InvalidRequest`, `no viable alternative`, `ALLOW FILTERING`).
- Source: https://www.invicti.com/blog/web-security/investigating-cql-injection-apache-cassandra
- **Mapping:** new KB class `cql-injection` in `injections_data.py` with signatures wired
  into `match_signatures()`; active differential handled by `sqli_probe`/nuclei DAST.

### G.4 Adminer arbitrary-server file-read + SSRF (CVE-2021-21311) 🟡 (panel found) — RANK JP-KR
`debug_exposure` finds the Adminer panel; the interesting part is Adminer connects to an
**arbitrary DB host** → SSRF (CVE-2021-21311, CISA KEV, <4.7.9) and rogue-MySQL
`LOAD DATA LOCAL INFILE` file-read — no creds on the target's own DB needed.
- **SAFE signal:** confirm panel (done), **parse the version footer** → flag <4.7.9
  (SSRF) / <4.6.3 (file-read); flag that the host field is user-controllable. Blind SSRF
  confirm via an OAST canary as the DB host (callback = reachable), no exploitation.
- Source: https://nvd.nist.gov/vuln/detail/CVE-2021-21311 · https://medium.com/@knownsec404team/mysql-client-arbitrary-file-reading-attack-chain-extension-727bb63f578c
- **Mapping:** enrich `debug_exposure`'s Adminer signature with version→CVE + an
  `arbitrary_db_host:true` flag; optional OAST-canary reachability check (intrusive).
  Rogue-MySQL file-read → Strix.

### G.5 APAC / regional WAF fingerprints ❌ — RANK JP-KR
MoonMCP's WAF DB is CN/RU/global. Missing: **WAPPLES** (#1 APAC share) + **MonitorApp
AIWAF** (Korean gov/finance), **Scutum / Cloudbric / 攻撃遮断くん** (Japan). Scutum is
explicitly ML-based not signature-based → down-weight naïve comment/case evasion against it.
- **SAFE signal:** passive header/cookie/block-page fingerprints in `web/waf.py:_SIGNATURES`.
- Source: https://www.scutum.jp/information/waf_tech_blog/2020/07/waf-blog-073.html · https://www.monitorapp.com/en/products/aiwaf
- **Mapping:** add APAC signatures to `web/waf.py`; the "which SQLi encoding works per-WAF"
  note + the Scutum "not signature-based" flag are native reasoning aids for C.5.

### G.6 Regional DB-backed web stacks (EC-CUBE / Gnuboard / XpressEngine) ❌ — RANK JP-KR
**EC-CUBE** (Japan's dominant OSS e-commerce, long SQLi history, CVE-2015-7784),
**Gnuboard / XpressEngine** (KR PHP+MySQL CMS) — `.co.kr`/`.jp` SME blanket coverage.
- **SAFE signal:** favicon-hash / header / cookie / body fingerprint → version → CVE
  lookup (never send the exploit). Same pattern as the CN/RU/LATAM/EU stack packs.
- Source: https://jvn.jp/jp/JVN55545372/index.html (EC-CUBE CVE-2015-7784) · https://www.ec-cube.net/info/weakness/
- **Mapping:** extend `stack_probe`/`fingerprint.py` with an EC-CUBE + Gnuboard +
  XpressEngine pack → version→CVE (delegate to nuclei once fingerprinted). Verify each
  version→CVE per target (Gnuboard/XpressEngine CVE ids are leads, not invented).

### G.7 SQLi getshell-feasibility differential (MySQL/MSSQL/PostgreSQL) ❌ — RANK B
After `sqli_probe` confirms injection, benign capability reads tell the operator whether
OUTFILE/UDF/`xp_cmdshell`/`COPY PROGRAM` is even reachable — **without** writing a file or
running a command: MySQL `@@secure_file_priv` empty vs NULL, `current_user()`=root,
`@@plugin_dir`; MSSQL `IS_SRVROLEMEMBER('sysadmin')`; PostgreSQL `is_superuser` /
`pg_execute_server_program`.
- **SAFE signal:** each is a benign boolean/read differential, no side effect.
- Source: https://www.cnblogs.com/jerrylocker/p/10890128.html · https://www.hackingarticles.in/mssql-for-pentester-command-execution-with-xp_cmdshell/ · https://nvd.nist.gov/vuln/detail/cve-2019-9193
- **Mapping:** a "getshell-feasibility" read-set layered on `sqli_probe`; webshell write /
  `--os-shell` / `COPY PROGRAM` exec → sqlmap (`--file-write`/`--os-shell`) / Strix.

---

## Theme H — Delegate to nuclei / Strix (fingerprint natively, don't re-implement)

Version→CVE matches and single static unauth reads are commodity — list them in
`external/nuclei.py:NUCLEI_DELEGATE`, keep only the differential native:
- **Kibana** Timelion PP RCE CVE-2019-7609, LFI CVE-2018-17246 — `GET /api/status`
  version → delegate.
- **Elasticsearch** Groovy RCE CVE-2015-1427 — ES version fingerprint → delegate.
- **PostgreSQL** `COPY … FROM PROGRAM` RCE (CVE-2019-9193, needs superuser) — G.7
  feasibility read native; exec → sqlmap/Strix.
- CouchDB/ES/InfluxDB/Redis/memcached CVE templates — nuclei has them; native probe earns
  its place only by producing a scoped minimal-data recon finding.

---

## Tooling strategy — delegate / build / skip (avoid reinvention)

The "exploit the DB once found" lane is saturated. Mirror the `NUCLEI_DELEGATE` /
`NATIVE_EDGE` split:

| DB capability | Verdict | How |
|---|---|---|
| Deep SQLi exploit (dump, tamper/WAF bypass, `--os-shell`, file R/W) | **Delegate** | `sqlmap` (already in `KNOWN_TOOLS`): `--technique --dbms --tamper --level --risk` |
| Blind / cloud-WAF SQLi complement | **Delegate** | add `ghauri` `ToolSpec` (intrusive): `-u URL --batch --dbs` |
| Oracle / MSSQL server enumeration | **Delegate (enum only)** | `odat` (Oracle), `msdat`/`impacket mssqlclient`/`NetExec` (MSSQL) — RCE steps → Strix |
| Commodity DB unauth / default-login / exposure + reflected-param SQLi | **Delegate** | `nuclei` via `vuln_scan` — `-tags redis,mongodb,elasticsearch,couchdb,default-login,exposure` + `-dast` |
| SSRF→DB gopher payloads | **Build (tiny KB)** | templated `gopher://` MySQL/PG/Redis payloads in the injection KB; don't bridge the interactive Gopherus generator |
| **Unauth DB detection + fingerprint (raw-socket)** | **BUILD native** | `db_exposure` (Theme B) — non-destructive read-only handshakes, scope-gated, lead-emitting |
| **NoSQL operator injection / ORM leak / second-order / OOB / JSON-WAF** | **BUILD native** | Themes A/C/D — structurally nuclei-blind differentials |
| **DSN discovery + DBaaS misconfig** | **BUILD** | Theme E — offline classifier + safe GET |
| Finding → PoC | **Wire (exists)** | `promote_lead(kind="sqli"/"unauth_db"/"ssrf"/…)` → Strix |
| Redis master-slave RCE (redis-rogue-server) | **SKIP — Strix only** | destructive (writes + loads `.so` on target) — never native, never bridge |
| DB credential brute (hydra/medusa) | **SKIP (gate hard)** | usually out of bug-bounty scope; noisy — only behind explicit authorization |
| NoSQLMap / jSQL / sqlmc / mongoaudit | **SKIP** | unmaintained / interactive / redundant with sqlmap + native probes |
| Public RDS/EBS snapshot sweep | **Delegate CSPM** | Prowler/CloudSploit own multi-region `Describe*`; creds-gated |

---

## Deliberately out of scope (safety)

Exploitation is never automated. Every entry above is a detection/indicator — a
read-only fetch, a benign two-request differential, an error-string match, or an OAST
reachability callback. No detection-path probe writes data, changes config, sleeps as a
DoS, loads a module, drops a UDF, or runs a command. Weaponization (dump, `--os-shell`,
`CONFIG SET`/`SLAVEOF`/`MODULE LOAD`, UDF, painless/Groovy/ChromaToast RCE, JNDI/gadget
chains, credential brute-force) is handed to **sqlmap** (commodity) or **Strix** (PoC)
under human confirmation. No pirated tooling.

## Honest coverage gaps (from the research)

- **TDengine** technique research is thin — only default-cred / `POST /rest/sql`
  fingerprinting is well-sourced; treat deep testing as a delegate.
- **Pinecone** is closed SaaS — its "exposure" is API-key leakage (belongs in
  `extract_secrets`/E.3), not a store probe.
- **Server-side prototype pollution** carries genuine process-wide persistence risk →
  reflected-gadget-only detection + Strix confirmation.
- Several CN/HackTricks/elttam blog URLs return HTTP 403 to automated fetches (anti-bot);
  those payloads/signals were corroborated from GitHub-raw PayloadsAllTheThings mirrors
  and official docs. Regional CVE ids (Gnuboard/XpressEngine) are **leads to verify per
  target**, not asserted facts.
