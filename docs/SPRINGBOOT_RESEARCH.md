# Spring Boot — offensive attack surface & detection research

> **Framing.** This is a *detection-oriented* reference for MoonMCP, the same discipline as
> `DATABASE_RESEARCH.md`: for every issue we record **what it leaks**, **how to confirm it
> benignly** (a single request, a differential, or an OAST callback), the **CVE/source**, and the
> **severity** — never a weaponized exploit chain. Weaponization (webshell write, gadget delivery,
> live RCE) is delegated to Strix under human confirmation. Everything below is public
> vulnerability-detection data (CVE signatures, actuator behaviours, nuclei-template-class checks).

Spring Boot is the dominant JVM web stack; its blast radius comes less from the framework core than
from **operational defaults** — Actuator management endpoints, Spring Cloud add-ons, and a long tail
of SpEL / data-binding / deserialization CVEs. MoonMCP already ships `actuator_probe` (a narrow
slice: `/env` secrets, `/heapdump`, Jolokia, `/mappings`). This document maps the *whole* surface so
that slice can grow into a full Spring detection suite.

Legend: **Confirm** = benign signal that proves the condition · **S** = severity (C/H/M/L/Info).

---

## 1. Fingerprinting Spring Boot (and deriving the version)

You must confirm the target *is* Spring Boot before Spring-specific probes, to avoid FP noise.

| Signal | How to read it |
| --- | --- |
| **Whitelabel Error Page** | Request a random path; the default error HTML contains `Whitelabel Error Page` and *"This application has no explicit mapping for /error"*. Strong Boot tell. |
| **Error JSON shape** | With `Accept: application/json`, an error returns `{"timestamp":…,"status":…,"error":…,"path":…}` (and `trace` when `server.error.include-stacktrace` is loose). The exact field set/order is a Boot fingerprint. |
| **`/actuator` base** | Boot 2/3: `GET /actuator` → HATEOAS `{"_links":{"self":…,"health":…,…}}`. The link set enumerates *which* endpoints are exposed. Boot 1.x: endpoints live flat at root (`/env`, `/health`, `/metrics`, `/beans`, `/dump`, `/trace`). |
| **`X-Application-Context` header** | Boot 1.x leaks the application context id (name:profile:port) in this response header. |
| **Favicon** | The stock Boot favicon (green leaf) has a well-known mmh3 favicon hash — feed `favicon_hash`; a match is a passive Boot tell. |
| **Default ports** | App `8080`; a separate `management.server.port` is often `8081`/`9001` and frequently *less* protected than the app port — always probe the management port too. |
| **springdoc / Swagger** | `/v3/api-docs`, `/swagger-ui/index.html`, `/swagger-ui.html` → OpenAPI enumeration + a version hint. |
| **Version derivation** | Order of preference: `GET /actuator/info` (may carry `build.version` / `git.*` from `build-info.properties`/`git.properties`); `/actuator/health` component versions; jar/`BOOT-INF` layout in any leaked path; the Actuator link-set shape (`/httpexchanges` = Boot 3, `/httptrace` = Boot 2, flat = Boot 1). Map the derived version to the CVE matrix below. |

**MoonMCP fit:** most of this belongs in `fingerprint` + a small `spring` version→CVE table (mirrors
`appliance.py`). `favicon_hash` already exists; `debug_exposure` already flags some panels.

---

## 2. Actuator endpoints — the operational blast radius

Actuator is the single richest Spring surface. Boot 2/3 gate endpoints behind
`management.endpoints.web.exposure.include`; the classic misconfig is `include=*` with **no**
Spring Security in front. Probe both the app port and any management port.

| Endpoint | Leaks / does | Confirm (unauth) | S |
| --- | --- | --- | --- |
| `/env`, `/env/{name}` | Every resolved property: DB DSNs, cloud keys, `spring.*`, system env. Secret-named keys are masked `******` since Boot 2 **only** for matching names — non-standard key names leak in clear. | 200 JSON with `propertySources[]` (Boot 2/3) or a flat map (Boot 1). Unmasked secret-named value = real leak. | H |
| `/heapdump` | Full JVM heap (HPROF) — every in-memory secret/session/token. Often GB-sized. | First bytes match HPROF magic `JAVA PROFILE 1.0` via a bounded/Range read — never download the whole dump. | C |
| `/threaddump` (Boot1 `/dump`) | Thread stacks; can leak inflight data / class internals. | 200 JSON `{"threads":[…]}`. | M |
| `/httpexchanges` (Boot3) / `/httptrace` (Boot2) | Last ~100 HTTP request/response pairs **including headers & cookies** → live session tokens / auth headers of *other users*. | 200 JSON `{"exchanges":[…]}` / `{"traces":[…]}` carrying `Authorization`/`Cookie` values. | H |
| `/sessions` | Spring Session store: list + **delete** sessions → session fixation/hijack. | 200 JSON of session ids; DELETE supported. | H |
| `/loggers`, `/loggers/{name}` | Read log config; **POST** changes a logger level at runtime (info-leak amplifier, occasional log injection). | GET 200 `{"levels":…,"loggers":…}`; POST accepted = writable. | M |
| `/mappings` | Full route map → hidden/undocumented endpoints. | 200 JSON with `dispatcherServlet`/`mappings`. | L |
| `/beans` | Spring bean graph (internal architecture). | 200 JSON `{"beans":…}`. | L |
| `/configprops` | Bound `@ConfigurationProperties` (like `/env`, often with secrets). | 200 JSON of prop trees. | M |
| `/metrics`, `/metrics/{name}` | Metric names/values (some leak internal hostnames, counts). | 200 JSON `{"names":[…]}`. | L |
| `/scheduledtasks`, `/quartz` | Scheduled/Quartz jobs (internal logic disclosure). | 200 JSON. | L |
| `/caches`, `/conditions`, `/startup`, `/health`, `/info` | Cache names / autoconfig conditions / startup steps / health & build info. `/health` with `show-details` leaks component internals. | 200 JSON per endpoint. | L/Info |
| `/refresh` (Spring Cloud) | Re-reads config → **the trigger** that turns a writable `/env` override into effect. | POST 200 returning changed keys = the env→refresh chain is live. | H (chain) |
| `/restart`, `/shutdown` (Spring Cloud / disabled by default) | Restart context / graceful shutdown → **DoS**. | POST accepted. | M (DoS) |
| `/jolokia` | JMX-over-HTTP. `/jolokia/version` confirms; `/jolokia/list` enumerates MBeans. RCE-capable MBeans (MLet `getMBeansFromURL`, `createJNDIRealm`, Logback `reloadByURL`, DiagnosticCommand) — **flag, never invoke**. | `/jolokia/version` → `{"value":{"agent":…}}`; `/jolokia/list` names the MBeans. | H |
| `/gateway` (Spring Cloud Gateway) | `GET /gateway/routes` lists routes; a route filter accepts **SpEL** → CVE-2022-22947 RCE (see §3). | `GET /actuator/gateway/routes` 200 = the SpEL-injection surface is present. | H |

**Known RCE chains (detection framing — MoonMCP flags the *precondition*, Strix weaponizes):**
- **`/env` write → `/refresh`.** POST `/actuator/env` sets a property; `/actuator/refresh` applies it.
  Classic pivots: a malicious `eureka.client.serviceUrl.defaultZone` (→ XStream deser on a rogue
  Eureka), `spring.datasource.*`/`spring.cloud...` to a rogue H2/MySQL (JDBC deserialization), or a
  logging-config URL. **Detect** by confirming `/env` accepts a *benign no-op* POST (then revert) —
  writability is the finding, not the gadget.
- **Jolokia MBean** MLet/JNDI/Logback chains — detect by *naming* the dangerous MBean from
  `/jolokia/list`; never call it.
- **`/gateway` SpEL** — see §3 (confirmable by arithmetic reflection or OAST without RCE).

**MoonMCP fit:** `actuator_probe` covers `/env` secrets + `/heapdump` + Jolokia + `/mappings`. **Gaps
to add:** `/httpexchanges`+`/httptrace` (token theft — high value), `/sessions`, `/gateway` presence
+ SpEL confirm, `/env`-writable + `/refresh` detection (benign no-op), `/loggers` writable,
`/configprops`.

---

## 3. SpEL / expression-injection & deserialization CVE family

The highest-severity Spring class. Detection favours an **OAST callback** or an **arithmetic
reflection** (`#{7*7}` → `49`) so nothing executes beyond a DNS/HTTP ping or a math echo.

| CVE | Component / trigger | Detection signal (benign) | S |
| --- | --- | --- | --- |
| **CVE-2022-22965 (Spring4Shell)** | Spring MVC/WebFlux data-binding on JDK 9+, WAR-on-Tomcat; binds `class.module.classLoader.*`. | Send a benign binding param (`class.module.classLoader.DefaultAssertionStatus=…`) and diff: a vulnerable binder accepts it (200 / no 400) where a patched/non-applicable app rejects it. **Do not** set Tomcat `pipeline`/`pattern` properties (that writes a shell). | C |
| **CVE-2022-22963** | Spring Cloud Function ≤3.2.2; header `spring.cloud.function.routing-expression` is evaluated as **SpEL** on a POST to the function router. | POST the function endpoint with the header set to an **OAST-only** SpEL (`T(java.net.InetAddress).getByName('<oast>')`) → an OAST DNS hit confirms. Pure detection: no command runs. | C |
| **CVE-2022-22947** | Spring Cloud Gateway Actuator; a route filter arg is SpEL. Requires `/actuator/gateway` exposed. | **Stateful:** add a route whose filter value is `#{1+1}` (or an OAST SpEL) → `/gateway/refresh` → read the route back / OAST → confirm → **delete the route** (revert). Arithmetic/OAST only. | C |
| **CVE-2022-22950** | Spring Framework SpEL — crafted expressions cause **DoS** (resource exhaustion). | Version-based (≤5.3.16 / ≤5.2.19); avoid actually triggering the DoS. | M |
| **CVE-2018-1273** | Spring Data Commons — SpEL via a property-path form field (`…[#this…]…`). | SpEL with OAST/arithmetic on the vulnerable form/param → OAST hit. | C |
| **CVE-2017-8046** | Spring Data REST — a JSON-Patch `path` is SpEL. | `PATCH` with `Content-Type: application/json-patch+json` and an OAST/arith SpEL path → OAST hit. | C |
| **CVE-2016-1000027** | Spring `HttpInvokerServiceExporter` deserializes Java objects from the POST body. | Passive: endpoint accepts `Content-Type: application/x-java-serialized-object`. Active: a `URLDNS` gadget → OAST DNS hit (no code exec). Overlaps `deserialize_fingerprint`. | C |

**MoonMCP fit:** `spring_cloud_function_probe` (CVE-2022-22963) and the `/gateway` SpEL confirm are
the two highest-value new **OAST** probes (both cleanly OAST-confirmable, both very common in the
wild). Spring4Shell is a benign-binding differential (a `spring4shell_probe`). CVE-2016-1000027
belongs with the existing deserialization lane.

---

## 4. Spring Security auth-bypass CVEs

Mostly **differential** detections (a protected path flips `401/403 → 2xx`), several overlapping our
`path_bypass_probe` / `open_redirect`.

| CVE | Mechanism | Detection signal | S |
| --- | --- | --- | --- |
| **CVE-2022-22978** | `RegexRequestMatcher` with a `.`-containing regex matches newline → append `%0a`/`\n` to bypass an actuator/admin authz rule. | Differential: `GET /protected` = 401/403; `GET /protected%0aanything` (or a trailing-newline variant) = 2xx. | H |
| **CVE-2023-34034** | Spring Security WebFlux/MVC `**` pattern vs router mismatch → authorization bypass. | Differential on a `/**`-protected route with a crafted path segment. | H |
| **CVE-2024-22243 / -22257 / -22259 / -22262** | `UriComponentsBuilder` host/authority parsing confusion (`[`, `\`, `//host`) → open redirect / SSRF. | Open-redirect differential (attacker string echoed into `Location`) — overlaps `open_redirect`. | M |
| **CVE-2025-22228** | `BCryptPasswordEncoder` accepts passwords > 72 bytes (length-truncation) → auth weakening. | Version-based; not remotely differentiable. | M |
| **CVE-2025-22223** | `@EnableMethodSecurity` authorization can be bypassed under specific conditions. | Version-based. | M |
| **Pattern: actuator behind Security, path-normalization bypass** | Front proxy / Security matcher and the servlet disagree on normalization: `/actuator/;/env`, `/actuator/%0a/env`, `//actuator/env`, `/actuator/env/`, `/actuator/./env`, matrix `;x`, `/actuator/%2e/env`. | Differential: `/actuator/env` = 401/403 but a normalization twin = 200 JSON `propertySources`. | H |

**MoonMCP fit:** the **actuator path-normalization bypass** is the standout — a Spring-tuned lane on
`path_bypass_probe` pointed at `/actuator/*` (very common: teams "protect" actuator with a Security
matcher that a twin defeats). The UriComponentsBuilder set folds into `open_redirect`.

---

## 5. Spring Cloud & satellites

| Target | Issue | Detection signal | S |
| --- | --- | --- | --- |
| **Spring Cloud Config Server** | Path traversal **CVE-2020-5410** (`/{app}/{profile}/{label}/..%252f..%252f…`) and **CVE-2019-3799** (placeholder path) → arbitrary file read. | Traversal differential: read a benign canary path and compare to a control; a 200 with file content = vulnerable. | H |
| **Netflix Eureka** | Registry unauth by default; XStream XML deserialization on registration → RCE (frequent `/env`+`/refresh` pivot target). | `GET /eureka/apps` unauth 200 (XML/JSON app registry) = exposed. | H |
| **Spring Boot Admin** | Often no auth; proxies every registered app's Actuator; historical CSRF/XSS. | `/applications` / the SBA UI reachable unauth = exposed (and pivots to all clients' actuator). | H |
| **Spring Cloud Data Flow** | **CVE-2024-22263** (arbitrary file write / SpEL via the Skipper/DataFlow API); older CVE-2024-37084. | Version/endpoint-based; the DataFlow/Skipper API reachable unauth. | H |
| **Spring Cloud Gateway** | Actuator SpEL (§3, CVE-2022-22947); also route-enumeration disclosure. | `/actuator/gateway/routes` reachable. | H |

**MoonMCP fit:** `spring_config_traversal_probe` (canary-read differential) and Eureka/SBA exposure
lanes (deterministic unauth GETs) — natural extensions of `stack_probe`/`db_exposure` style.

---

## 6. Defaults & misconfigurations

| Item | Detection signal | S |
| --- | --- | --- |
| **Unauth `/actuator`** | The `/actuator` HATEOAS index reachable with sensitive endpoints in `_links`. | H |
| **H2 console `/h2-console`** | Login page present; if a JDBC URL is settable, `CREATE ALIAS`/`INIT` → RCE (CVE-2021-42392, CVE-2022-23221 JNDI). **Detect** the console's presence only. | H |
| **Verbose stacktraces** | `server.error.include-stacktrace=always` → `trace` field / full Java stack in error JSON (class/path/dependency disclosure). | M |
| **Swagger / springdoc** | `/v3/api-docs`, `/swagger-ui/index.html` reachable → full API map. | L |
| **Groovy / JMX consoles, Spring Boot DevTools** | DevTools remote (`/.~~spring-boot!~/restart`) / consoles left enabled. | H |
| **Default creds** | Spring Boot Admin, Eureka, embedded consoles with shipped/no credentials. | H |

---

## 7. Detection-signature summary (probe → signal → severity)

| # | Issue | Benign probe | Confirmation signal | S | nuclei? |
| --- | --- | --- | --- | --- | --- |
| 1 | Boot fingerprint | random path + `Accept: json` | Whitelabel / error-JSON shape / `/actuator` `_links` | Info | yes |
| 2 | `/env` secret leak | `GET /actuator/env` | unmasked secret-named value | H | partial |
| 3 | `/heapdump` | `GET /actuator/heapdump` (Range 0-63) | HPROF magic | C | yes |
| 4 | `/httpexchanges` token theft | `GET /actuator/httpexchanges` | exchange list w/ `Authorization`/`Cookie` | H | no (value-inspecting) |
| 5 | `/sessions` | `GET /actuator/sessions` | session id list | H | partial |
| 6 | `/gateway` SpEL surface | `GET /actuator/gateway/routes` | routes JSON 200 | H | partial |
| 7 | Gateway SpEL RCE (CVE-2022-22947) | add route `#{1+1}` → refresh → read → **delete** | `2` reflected / OAST hit | C | no (stateful) |
| 8 | Cloud Function SpEL (CVE-2022-22963) | POST fn + `spring.cloud.function.routing-expression` OAST SpEL | OAST DNS hit | C | yes (single-shot) |
| 9 | Spring4Shell (CVE-2022-22965) | benign `class.module.classLoader.*` binding | accept/400 differential | C | yes |
| 10 | Jolokia RCE MBeans | `/jolokia/list` | dangerous MBean names present | H | partial |
| 11 | `/env` write→refresh chain | benign no-op POST `/env` → `/refresh` → revert | POST accepted + refresh applies | H | no (stateful) |
| 12 | Actuator authz path-bypass | `/actuator/env` vs normalization twins | twin returns `propertySources` | H | no (differential) |
| 13 | Config Server traversal (CVE-2020-5410) | canary traversal read | file content vs control | H | yes |
| 14 | Eureka / SBA exposure | `GET /eureka/apps`, SBA UI | unauth registry / admin | H | yes |
| 15 | H2 console | `GET /h2-console` | login page | H | yes |
| 16 | Verbose stacktrace | error path | `trace` field in JSON | M | yes |
| 17 | Swagger/springdoc | `/v3/api-docs` | OpenAPI doc | L | yes |

**Nuclei-delegation read:** rows 1–3, 8–9, 13–17 are single-request checks nuclei already expresses —
delegate to `vuln_scan`. The **native, high-value** rows for MoonMCP are the **stateful / differential
/ value-inspecting** ones nuclei can't cleanly do: **#4** (`/httpexchanges` token-value inspection),
**#7** (gateway SpEL add→refresh→trigger→**revert**), **#11** (`/env`-write→refresh no-op detection
with revert), **#12** (actuator authz path-normalization differential), and **#6** gateway-surface
gating.

---

## 8. MoonMCP build shortlist (ranked)

Grown from `actuator_probe`, detection-only, differential/OAST-first, reusing existing HTTP+OAST
plumbing:

1. **`spring_cloud_function_probe`** (CVE-2022-22963) — `routing-expression` header SpEL → **OAST**
   callback. Single-shot, cleanly confirmable, very common. → `intrusive`.
2. **Extend `actuator_probe`** — add `/httpexchanges`+`/httptrace` (auth-token theft, value-inspecting),
   `/sessions`, `/gateway/routes` surface, `/env`-writable + `/refresh` detection (benign no-op +
   revert), `/configprops`, `/loggers`-writable. Highest coverage-per-effort.
3. **`spring_gateway_spel_probe`** (CVE-2022-22947) — stateful add-route `#{1+1}`/OAST → refresh →
   confirm → **delete** (self-reverting). → `intrusive`.
4. **`spring4shell_probe`** (CVE-2022-22965) — benign `class.module.classLoader.*` binding
   differential (never touches Tomcat pipeline props). → `intrusive`.
5. **Actuator authz path-bypass lane** on `path_bypass_probe` — Spring-tuned twins against
   `/actuator/*` (`;/`, `%0a`, `//`, `%2e`, trailing-slash). → enhancement.
6. **`spring_config_traversal_probe`** (CVE-2020-5410) + **Eureka/SBA exposure** — canary-read
   differential + deterministic unauth GETs. → `intrusive` / `stack_probe` extension.
7. **Fingerprint enhancement** — Spring Boot version derivation (`/actuator/info`, link-set shape,
   favicon) → CVE matrix, gating all of the above. → `light_active`.

Sources: Spring Security advisories (spring.io/security), NVD, VMware/Broadcom Tanzu advisories;
PortSwigger & Orange Tsai / Wallarm Spring4Shell write-ups; the Chinese Spring-research community
(FreeBuf, Seebug/qkl, y4er.com, xz.aliyun, LandGrey/SpringBootVulExploit); nuclei-templates
`http/vulnerabilities/spring/*` and `http/exposures/…/springboot-*`.
