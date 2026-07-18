# MoonMCP — Capability Gap Research (multi-language)

A living tracker of **techniques MoonMCP does not yet cover**, mined from national
security communities in their own languages (Chinese, Russian, Japanese, Korean,
Vietnamese, Turkish, Persian, plus global cutting-edge research). Each entry maps
a real-world technique to a **concrete new active detector / recon capability** —
weighted toward things that *do something* (send a probe, diff a response), not
more reference text (the knowledge base is already large).

Legend: **Status** = ❌ not covered · 🟡 partial · ✅ covered (listed to prevent
duplicate work). Every item is backed by a CVE or a public PoC / primary write-up.

---

## Priority build order (highest ROI, all safe-detection)

| # | Capability | Why first | Reuses |
|---|---|---|---|
| 1 | Web **cache deception** probe | half the plumbing (`cacheable()`) exists | `web/probes.py` |
| 2 | `oauth_probe` (OIDC discovery) + **JWT active** (HMAC crack, `alg=none`, `jku`→OAST) | one GET maps auth; crack is zero-traffic | `intel/oast`, `web/jwt.py` |
| 3 | Multi-cloud **response-based SSRF** (`ssrf_metadata_probe`) | turns blind SSRF into credential theft | OAST, `web/params.py` |
| 4 | **Modern desync** (0.CL / TE.0 / Expect / chunk-ext + timing) | $-class; needs timing, not just header ambiguity | `web/desync.py` sockets |
| 5 | **CN/RU stack detectors** + EHole fingerprints + CN WAFs | highest-payout pre-auth RCE, English tools miss | `fingerprint.py`, OAST, differential |
| 6 | `ja4_fingerprint` (JA4/JA4S/JA4H/JA4X/JA4T) | best net-new recon, beats JARM | `net/jarm.py`, `net/tls.py` |
| 7 | `recover_sourcemaps` + `dependency_confusion` | source + secret disclosure; supply-chain | `recon/secrets.py` |
| 8 | Server-side **prototype pollution** + **parser differentials** | WAF-bypass multiplier + standalone bugs | `web/params.py` diff |

---

## Theme 1 — Modern desync & cache (global; adapted 🇯🇵)

### 1.1 Modern request smuggling: 0.CL / TE.0 / Expect / chunk-extension ✅ (SHIPPED)
Implemented in `moonmcp/web/desync.py` (`probe_modern_desync` + pure `interpret_modern`)
+ the `desync_modern_probe` tool (intrusive): the **timeout-differential** technique —
each probe runs on its own fresh `Connection: close` socket that is closed immediately
(no second/victim request shares it, so nothing is smuggled). Infers which length
header the server honours from whether it waits for the promised body: TE.0 (chunked
with no terminator answered anyway), CL.0 (short-body answered anyway), 0.CL (malformed
`Expect: y 100-continue` twin diverges — CVE-2025-32094), chunk-extension divergence
(CVE-2025-55315). A probe only signals when the ambiguous framing was *accepted* with a
non-error status; a fast 4xx (rejection) or a read timeout (honoured framing) is no signal.
Kettle's 2025 "HTTP/1.1 Must Die." `CL.0`, `0.CL` (broken `Expect: 100-continue`),
`TE.0`, and chunk-extension / bare-CR parsing. Researchers earned $200k+ in weeks.
- CVEs: CVE-2025-32094 (Akamai `Expect: y 100-continue` 0.CL), CVE-2025-55315 (Kestrel chunk-ext, CVSS 9.9), Netty GHSA-fghv-69vj-qj49.
- Source: https://portswigger.net/research/http1-must-die · https://portswigger.net/research/how-to-distinguish-http-pipelining-from-request-smuggling
- **Mapping:** extend `web/desync.py` — `Content-Length > body` **timeout-delta** probe (CL.0 candidate), `Expect: 100-continue` + malformed twin (0.CL), TE-only (TE.0), chunk-extension + bare-LF twin. All on fresh closed sockets; verdict from status/timing divergence vs a correct-framing control.

### 1.2 Web Cache Deception (delimiter/normalization variants) ✅ (SHIPPED)
Implemented in `moonmcp/web/cache_deception.py` + the `cache_deception_probe` tool
(intrusive-gated): fetches the private page authed vs anonymously, primes each
path-confusion variant (`/x.css`, `;x.css`, `%2f`, encoded traversal) and re-reads
it cookieless — confirmed when the cookieless variant returns the private-sized body
with a cache-HIT header. Reuses `probes.cacheable()`.
BH-USA-2024 "Gotta cache 'em all." Trick the cache into storing a victim's
*authenticated* response under an attacker-readable key via CDN↔origin URL-parser
discrepancies (`;`, `%2f`, encoded dot-segments, IIS backslash, static-ext rules).
- Source: https://portswigger.net/research/gotta-cache-em-all · https://portswigger.net/kb/papers/kapvrid/gotta-cache-em-all.pdf
- **Mapping:** with the operator's session, request the private page via a crafted variant (`/account/wcd.js`, `/account;x.css`, `/account%2f%2e%2e%2fstatic%2fx.css`), then re-request identically **cookieless**; deception confirmed if private content or a cache-HIT header returns. `web/probes.py:cacheable()` already parses the HIT headers — reuse it.

---

## Theme 2 — SSRF as an active, multi-cloud, response-based probe (🇷🇺 + global)

Today `ssrf_probe` only plants a blind OAST canary. Gap = response-based metadata theft.

### 2.1 Multi-cloud metadata target list ✅ (SHIPPED)
Implemented in `moonmcp/web/ssrf_meta.py` + the `ssrf_metadata_probe` tool
(intrusive): injects each provider's metadata URL into a param and scans the
response for its credential signature. `CLOUD_METADATA_TARGETS` covers
AWS/GCP/Azure/Alibaba/**Yandex (GCE-flavored)**/Oracle/DigitalOcean.
Per-provider host + required header + credential path:
| Provider | Host | Header | Path |
|---|---|---|---|
| AWS IMDSv1/v2 | `169.254.169.254` | (v2) `X-aws-ec2-metadata-token` | `/latest/meta-data/iam/security-credentials/` |
| GCP | `metadata.google.internal` | `Metadata-Flavor: Google` | `/computeMetadata/v1/instance/service-accounts/default/token` |
| Azure | `169.254.169.254` | `Metadata: true` | `/metadata/identity/oauth2/token?...` |
| **Alibaba** | `100.100.100.200` | — | `/latest/meta-data/ram/security-credentials/` |
| **Yandex Cloud** | `169.254.169.254` (GCE-flavored!) | `Metadata-Flavor: Google` | `/computeMetadata/v1/.../token` |
| Oracle OCI | `192.0.0.192` | `Authorization: Bearer Oracle` | `/opc/v2/instance/` |
| DigitalOcean | `169.254.169.254` | — | `/metadata/v1/` |
- Source: https://yandex.cloud/en/docs/compute/concepts/vm-metadata · https://ringsafe.in/ssrf-beyond-aws-gcp-azure-onprem/ · Wiz cloud-SSRF.
- **Mapping:** `ssrf_metadata_probe(target, param)` — inject each metadata URL, diff for provider credential signatures (`AccessKeyId`, `access_token`, `ram/security-credentials`). Expose `CLOUD_METADATA_TARGETS` as a reusable constant. Intrusive-gated.

### 2.2 Unicode / IDN / punycode filter-bypass for SSRF & redirect 🟡 (general normalization detector SHIPPED)
HostSplit (BH-2019 → 2024): fullwidth `．`(U+FF0E)→`.`, fraction slash `⁄`(U+2044)→`/`,
Turkish dotless-ı case-mapping, zero-width strip, `xn--` twins — pass an allowlist as
one value, resolve/normalize to another.
- Source: HostSplit whitepaper (BH-USA-19) · https://herish.me/blog/0click-account-takeover-punycode/ · axios #7315.
- **Mapping:** for host/URL/redirect/SSRF params, send ASCII control + confusable twin + `xn--` form; if confusable is accepted where an obviously-out-of-scope ASCII value is rejected → normalization-after-validation bypass. Confirm SSRF via existing OAST.
- ✅ **SHIPPED (general case):** `unicode_bypass_probe` detects server-side NFKC / case-fold normalization via a canary-wrapped reflection differential (fullwidth `＜＞＂＇／＼（；．`→ dangerous ASCII, `ſ`→`s`, `ﬀ`→`ff`, Kelvin `K`→`k`). The SSRF/redirect-specific *resolve-to-internal-host* confirmation still routes through `ssrf_*`/`redirect_probe` + OAST.

---

## Theme 3 — Identity / protocol detectors (🇮🇷 🇯🇵 🇰🇷 🇹🇷)

`web/jwt.py` is offline-parse only; there is no OAuth/OIDC, SAML, or WebSocket coverage.

### 3.1 `oauth_probe` — OIDC discovery recon ✅ (SHIPPED)
Implemented in `moonmcp/web/oauth.py` + the `oauth_probe` tool: fetches both well-known docs, returns endpoints, and flags implicit grant / weak-or-missing PKCE / `none`+HS256 signing / http issuer / issuer↔jwks mix-up / public clients.
GET `/.well-known/openid-configuration` (+ `/oauth-authorization-server`). Flags:
implicit grant (`response_types` has `token`), no PKCE (`code_challenge_methods`
absent/`plain`), `none`/`HS256` signing, `http` issuer, `jwks_uri` host ≠ issuer.
- Source: OpenID Connect Discovery 1.0; OAuth BCP **RFC 9700**.
- **Mapping:** one scope-gated GET; parse JSON → findings; auto-feed `jwks_uri` into the JWT tool, `authorization_endpoint` into 3.3.

### 3.2 JWT active attacks 🟡 (offline crack + alg=none forge SHIPPED)
Implemented in `moonmcp/web/jwt.py` + the `jwt_crack` tool: offline HS256/384/512
secret crack against a weak-secret wordlist, and an `alg:none` forgery of the token.
Remaining: live acceptance test (replay the none/forged token) and `jku`/`x5u`→OAST.
- **HMAC secret crack (offline, 0 traffic)** — recompute HMAC over `header.payload` vs a weak-secret wordlist → key disclosure = critical. Source: TrustedSec "Keys to JWT Assessments"; hashcat `-m 16500`.
- **`alg=none` acceptance** — replay a `none`/`None`/`NONE` token to an authed endpoint, diff status. CVE-2015-9235, CVE-2020-28042.
- **`jku`/`x5u` SSRF** — set to a MoonMCP OAST canary, poll for callback. CVE-2018-0114.
- **`kid` injection** — benign path/SQLi canary in `kid`, diff behavior.
- Turkish (Eresus) variant: server decodes JWT with `verify_signature=False` — same test as `alg=none` against the callback.

### 3.3 OAuth `redirect_uri` validation bypass 🟡
Path tricks (`/callback/../evil`), subdomain/lookalike, **unescaped-dot regex** (`app.example.com` ≈ `app0example.com`). CVE-2024-52289 (Authentik), CVE-2023-6927 (Keycloak). Persian: Voorivex "Abusing a Fully Secured redirect_uri."
- **Mapping:** OAuth-aware payload set in `web/redirect.py` applied to `redirect_uri` against a discovered `authorization_endpoint`; verdict when a 3xx `Location` lands on the canary carrying `code`/`token`.

### 3.4 SAML endpoint + unsigned-assertion signal ❌
XML Signature Wrapping (XSW), comment/NameID truncation, XPath smuggling. CVE-2024-45409 (ruby-saml/GitLab, 9.8).
- **Mapping (safe):** detect ACS/SSO paths + SP metadata; flag `WantAssertionsSigned="false"` / `AuthnRequestsSigned="false"`. Do not attempt live XSW.

### 3.5 Cross-Site WebSocket Hijacking (`cswsh_probe`) ❌
WS handshake authed by cookie without `Origin` validation (CWE-1385).
- **Mapping (handshake only):** send `Upgrade: websocket` twice — legit vs foreign `Origin` + session cookie; `101 Switching Protocols` for the foreign Origin = CSWSH candidate. Never sends frames.

### 3.6 GraphQL batching / aliasing / field-suggestion / GET-CSRF 🟡
CVE-2024-39895 (Directus alias DoS), Apollo GHSA-2p3c-p3qw-69r4.
- **Mapping:** 2-element array batch (batching), `{a:__typename b:__typename}` (aliasing), `{ ussr }` typo → "Did you mean" (schema leak past disabled introspection), `GET ?query={__typename}` (CSRF). Low volume, safe.

### 3.7 gRPC / gRPC-web reflection exposure ✅ (SHIPPED)
`grpc.reflection.v1alpha.ServerReflection` enabled in prod = unauth API enumeration.
- **Mapping:** detect `Content-Type: application/grpc[-web]`; for gRPC-web attempt the reflection `list` call → service list = exposed. Fingerprint only.
- ✅ **SHIPPED:** `grpc_probe` fingerprints gRPC via the gRPC-Web framing (an invented method → `UNIMPLEMENTED`), then runs a benign `ListServices` against `ServerReflection` v1alpha/v1 (`grpc-status: 0` = exposed; the leaked service names are parsed from the `ServerReflectionResponse` when present) and flags the standard `grpc.health.v1.Health/Check` answering unauthenticated. Detection-only; grpcurl/Strix to weaponize.

### 3.8 Next.js middleware auth-bypass (`nextjs_middleware_probe`) ✅ (SHIPPED)
CVE-2025-29927: the internal `x-middleware-subrequest` header (never stripped from external requests) makes Next.js skip its middleware — bypassing auth gates / redirects / path allow-lists. Affected < 12.3.5 / 13.5.9 / 14.2.25 / 15.2.3. Source: Assetnote & JFrog write-ups (2025-03), zhero-web-sec.
- ✅ **SHIPPED:** `nextjs_middleware_probe` (light_active) fingerprints Next.js, then runs a pure **differential** against a middleware-gated route — baseline (no header) vs a small manifest-path payload set (`middleware`, `src/middleware`, the Next 12 `pages/_middleware`, and the `:`-repeated form that defeats the Next 13.2–15 recursion counter); a gated response (auth redirect / 401 / 403) that flips to `2xx` confirms the middleware was skipped. Auth-gate bypass ranks `high/confirmed` above a bare redirect bypass (`review`). Detection-only; verify the 2xx body + weaponize via Strix.

---

## Theme 4 — Regional stacks: fingerprint → exploit-surface (🇨🇳 🇷🇺)

Highest-payout pre-auth RCE; English tools don't fingerprint these. Build as active
differential/oracle detectors (reuse OAST + differential engine), **not** KB text.

> **🟡 First `stack_probe` SHIPPED** — `moonmcp/web/stacks.py` + the `stack_probe`
> tool (intrusive) do passive fingerprinting (Bitrix / ThinkPHP / Shiro / Nacos /
> Druid / Weaver / Seeyon / Yonyou / ClickHouse) plus deterministic unauth checks:
> **ThinkPHP** invokefunction RCE (benign md5 echo), **Nacos** UA auth bypass,
> **Shiro** rememberMe tell, **Druid** monitor exposure, **1C-Bitrix** admin,
> unauthenticated **ClickHouse** HTTP. Fastjson-OAST (`fastjson_oast_probe`) and
> Actuator `/env`+heapdump (`actuator_probe`) since SHIPPED; remaining below: the full
> OA suite, CN WAF signatures, EHole corpus, ICP recon.

### 🇨🇳 China (FreeBuf / Seebug / AnQuanKe)
- **Apache Shiro-550** (CVE-2016-4437) ✅ (SHIPPED) — `moonmcp/web/shiro.py` + the `stack_probe` Shiro path: `rememberMe=1` → `rememberMe=deleteMe` fingerprint, then a **safe key oracle** — a benign `SimplePrincipalCollection` AES-CBC-encrypted under each of ~24 public default keys; the key whose cookie is NOT rejected (no `deleteMe`) is recovered, with a garbage-key negative control so an endpoint that stopped emitting the tell can't false-fire. Reports the recovered key; the gadget chain → Strix. No exploit is ever sent.
- **Fastjson/Jackson autoType** (CVE-2017-18349, CVE-2022-25845) ✅ (SHIPPED) — `fastjson_oast_probe` (intrusive, OAST) POSTs `{"@type":"java.net.Inet4Address","val":"<oast>"}` + evasion twins → **OAST DNS/HTTP callback** confirms the autoType deser.
- **ThinkPHP 5 RCE** (CVE-2018-20062/CVE-2019-9082) ✅ (SHIPPED) — `stack_probe`'s `_probe_thinkphp`: GET `?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=moonmcp` → deterministic md5 echo (benign proof).
- **Nacos auth bypass** (CVE-2021-29441) ✅ (SHIPPED) — `stack_probe`'s `_probe_nacos`: `User-Agent: Nacos-Server` on `/nacos/v1/auth/users` returns 200 JSON.
- **OA suite** ❌ (CNVD/Seebug, PoC-verified): Yonyou NC `bsh.servlet.BshServlet`/`NCFindWeb`; Weaver e-cology `WorkflowServiceXml`; Seeyon `getSessionList.jsp`; Tongda `ispirit/*` upload+LFI; Landray `custom.jsp` SSRF + `treexml.tmpl`.
- **Druid monitor unauth** ✅ (SHIPPED) — `stack_probe`'s `_probe_druid`: `/druid/index.html` → `/druid/websession.json` live-session leak (high) vs monitor-only (medium).
- **Spring Actuator `/heapdump` + `/env`** ✅ (SHIPPED) — `actuator_probe` parses `/env` for unmasked secret-named properties, confirms `/heapdump` by the HPROF magic via a bounded 64-byte read, reads `/mappings`, and enumerates Jolokia (`/jolokia/version` + `/list`) flagging RCE-capable MBeans without invoking them (Boot 1.x + 2/3). Detection-only; weaponization → Strix.
- **CN WAF fingerprints** ❌ — add to `web/waf.py` `_SIGNATURES`: SafeDog (`safedog-flow-item` cookie), Yunsuo (`yunsuo_session`), Jiasule/ChuangYu (`jiasule-waf`), 360 (`qianxin-waf`), Yunjiasu (`yunjiasu-nginx`), BaoTa (`宝塔网站防火墙` block page), D-Shield. Source: wafw00f + hacking8.com.
- Sources: gm7.org, freebuf.com/vuls, y4er.com, github.com/SkyBlueEternal, cnblogs pursue-security, Threekiii/Vulnerability-Wiki, qkl.seebug.org.

### 🇷🇺 Russia / CIS (Habr / Xakep)
- **1C-Bitrix** 🟡 (SSRF SHIPPED) — fingerprint (`/bitrix/js/`, `BITRIX_SM_` cookies, `/bitrix/tools/composite_data.php`); vuln paths `/bitrix/admin/`, license disclosure, vote-module CVE-2022-27228, `html_editor_action.php` unauth SSRF (→ OAST), FPD. Source: itsoft.ru, Habr/RUVDS, STAR Labs CVE-2023-1714/1719, github.com/k1rurk/check_bitrix.
  - ✅ **SHIPPED:** `stack_probe`'s `_probe_bitrix` now flags the unauth `composite_data.php` sessid leak (the SSRF prerequisite), and the new `bitrix_ssrf_probe` (intrusive, OAST) confirms the `html_editor_action.php` `action=uploadfile` `tmp_url` SSRF by a callback. Remaining: vote-module CVE-2022-27228 RCE + license/FPD scrape → Strix.
- **ClickHouse `/play`** 🟡 (HTTP query SHIPPED) — `stack_probe`'s `_probe_clickhouse` already flags the unauth `GET :8123/?query=SELECT%201` = critical; **remaining:** the `/play` SQL-console UI signal. Ports 8123/9000. (Wiz DeepSeek leak was exactly this.) Source: wiz.io/blog/wiz-research-uncovers-exposed-deepseek-database-leak.
- **CIS takeover fingerprints** 🟡 — add to `web/takeover.py`: Yandex Object Storage (`website.yandexcloud.net` → `NoSuchBucket`), VK Cloud (`hb.bizmrg.com`), Selectel (`selcdn.ru`).

### Recon multipliers
- **EHole `finger.json` ingest** ❌ into `recon/fingerprint.py` — thousands of CN product fingerprints onto the existing favicon-hash + header/body engine. Source: github.com/EdgeSecurityTeam/EHole.
- **ICP备案 → org → all domains** ❌ — new `recon/icp.py` for CN scope expansion. Source: icp.chinaz.com.

---

## Theme 5 — Recon upgrades (🇬🇧 FoxIO + supply-chain)

- **`ja4_fingerprint`** ✅ (SHIPPED) — `moonmcp/net/ja4.py` + the `ja4_fingerprint` tool: **JA4S** (server TLS ServerHello: negotiated version + chosen cipher + ordered extensions/ALPN, parsed from a raw ClientHello reusing `net/jarm.py`) and **JA4X** (certificate Issuer/Subject/extension-OID fingerprint from the handshake DER). Directly comparable to the FoxIO databases for server-stack/CDN/cert attribution + known-C2 correlation; raw components returned for verification. **JA4/JA4H** (client-side — would fingerprint MoonMCP itself) and **JA4T** (needs the peer's TCP SYN-ACK options, unavailable to a pure-Python socket) are out of scope for a client scanner; QUIC not probed. Source: github.com/FoxIO-LLC/ja4 (JA4S BSD-3; JA4X under FoxIO License 1.1).
- **`recover_sourcemaps`** ✅ (SHIPPED) — `moonmcp/recon/sourcemaps.py` + the `recover_sourcemaps` tool: fetches the `.js.map` (from a `.js`/`.map`/page), reconstructs each module's original source from `sourcesContent[]`, splits app source from vendor (`node_modules`/webpack runtime), flags config/secret-looking files, and runs the recovered app source through `recon/secrets.py`. Source: pulsesecurity.co.nz/articles/javascript-from-sourcemaps.
- **`dependency_confusion`** ✅ (SHIPPED) — `moonmcp/recon/depconf.py` + the `dependency_confusion` tool (passive OSINT): parses package.json / composer.json / requirements.txt / Pipfile / Gemfile and existence-checks each dep against its public registry (npm/PyPI/RubyGems/Packagist) — 404 = claimable (scoped 404 = high). Source: blog.gitguardian.com/dependency-confusion-attacks.
- **Cloud bucket takeover + Alibaba OSS / DO Spaces** 🟡 — `recon/buckets.py` treats `404/NoSuchBucket` as absent; surface "absent-but-referenced" as claimable, add OSS/Spaces providers.
- **`.well-known` expansion** 🟡 — add `openid-configuration`, `oauth-authorization-server`, `assetlinks.json`, `apple-app-site-association`, `mta-sts.txt` to `recon/content.py`.
- **CT** ✅ — crt.sh already a source in `enumerate_subdomains`; optional add certspotter as a 2nd key-less source.

---

## Theme 6 — Parser differentials & prototype pollution (🇬🇧 WAFFLED / Bishop Fox)

- **Server-side prototype pollution** ✅ (SHIPPED) — `moonmcp/web/sspp.py` + the `sspp_probe` tool (intrusive): pollutes the Express `json spaces` setting via `{"__proto__":{"json spaces":10}}` (and a `constructor.prototype` and `?__proto__[json spaces]=10` query variant) and confirms only by the full **causal transition** — a `res.json()` body that is compact, becomes pretty-printed while polluted, then compact again after the probe restores `json spaces` to 0 (always reverts, no lingering pollution). Weaponizing the sink → Strix. Source: portswigger.net/research/server-side-prototype-pollution.
- **Parser differentials (JSON / multipart / charset)** ✅ (SHIPPED) — `web/parserdiff.py` + the `parser_diff_probe` tool (intrusive). Pairs a canonical request with quirk-twins carrying one inert canary: **decode** lanes (UTF-7 `+AG0-` / overlong-UTF-8 `%C1%AD` reflected back as plain text ⇒ the app applied the transform) and **tolerance** lanes (duplicate JSON keys, JSON comments, trailing commas, duplicate multipart fields *accepted* while a blatantly-invalid control is *rejected* ⇒ a lax-parser surface, with first-wins/last-wins precedence named). Detection-only — delivers nothing executable; smuggling a real payload through the confirmed differential → Strix. Diff canonical vs quirk-twin. Source: WAFFLED (arXiv 2503.10846), bishopfox.com/blog/json-interoperability-vulnerabilities.
- **HTTP/2 CONTINUATION flood** ✅ (SHIPPED, advisory) — `http2_probe` detects passively: ALPN `h2` (+ the confirmable **h2c cleartext-upgrade / smuggling** signal) and maps `Server` version → the CONTINUATION/Rapid-Reset DoS-CVE matrix (CVE-2024-27316, CVE-2023-44487); never floods. Source: kb.cert.org/vuls/id/421644.
- **Client-side prototype pollution** ✅ (SHIPPED) — `web/cspp.py` + the `cspp_probe` tool. Loads `__proto__`/`constructor.prototype` bracket+dotted paths (in both query and hash) in MoonMCP's **own ephemeral headless browser** and reads `Object.prototype[<marker>]` back; a clean baseline confirms the marker isn't natural, so a read-back of the exact sentinel is a definitive confirm. Safe by design — the pollution lands in our throwaway Chromium, never the target server; gadget→DOM-XSS chaining → Strix. Source: portswigger.net/web-security/prototype-pollution/client-side · github.com/BlackFan/client-side-prototype-pollution.

---

## Tooling strategy — don't reinvent nuclei (`scan_coverage` + `vuln_scan`)
nuclei is a **stateless per-template matcher**; because everyone mass-scans with it,
the bugs it can find are largely already reported. So MoonMCP **delegates** the
commodity detection nuclei owns (version→CVE, static exposures, takeovers, tech
fingerprints, DAST fuzzing of reflected params) via `vuln_scan`, and spends its own
effort on the **stateful / differential / timing / business-logic** probes nuclei
structurally *cannot* express — those have a higher marginal hit-rate on already-
scanned targets. The split is encoded (and testable) in `moonmcp/external/nuclei.py`
(`NUCLEI_DELEGATE` vs `NATIVE_EDGE`) and surfaced live by the `scan_coverage` tool;
`vuln_scan` returns `also_run_native` to steer the agent to the edge probes after the
nuclei pass. **Native-edge (keep + sharpen):** authz_probe, logic_probe,
race_probe, desync_probe/desync_modern_probe, path_bypass_probe, cache_deception_probe,
response_leak_probe, reset_poison_probe, ssrf_metadata_probe, confirm_finding,
surface_diff, the behavioural-infra probes, oauth_probe, the config_audit forge-chain
classifier. **Delegate to nuclei:** cve_*, vcs_exposure, debug_exposure, extract_secrets,
takeover_check, fingerprint/favicon/waf_detect, and reflected-param injection (`-dast`).

## Deliberately out of scope (safety)
Exploitation is never automated — every probe above is a **detection/indicator**;
weaponization is handed to Strix under human confirmation. No pirated tooling.

---
---

# ROUND 2 — additional national segments

## 🇪🇺 Western & Central/Eastern Europe (Synacktiv 🇫🇷 · Cure53/SySS/heise 🇩🇪 · sekurak 🇵🇱 · Vaadata/SSTIC 🇫🇷 · Computest 🇳🇱)

### EU-A. Leaked framework signing-secret → forge signed blob → deserialization RCE — the EU meta-gap 🟡 (classifier SHIPPED)
**Implemented:** `config_audit.py` now carries a `SIGNING_SECRETS` table + `classify_signing_secret()` — every recognized key is flagged **critical** as a "forge-capable signing secret" with its forge primitive, and surfaced in `summary.forge_chains` (this also catches `APP_KEY`/`machineKey`, which the generic secret rule missed). Remaining future step: the *live* forge-validation (decrypt a captured cookie to confirm the key). Offline classifier mapping key → framework → primitive:
- **Laravel `APP_KEY`** → forge `laravel_session` cookie → auto-`unserialize()` (if `SESSION_DRIVER=cookie`) → phpggc RCE. 600+ apps mass-exploited 2025 (`laravel-crypto-killer`). CVE-2024-48987 (Snipe-IT), CVE-2024-55555 (Invoice Ninja). Source: synacktiv.com/publications/laravel-appkey-leakage-analysis · blog.gitguardian.com/exploiting-public-app_key-leaks. **Confirm offline** by validating the key decrypts one captured cookie (zero extra traffic).
- **TYPO3 `encryptionKey`** → forge `__trustedProperties` (HMAC-SHA1) → deser + arbitrary file read. Dominant in DE/AT/CH gov. CVE-2019-12747. Source: synacktiv.com/publications/typo3-leak-to-remote-code-execution.
- **Symfony `APP_SECRET`** → forge `/_fragment` signed URI → RCE; secret harvested from exposed `/_profiler`. CVE-2019-18889; ambionics/symfony-exploits.
- **ASP.NET `machineKey`** → forge `__VIEWSTATE` (ysoserial.net). CVE-2025-30406 (CentreStack static key). Passive signal: `__VIEWSTATE` present + no `__VIEWSTATEENCRYPTED` = forgeable.
- **Rails `secret_key_base`** → cookie `Marshal.load`; **Flask/Django `SECRET_KEY`** → session forge.
- **Mapping:** one `SIGNING_SECRETS` table in `config_audit.py`; each leaked secret auto-classified, the specific forge-chain surfaced, weaponization → Strix. **Single highest-confidence net-new gap** (offline/safe, unlocks 5 pre-auth-RCE chains).

### EU-B. `appliance_cve_probe` — EU enterprise-appliance fingerprint → version → CVE oracle ✅ (SHIPPED)
Version-match only (never send the exploit; hand that to Strix). EU orgs run these at scale:
- ✅ **SHIPPED:** `appliance_cve_probe` fingerprints Citrix NetScaler/Gateway, Ivanti Connect Secure, Fortinet SSL-VPN, PAN GlobalProtect, and F5 BIG-IP from login-portal paths + cookie/header/body markers, reads the version where disclosed (Ivanti `nc_gina_ver.txt`), and attaches each product's known-exploited (KEV) CVEs. Detection-only — fingerprint + version GETs, no exploit. A follow-up could add the version-vs-fixed comparison + the CVE-2025-4427 no-Cookie differential below.
- **Citrix NetScaler** CitrixBleed CVE-2023-4966 / CVE-2025-5777 (session-token overread) — build from `/vpn/index.html` + `NSC_` cookies. Source: assetnote.io/resources/research/citrix-bleed…
- **Ivanti Connect Secure / EPMM** CVE-2025-0282, CVE-2023-46805+CVE-2024-21887 chain, **CVE-2025-4427 (auth bypass = omit the `Cookie` header** on `/rs/api/v2/featureusage` — clean differential probe). Version-scrape via admin-immutable `/dana-na/setup/psaldownload.cgi`. Source: Synacktiv PDF · sekurak.pl.
- **Fortinet FortiOS** CVE-2024-55591 (websocket auth bypass). watchtowr.
- **SonicWall SSLVPN** CVE-2024-53704 (null-byte session cookie). Bishop Fox + SySS.
- **Palo Alto GlobalProtect** CVE-2024-3400 + CVE-2024-9474 (`X-PAN-AuthCheck`). sekurak.pl.
- **Mapping:** one `{product: {version_range: CVE}}` table on `fingerprint.py`.

### EU-C. Framework debug/console exposure ✅ (SHIPPED)
Implemented in `moonmcp/web/debugpanel.py` + the `debug_exposure` tool: a curated
path → distinctive content-signature map covering Laravel Ignition, Symfony profiler /
`app_dev.php`, Telescope/Horizon, Spring Boot Actuator `/env`, Django debug toolbar,
the Werkzeug/Flask interactive debugger, Adminer, phpMyAdmin and Rails dev info —
confirmed by signature (no soft-404 FPs). Panels that leak the signing secret point
the operator at `analyze_config` for the forge chain (feeds EU-A).
Laravel **Ignition** (`GET /_ignition/health-check` = exposed; CVE-2021-3129 RCE), Symfony **profiler** (`/_profiler`, `/_wdt`, `/app_dev.php`), **Telescope/Horizon** (`/telescope`, `/horizon`), **Whoops**/Adminer/phpMyAdmin. Path+content-signature, same engine as `.git`/`.env`.

### EU-D. Path-normalization ACL bypass family ✅ (SHIPPED)
Implemented in `moonmcp/web/pathnorm.py` + the `path_bypass_probe` tool: confirms the
plain path is protected (401/403), then replays a deduped normalization twin-set
(`/admin/..;/`, `/%2e/admin`, matrix `;x`, trailing `%2f`/`%2e`/`;`, double internal
slash, `%`-encoded first char, dot-dot reinjection) and flags any that flip to 2xx.
GET-only, non-destructive; findings are `review` leads (confirm the 2xx body is the
real protected content).
`/..;/`, `/%2e%2e;/`, matrix `admin;x`, trailing dot, double-encoding — front proxy vs backend disagree → reach protected routes. CVE-2024-0204 (Fortra GoAnywhere `/..;/` → admin creation). Source: sekurak.pl · vaadata.com. **Mapping:** for any `401/403` path, replay a fixed twin-set; `200` + protected body on a twin = bypass. Reuses `confirm.py` differential + `web/methods.py`.

### EU-E. DOMPurify version → mXSS bypass matrix ❌ (🇩🇪 Cure53; client-side recon)
Detect DOMPurify in JS bundles, extract `VERSION`, map to known bypass class (≤2.0.17 rawtext, ≤2.2.2 namespace confusion, ≤3.1.2 mutation, CVE-2024-45801). Source: github.com/cure53/DOMPurify · mizu.re/post/exploring-the-dompurify-library-bypasses. **Mapping:** regex in `jsendpoints.py`/`secrets.py`; fingerprint-only, mXSS → `web/browser.py`/Strix.

### EU-F. EU webmail/groupware fingerprint → CVE ❌ (self-hosted heavy)
Zimbra (CVE-2019-9670 XXE→SSRF chain, CVE-2022-27924 memcached-injection, CVE-2024-45519 RCE), Roundcube (CVE-2024-37383, CVE-2025-49113), EGroupware (SYSS-2024-047 SQLi). **Mapping:** fingerprint each → version→CVE; Zimbra ProxyServlet SSRF confirmable via existing OAST canary.

### EU — also-worth-noting
NetScaler `ns.conf` LDAP passwords use **hardcoded keys common to all appliances** → auto-decrypt when a `ns.conf` is ingested (`config_audit.py`). Source: dozer.nz/posts/citrix-decrypt.

---

## 🌎 Latin America & Iberia (DragonJAR/ElevenPaths 🇪🇸 · Conviso/H2HC/Tempest 🇧🇷)

### LATAM-1. FOCA-style public-document metadata OSINT ✅ (SHIPPED)
Harvest a target's public PDF/DOCX/XLSX → extract authors, internal usernames, local/UNC paths, printer/host names, software versions, internal IPs. Chema Alonso's FOCA tradition; still under-automated. Source: es.wikipedia.org/wiki/FOCA_Tool · dragonjar.org · elladodelmal.com. **SHIPPED:** `moonmcp/web/docmeta.py` + the `document_metadata_osint` tool (passive OSINT, block-private SSRF still applies) — stdlib parse of OOXML `docProps/core.xml`+`app.xml` (XXE/DTD-hardened, member-capped), PDF `/Info`+XMP, JPEG EXIF/GPS and PNG text/eXIf → authors / usernames / internal paths / software → classify. Remaining: auto-harvest via `wayback`+`filetype:` dorks feeding it, and versions → CVE mapper.

### LATAM-2. ExifTool image-upload blind RCE ❌ (active, OAST) — CVE-2021-22204 / GitLab CVE-2021-22205
Upload endpoints that run ExifTool server-side are RCE-able via a DjVu ANT annotation reaching Perl `eval`. Source: convisoappsec.com (BR) · devcraft.io. **Mapping:** new intrusive `upload_probe` — discover multipart endpoints (`crawl`/`openapi`), send a benign JPEG whose embedded payload is an OS callback to `oast_selfhost` → OAST hit = `confirmed` (callback-only, no shell). Also passive `ExifTool`/`Perl` error strings. **No file-upload detector exists today.**

### LATAM-3. "LATAM stack" fingerprint→CVE pack ❌ (extends `fingerprint.py`+`vulns_data.py`)
MoonMCP offloads all of these to nuclei with no native fingerprint→CVE mapping:
- **Liferay** JSONWS unauth deser CVE-2020-7961 (LATAM gov/edu; JavaDeserH2HC/JexBoss is Brazilian). `/api/jsonws` exposed → OAST deser probe.
- **WSO2** file-upload RCE CVE-2022-29464 (`/fileupload`; identity layer). Orange Tsai.
- **GLPI** htmLawed RCE CVE-2022-35914 (`/vendor/htmlawed/.../htmLawedTest.php`; math-eval differential).
- **Moodle** CVE-2024-43425 (calculated-question eval), CVE-2025-26529 (SSRF→XSS→admin) — every LATAM university.
- **Oracle Forms/Reports** `rwservlet` file-read→RCE CVE-2012-3152 (legacy banking/telecom).
- **TOTVS Fluig** path traversal CVE-2020-29134 + **Protheus** AppServer default-cert JARM fingerprint — *the* dominant Brazilian ERP.
- **Mapping:** one fingerprint pack (favicon/header/cookie/JARM) → version→CVE; file-read CVEs confirmable via `confirm.py` differential.

### LATAM-4. PIX BR Code SSRF + payment-race ❌ (region-specific payment logic)
Dynamic PIX QR carries a **payload URL the PSP fetches** → SSRF primitive; static-QR amount/beneficiary tamper with recomputed CRC-16; refund (*estorno*) race. Source: BCB Manual do BR Code · tabnews.com.br. **Mapping:** `pix_brcode` TLV helper (valid CRC-16) → point dynamic-QR URL at `oast_selfhost` (OAST hit from a bank ASN = SSRF); drive existing single-packet race on estorno. *(Technique/standard-level, not a single CVE — gate as heuristic.)*

### LATAM-5. CPF/CNPJ check-digit-aware IDOR + enumeration ❌ (active differential)
Generate **valid** Módulo-11 CPFs/CNPJs → drive the IDOR/access-control differential swapping the document; second signal = absence of rate-limit across a small valid-CPF sweep. Behind the recurring gov.br-scale PII dumps (LGPD → top severity). **Mapping:** `cpf_cnpj` generator + existing two-identity differential. *(Incident-documented, not a CVE.)*

### LATAM-6. Boleto `linha digitável` value-tamper ❌ — Módulo-10/11 DV recompute; submit amount-mutated-but-DV-valid boleto vs baseline. *(Fraud-documented; lowest rank, needs authed flow.)*

---

## 🌏 India / MENA / SEA + cross-cutting "unusual but automatable" findings

This region's bug-bounty community (Indian/SEA fintech especially) documents a set
of high-yield **auth/logic** bugs that a scanner rarely automates but easily can —
each is a small, safe differential/regex detector.

### GLOBAL-1. Sensitive value returned in the HTTP response body ✅ (SHIPPED)
Implemented in `moonmcp/web/authflow.py` + the `response_leak_probe` tool: drives
the OTP/reset/verify endpoint and scans the response body for out-of-band secrets
returned in-band — named `otp`/`reset_token`/`verification_code`/reset-link fields
(`confirmed`) and, only in an OTP-context body, bare 4–8-digit codes (`review`).
Deliberately ignores `csrf`/OAuth `access_token` (legitimately in-band); secrets are
**redacted** in output.
OTP / 2FA code / password-reset token / verification link echoed in the JSON or body
of the *request* response instead of being delivered out-of-band → instant account
takeover. Extremely common in fintech APIs. Source: github.com/tuhin1729/Bug-Bounty-Methodology (PasswordReset/2FA), HackTricks reset-password.
- **Mapping:** new `response_leak_probe` — drive the OTP / reset / email-verify flow, regex the response for a standalone 4–8-digit code, `otp`/`token`/`reset`/`verification` field, or a reset URL. Verdict `confirmed` = the out-of-band secret is in-band. Highest-yield, trivially safe.

### GLOBAL-2. Password-reset poisoning (Host / X-Forwarded-Host) ✅ (SHIPPED)
Implemented in `moonmcp/web/authflow.py` + the `reset_poison_probe` tool: replays the
reset request once per host-routing header (`Host`, `X-Forwarded-Host`, `Forwarded`,
`X-Host`, `X-Original-Host`, …) set to a canary and flags any reflected in the body /
`Location`. Omit the canary to auto-mint an OAST host, which also catches a server-side
host fetch (poll with `oast_poll`). The connection stays on the in-scope host.
The reset-link host is built from a user-controlled `Host` / `X-Forwarded-Host`; point
it at a canary → the victim's reset token is delivered to the attacker. Full ATO, no
session/exploit chain. Source: herish.me/blog/reset-password-poisoning-host-header, OWASP WSTG-INPV-17, PayloadsAllTheThings/Account-Takeover.
- **Mapping:** `reset_poison_probe` — send the reset request with `Host`/`X-Forwarded-Host`/`X-Forwarded-Server: <canary>`; verdict when the canary is reflected in the response body/`Location`, or (best) an `oast_selfhost` hit arrives if the app server-side-fetches the host. Reuses OAST.

### GLOBAL-3. CRLF injection → response splitting / header injection ✅ (SHIPPED)
Implemented in `moonmcp/web/crlf.py` + the `crlf_probe` tool: injects a benign
`X-Moonmcp-Inj: 1` marker via CR/LF variants (bare-LF, fragment, unicode/overlong,
double-encoded, Set-Cookie split) and confirms when it surfaces as a *real*
response header/cookie.
`%0d%0a` (and `%0d`, `%23%0d%0a`, `%E5%98%8A%E5%98%8D` overlong) in a param (often
`?lang=`, redirect params, subdomain routing) injects a real response header. Real
bounties: X/xAI (HackerOne #446271), Twitter `?lang=`, Uber subdomain, PayPal.
Source: hacktricks.wiki/en/pentesting-web/crlf-0d-0a.
- **Mapping:** `crlf_probe` — inject `%0d%0aX-Moonmcp-Inj: 1` (and a `%0d%0aSet-Cookie:` twin) into reflected params; verdict when the injected header appears as a genuine response header (not body). Differential vs a benign control. Safe, non-destructive.

### GLOBAL-4. OTP / 2FA brute-force surface (rate-limit absence) 🟡
No lockout / no rate-limit on OTP submission → brute a 4–6-digit code. Reuse the
existing rate-limit behaviour detector, but aimed at the OTP-verify endpoint; verdict
= many attempts accepted without 429/lockout. Source: tuhin1729 2FA methodology.

### GLOBAL-5. Race-condition limit bypass (single-packet) ✅ (SHIPPED)
Implemented in `moonmcp/web/logic.py` + the `race_probe` tool (fire N parallel
requests, report 2xx-success count) — part of the business-logic toolkit
(`logic_probe` for parameter-tampering + mass-assignment, and the
`business_logic_hunt` methodology prompt).
Parallel requests bypass non-atomic app-level limits (coupon reuse, refund double-spend,
free-tier overrun, multi-vote). MoonMCP already has the single-packet-race *concept* in
`confirm.py`; the gap is an **active** detector that fires N parallel requests at a
limit/coupon/refund endpoint and flags >1 success. Source: portswigger.net/web-security/race-conditions, yeswehack.com race-condition guide.
- **Mapping:** `race_probe(url, n=20)` reusing the concurrency path in `confirm.py`; verdict = success count > expected. Intrusive-gated.

### Region-specific stacks (leads; verify version→CVE per target)
- **MENA / gov student & citizen portals** — custom portals with unauth RCE, e.g. Uniclare Student Portal CVE-2024-57401 (RCE). Fingerprint→CVE via the same pack pattern as EU-B / LATAM-3.
- **India** — UIDAI/UPI/payment-flow logic (OTP-in-response above is the dominant automatable slice); Indian gov portals often on legacy Java/PHP stacks the fingerprint pack already covers.
- **SEA** — Indonesian fintech (OTP-in-response, race on wallet top-up), Vietnam disclosures aggregate on **WhiteHat.vn** (JWT/auth-bypass framing).

> Note: GLOBAL-1..5 are technique/disclosure-documented (bug-bounty write-ups, OWASP,
> PortSwigger), not single CVEs — gate them as heuristic detectors. They are among the
> **highest ROI** here: tiny, safe, and they map onto flows every app has.

