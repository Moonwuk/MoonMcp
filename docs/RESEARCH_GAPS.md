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

### 1.1 Modern request smuggling: 0.CL / TE.0 / Expect / chunk-extension ❌
Kettle's 2025 "HTTP/1.1 Must Die." `CL.0`, `0.CL` (broken `Expect: 100-continue`),
`TE.0`, and chunk-extension / bare-CR parsing. Researchers earned $200k+ in weeks.
- CVEs: CVE-2025-32094 (Akamai `Expect: y 100-continue` 0.CL), CVE-2025-55315 (Kestrel chunk-ext, CVSS 9.9), Netty GHSA-fghv-69vj-qj49.
- Source: https://portswigger.net/research/http1-must-die · https://portswigger.net/research/how-to-distinguish-http-pipelining-from-request-smuggling
- **Mapping:** extend `web/desync.py` — `Content-Length > body` **timeout-delta** probe (CL.0 candidate), `Expect: 100-continue` + malformed twin (0.CL), TE-only (TE.0), chunk-extension + bare-LF twin. All on fresh closed sockets; verdict from status/timing divergence vs a correct-framing control.

### 1.2 Web Cache Deception (delimiter/normalization variants) ❌
BH-USA-2024 "Gotta cache 'em all." Trick the cache into storing a victim's
*authenticated* response under an attacker-readable key via CDN↔origin URL-parser
discrepancies (`;`, `%2f`, encoded dot-segments, IIS backslash, static-ext rules).
- Source: https://portswigger.net/research/gotta-cache-em-all · https://portswigger.net/kb/papers/kapvrid/gotta-cache-em-all.pdf
- **Mapping:** with the operator's session, request the private page via a crafted variant (`/account/wcd.js`, `/account;x.css`, `/account%2f%2e%2e%2fstatic%2fx.css`), then re-request identically **cookieless**; deception confirmed if private content or a cache-HIT header returns. `web/probes.py:cacheable()` already parses the HIT headers — reuse it.

---

## Theme 2 — SSRF as an active, multi-cloud, response-based probe (🇷🇺 + global)

Today `ssrf_probe` only plants a blind OAST canary. Gap = response-based metadata theft.

### 2.1 Multi-cloud metadata target list ❌
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

### 2.2 Unicode / IDN / punycode filter-bypass for SSRF & redirect ❌
HostSplit (BH-2019 → 2024): fullwidth `．`(U+FF0E)→`.`, fraction slash `⁄`(U+2044)→`/`,
Turkish dotless-ı case-mapping, zero-width strip, `xn--` twins — pass an allowlist as
one value, resolve/normalize to another.
- Source: HostSplit whitepaper (BH-USA-19) · https://herish.me/blog/0click-account-takeover-punycode/ · axios #7315.
- **Mapping:** for host/URL/redirect/SSRF params, send ASCII control + confusable twin + `xn--` form; if confusable is accepted where an obviously-out-of-scope ASCII value is rejected → normalization-after-validation bypass. Confirm SSRF via existing OAST.

---

## Theme 3 — Identity / protocol detectors (🇮🇷 🇯🇵 🇰🇷 🇹🇷)

`web/jwt.py` is offline-parse only; there is no OAuth/OIDC, SAML, or WebSocket coverage.

### 3.1 `oauth_probe` — OIDC discovery recon ❌
GET `/.well-known/openid-configuration` (+ `/oauth-authorization-server`). Flags:
implicit grant (`response_types` has `token`), no PKCE (`code_challenge_methods`
absent/`plain`), `none`/`HS256` signing, `http` issuer, `jwks_uri` host ≠ issuer.
- Source: OpenID Connect Discovery 1.0; OAuth BCP **RFC 9700**.
- **Mapping:** one scope-gated GET; parse JSON → findings; auto-feed `jwks_uri` into the JWT tool, `authorization_endpoint` into 3.3.

### 3.2 JWT active attacks ❌
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

### 3.7 gRPC / gRPC-web reflection exposure ❌
`grpc.reflection.v1alpha.ServerReflection` enabled in prod = unauth API enumeration.
- **Mapping:** detect `Content-Type: application/grpc[-web]`; for gRPC-web attempt the reflection `list` call → service list = exposed. Fingerprint only.

---

## Theme 4 — Regional stacks: fingerprint → exploit-surface (🇨🇳 🇷🇺)

Highest-payout pre-auth RCE; English tools don't fingerprint these. Build as active
differential/oracle detectors (reuse OAST + differential engine), **not** KB text.

### 🇨🇳 China (FreeBuf / Seebug / AnQuanKe)
- **Apache Shiro-550** (CVE-2016-4437) ❌ — `rememberMe=1` → `rememberMe=deleteMe` fingerprint; then a safe **key oracle** over a ~30-key default list (absence of `deleteMe` = key found). Report recovered key; hand exploitation to Strix.
- **Fastjson/Jackson autoType** (CVE-2017-18349, CVE-2022-25845) ❌ — POST `{"@type":"java.net.Inet4Address","val":"<oast>"}` (+ evasion twins) → **OAST DNS callback**.
- **ThinkPHP 5 RCE** (CVE-2018-20062/CVE-2019-9082) ❌ — GET `?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=moonmcp` → deterministic md5 echo (benign proof).
- **Nacos auth bypass** (CVE-2021-29441) ❌ — `User-Agent: Nacos-Server` on `/nacos/v1/auth/users` returns 200 JSON.
- **OA suite** ❌ (CNVD/Seebug, PoC-verified): Yonyou NC `bsh.servlet.BshServlet`/`NCFindWeb`; Weaver e-cology `WorkflowServiceXml`; Seeyon `getSessionList.jsp`; Tongda `ispirit/*` upload+LFI; Landray `custom.jsp` SSRF + `treexml.tmpl`.
- **Druid monitor unauth** ❌ — `/druid/index.html` → `/druid/websession.json` leaks live sessions.
- **Spring Actuator `/heapdump` + `/env`** 🟡 — path is in wordlist; gap is parsing `/env` secrets + HPROF-magic heapdump confirm + jolokia chain.
- **CN WAF fingerprints** ❌ — add to `web/waf.py` `_SIGNATURES`: SafeDog (`safedog-flow-item` cookie), Yunsuo (`yunsuo_session`), Jiasule/ChuangYu (`jiasule-waf`), 360 (`qianxin-waf`), Yunjiasu (`yunjiasu-nginx`), BaoTa (`宝塔网站防火墙` block page), D-Shield. Source: wafw00f + hacking8.com.
- Sources: gm7.org, freebuf.com/vuls, y4er.com, github.com/SkyBlueEternal, cnblogs pursue-security, Threekiii/Vulnerability-Wiki, qkl.seebug.org.

### 🇷🇺 Russia / CIS (Habr / Xakep)
- **1C-Bitrix** ❌ (TOP RU gap) — fingerprint (`/bitrix/js/`, `BITRIX_SM_` cookies, `/bitrix/tools/composite_data.php`); vuln paths `/bitrix/admin/`, license disclosure, vote-module CVE-2022-27228, `html_editor_action.php` unauth SSRF (→ OAST), FPD. Source: itsoft.ru, Habr/RUVDS, STAR Labs CVE-2023-1714/1719, github.com/k1rurk/check_bitrix.
- **ClickHouse `/play`** ❌ — ports 8123/9000; `GET :8123/?query=SELECT%201` unauth = critical; `/play` SQL console. (Wiz DeepSeek leak was exactly this.) Source: wiz.io/blog/wiz-research-uncovers-exposed-deepseek-database-leak.
- **CIS takeover fingerprints** 🟡 — add to `web/takeover.py`: Yandex Object Storage (`website.yandexcloud.net` → `NoSuchBucket`), VK Cloud (`hb.bizmrg.com`), Selectel (`selcdn.ru`).

### Recon multipliers
- **EHole `finger.json` ingest** ❌ into `recon/fingerprint.py` — thousands of CN product fingerprints onto the existing favicon-hash + header/body engine. Source: github.com/EdgeSecurityTeam/EHole.
- **ICP备案 → org → all domains** ❌ — new `recon/icp.py` for CN scope expansion. Source: icp.chinaz.com.

---

## Theme 5 — Recon upgrades (🇬🇧 FoxIO + supply-chain)

- **`ja4_fingerprint`** (JA4/JA4S/JA4H/JA4X/JA4T) ❌ — successor to JARM/JA3; sorting defeats Chrome extension-randomization; server/CDN/cert attribution. Reuse `net/jarm.py` ClientHello + `net/tls.py`. Source: github.com/FoxIO-LLC/ja4 (JA4 client is BSD; JA4S/H/X/T under FoxIO License 1.1).
- **`recover_sourcemaps`** 🟡 — we *detect* `.js.map` (`jsendpoints.py`) but never download; parse `sourcesContent[]` → original source + run through `recon/secrets.py`. Source: pulsesecurity.co.nz/articles/javascript-from-sourcemaps.
- **`dependency_confusion`** ❌ — from `package.json`/`composer.json`/`requirements`/`pom`, existence-check the public registry (404 = claimable). Source: blog.gitguardian.com/dependency-confusion-attacks.
- **Cloud bucket takeover + Alibaba OSS / DO Spaces** 🟡 — `recon/buckets.py` treats `404/NoSuchBucket` as absent; surface "absent-but-referenced" as claimable, add OSS/Spaces providers.
- **`.well-known` expansion** 🟡 — add `openid-configuration`, `oauth-authorization-server`, `assetlinks.json`, `apple-app-site-association`, `mta-sts.txt` to `recon/content.py`.
- **CT** ✅ — crt.sh already a source in `enumerate_subdomains`; optional add certspotter as a 2nd key-less source.

---

## Theme 6 — Parser differentials & prototype pollution (🇬🇧 WAFFLED / Bishop Fox)

- **Server-side prototype pollution** ❌ — JSON body `{"__proto__":{"json spaces":10}}` → subsequent JSON responses become indented (byte-size change); reversible. GET variants (`?__proto__[json spaces]=10`) fit `web/params.py`. Source: portswigger.net/research/server-side-prototype-pollution.
- **Parser differentials (JSON / multipart / charset)** ❌ — WAF-bypass multiplier. JSON dup-keys `{"qty":1,"qty":-1}`, comment-truncation, big-number; multipart duplicate/missing `boundary=`; charset UTF-7 `+ADw-`→`<` / overlong `%c0%ae`→`.`. Diff canonical vs quirk-twin. Source: WAFFLED (arXiv 2503.10846), bishopfox.com/blog/json-interoperability-vulnerabilities.
- **HTTP/2 CONTINUATION flood** ❌ (CVE-2024-27316 family) — **detect passively**: ALPN `h2` + `Server` version → CVE matrix; never flood. Source: kb.cert.org/vuls/id/421644.
- **Client-side prototype pollution** ❌ — load `?__proto__[test]=polluted` in the headless browser (`web/browser.py`), read `Object.prototype.test`.

---

## Deliberately out of scope (safety)
Exploitation is never automated — every probe above is a **detection/indicator**;
weaponization is handed to Strix under human confirmation. No pirated tooling.

---
---

# ROUND 2 — additional national segments

## 🇪🇺 Western & Central/Eastern Europe (Synacktiv 🇫🇷 · Cure53/SySS/heise 🇩🇪 · sekurak 🇵🇱 · Vaadata/SSTIC 🇫🇷 · Computest 🇳🇱)

### EU-A. Leaked framework signing-secret → forge signed blob → deserialization RCE — the EU meta-gap ❌
`config_audit.py` already *extracts* secrets and `exposure.py` confirms a leaked `.env`, but MoonMCP never **classifies a secret as a forge-capable signing key**. Build one offline, zero-traffic `SIGNING_SECRETS` classifier mapping key → framework → primitive:
- **Laravel `APP_KEY`** → forge `laravel_session` cookie → auto-`unserialize()` (if `SESSION_DRIVER=cookie`) → phpggc RCE. 600+ apps mass-exploited 2025 (`laravel-crypto-killer`). CVE-2024-48987 (Snipe-IT), CVE-2024-55555 (Invoice Ninja). Source: synacktiv.com/publications/laravel-appkey-leakage-analysis · blog.gitguardian.com/exploiting-public-app_key-leaks. **Confirm offline** by validating the key decrypts one captured cookie (zero extra traffic).
- **TYPO3 `encryptionKey`** → forge `__trustedProperties` (HMAC-SHA1) → deser + arbitrary file read. Dominant in DE/AT/CH gov. CVE-2019-12747. Source: synacktiv.com/publications/typo3-leak-to-remote-code-execution.
- **Symfony `APP_SECRET`** → forge `/_fragment` signed URI → RCE; secret harvested from exposed `/_profiler`. CVE-2019-18889; ambionics/symfony-exploits.
- **ASP.NET `machineKey`** → forge `__VIEWSTATE` (ysoserial.net). CVE-2025-30406 (CentreStack static key). Passive signal: `__VIEWSTATE` present + no `__VIEWSTATEENCRYPTED` = forgeable.
- **Rails `secret_key_base`** → cookie `Marshal.load`; **Flask/Django `SECRET_KEY`** → session forge.
- **Mapping:** one `SIGNING_SECRETS` table in `config_audit.py`; each leaked secret auto-classified, the specific forge-chain surfaced, weaponization → Strix. **Single highest-confidence net-new gap** (offline/safe, unlocks 5 pre-auth-RCE chains).

### EU-B. `appliance_cve_probe` — EU enterprise-appliance fingerprint → version → CVE oracle ❌
Version-match only (never send the exploit; hand that to Strix). EU orgs run these at scale:
- **Citrix NetScaler** CitrixBleed CVE-2023-4966 / CVE-2025-5777 (session-token overread) — build from `/vpn/index.html` + `NSC_` cookies. Source: assetnote.io/resources/research/citrix-bleed…
- **Ivanti Connect Secure / EPMM** CVE-2025-0282, CVE-2023-46805+CVE-2024-21887 chain, **CVE-2025-4427 (auth bypass = omit the `Cookie` header** on `/rs/api/v2/featureusage` — clean differential probe). Version-scrape via admin-immutable `/dana-na/setup/psaldownload.cgi`. Source: Synacktiv PDF · sekurak.pl.
- **Fortinet FortiOS** CVE-2024-55591 (websocket auth bypass). watchtowr.
- **SonicWall SSLVPN** CVE-2024-53704 (null-byte session cookie). Bishop Fox + SySS.
- **Palo Alto GlobalProtect** CVE-2024-3400 + CVE-2024-9474 (`X-PAN-AuthCheck`). sekurak.pl.
- **Mapping:** one `{product: {version_range: CVE}}` table on `fingerprint.py`.

### EU-C. Framework debug/console exposure ❌ (extends `exposure.py`; feeds EU-A)
Laravel **Ignition** (`GET /_ignition/health-check` = exposed; CVE-2021-3129 RCE), Symfony **profiler** (`/_profiler`, `/_wdt`, `/app_dev.php`), **Telescope/Horizon** (`/telescope`, `/horizon`), **Whoops**/Adminer/phpMyAdmin. Path+content-signature, same engine as `.git`/`.env`.

### EU-D. Path-normalization ACL bypass family ❌ (differential; distinct from cache-deception)
`/..;/`, `/%2e%2e;/`, matrix `admin;x`, trailing dot, double-encoding — front proxy vs backend disagree → reach protected routes. CVE-2024-0204 (Fortra GoAnywhere `/..;/` → admin creation). Source: sekurak.pl · vaadata.com. **Mapping:** for any `401/403` path, replay a fixed twin-set; `200` + protected body on a twin = bypass. Reuses `confirm.py` differential + `web/methods.py`.

### EU-E. DOMPurify version → mXSS bypass matrix ❌ (🇩🇪 Cure53; client-side recon)
Detect DOMPurify in JS bundles, extract `VERSION`, map to known bypass class (≤2.0.17 rawtext, ≤2.2.2 namespace confusion, ≤3.1.2 mutation, CVE-2024-45801). Source: github.com/cure53/DOMPurify · mizu.re/post/exploring-the-dompurify-library-bypasses. **Mapping:** regex in `jsendpoints.py`/`secrets.py`; fingerprint-only, mXSS → `web/browser.py`/Strix.

### EU-F. EU webmail/groupware fingerprint → CVE ❌ (self-hosted heavy)
Zimbra (CVE-2019-9670 XXE→SSRF chain, CVE-2022-27924 memcached-injection, CVE-2024-45519 RCE), Roundcube (CVE-2024-37383, CVE-2025-49113), EGroupware (SYSS-2024-047 SQLi). **Mapping:** fingerprint each → version→CVE; Zimbra ProxyServlet SSRF confirmable via existing OAST canary.

### EU — also-worth-noting
NetScaler `ns.conf` LDAP passwords use **hardcoded keys common to all appliances** → auto-decrypt when a `ns.conf` is ingested (`config_audit.py`). Source: dozer.nz/posts/citrix-decrypt.

---

## 🌎 Latin America & Iberia (DragonJAR/ElevenPaths 🇪🇸 · Conviso/H2HC/Tempest 🇧🇷)

### LATAM-1. FOCA-style public-document metadata OSINT ❌ (biggest clean recon gap)
Harvest a target's public PDF/DOCX/XLSX → extract authors, internal usernames, local/UNC paths, printer/host names, software versions, internal IPs. Chema Alonso's FOCA tradition; still under-automated. Source: es.wikipedia.org/wiki/FOCA_Tool · dragonjar.org · elladodelmal.com. **Mapping:** new passive `doc_metadata_osint` — reuse `wayback` + `filetype:` dorks → parse via stdlib (`zipfile` for OOXML `docProps/core.xml`, PDF `/Author`/`/Producer`, EXIF) → usernames → `memory_add` (untrusted), versions → CVE mapper.

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

## 🌏 India / MENA / SEA — PARTIAL (agent hit a session limit; to finish)
Surfaced before termination (verify + expand later):
- **OTP / token / reset-link returned in the HTTP response body** — very common in Indian/SEA fintech; a cheap detector: request an OTP/password-reset flow, regex the JSON/body for a 4–8-digit code or a `token=`/`reset` value that should have been delivered out-of-band. High-yield, easily automatable.
- **CRLF injection** (`%0d%0a` in params → response-splitting / header injection / open-redirect-via-Location) — differential on reflected `Set-Cookie`/`Location`.
- TODO on resume: UPI/payment-flow logic, Indian gov (UIDAI) patterns, Arabic/MENA gov portals, Indonesian fintech, deeper WhiteHat.vn.

<!-- Round 2 India/MENA/SEA to be completed on a fresh session (agent session-limited). -->

