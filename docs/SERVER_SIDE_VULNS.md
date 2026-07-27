# MoonMCP — Server-Side Vulnerability Catalog

> Popular **and** obscure server-side vulnerability classes — what everyone hunts and
> the underrated ones that pay. Each entry maps to the ROOT CAUSE it springs from
> ([`ROOT_CAUSES.md`](ROOT_CAUSES.md)) and pins the concrete point where real apps get
> it wrong (*where it breaks*), with detection, WAF notes and real-world incidents.
> Behind `vuln_info` / `vuln_search` / `rootcause_info` / `vuln_tools` and `vulns://all`.


**44 classes** — 21 common · 18 uncommon · 5 rare. Referenced only — no weaponized code.


## Common (21)

### Broken Access Control / IDOR / BOLA
*id:* `broken-access-control-idor-bola` · *category:* `access-control` · *severity:* **high** · *root cause:* [Missing or Broken Authorization](ROOT_CAUSES.md)

The application fails to enforce that the authenticated user is authorized for the specific object or action, letting users read/modify other users' data or reach privileged functions.

**Where it breaks —** Endpoints that trust a client-supplied object identifier (IDOR/BOLA) without an ownership/tenant check, missing function-level checks on admin routes, relying on hidden UI or unguessable IDs (security by obscurity), and horizontal/vertical privilege gaps in multi-tenant APIs. The #1 API risk per OWASP API Top 10.

**Detection:**
- Enumerate object IDs across two accounts and diff access
- Map every endpoint to required role/ownership and test negative cases
- Automated authz differential testing (Autorize/AuthMatrix)
- Review for per-object checks vs per-endpoint-only checks

**WAF —** Effectively undetectable by generic WAFs because requests are well-formed and authenticated; defense requires application-layer policy enforcement and per-tenant anomaly monitoring.

**Real-world:** Facebook/Instagram, Uber, and many bug-bounty BOLA reports; CVE-2021-22986 adjacent; USPS Informed Visibility IDOR (60M users, 2018); T-Mobile API BOLA incidents; Optus 2022 breach (unauthenticated API)

**Tools:** burp suite + autorize/authmatrix, custom fuzzers, postman, nuclei

**References:** [link](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) · [link](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/) · [link](https://portswigger.net/web-security/access-control/idor) · [link](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

### CORS Misconfiguration
*id:* `cors-misconfiguration` · *category:* `access-control` · *severity:* **medium** · *root cause:* [Insecure Defaults & Misconfiguration](ROOT_CAUSES.md)

Overly permissive Cross-Origin Resource Sharing lets malicious origins read authenticated cross-origin responses, exposing user data.

**Where it breaks —** Reflecting the request Origin into Access-Control-Allow-Origin while also sending Access-Control-Allow-Credentials: true, weak Origin allowlists (substring/suffix/prefix matching, null origin trusted, http allowed), and wildcarding sensitive APIs — turning any attacker page into an authenticated reader of the victim's data.

**Detection:**
- Send varied Origin headers and inspect ACAO/ACAC reflection
- Test null origin (sandboxed iframe), subdomain and suffix bypasses
- Grep CORS middleware config for Origin reflection and credentials true
- Automated CORS scanners

**WAF —** Not a payload class — WAFs don't help; the misconfiguration is in response headers, so review and test the CORS policy directly.

**Real-world:** Numerous bug-bounty CORS data-exfiltration reports; James Kettle 'Exploiting CORS Misconfigurations' research; Multiple SaaS API credentialed-CORS disclosures

**Tools:** burp suite, corscanner, corsy, nuclei

**References:** [link](https://portswigger.net/web-security/cors) · [link](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#cross-origin-resource-sharing) · [link](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)

### Authentication Bypass
*id:* `authentication-bypass` · *category:* `auth-bypass` · *severity:* **critical** · *root cause:* [Missing or Broken Authorization](ROOT_CAUSES.md)

Flaws in login, session, or credential-verification logic let an attacker authenticate as another user or skip authentication entirely.

**Where it breaks —** Logic errors in auth flows — verification that returns early or trusts client-supplied identity, insecure password-reset tokens, response manipulation on multi-step login/2FA, default/hardcoded credentials, type-juggling in comparisons, SQLi in the login query, and forgotten pre-auth admin endpoints or debug backdoors.

**Detection:**
- Review auth state machine and each step's server-side enforcement
- Test forced browsing to post-auth endpoints
- Check password-reset token entropy/expiry/binding
- Look for loose comparisons and default creds
- Fuzz 2FA/OTP for rate limits and response tampering

**WAF —** Largely invisible to WAFs since requests look legitimate; detection depends on anomaly monitoring (impossible travel, credential stuffing volume, reset-token abuse) rather than signatures.

**Real-world:** CVE-2022-40684 (Fortinet auth bypass); CVE-2023-46805 / CVE-2024-21887 (Ivanti auth bypass chain); CVE-2021-44529 adjacent; CVE-2020-1938 (Ghostcat) adjacent; CVE-2018-13379 (Fortinet)

**Tools:** burp suite, hydra (rate-limit testing), custom scripts, nuclei templates

**References:** [link](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) · [link](https://portswigger.net/web-security/authentication) · [link](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

### Business Logic Flaws / Mass Abuse
*id:* `business-logic-abuse` · *category:* `business-logic` · *severity:* **high** · *root cause:* [Missing or Broken Authorization](ROOT_CAUSES.md)

The application enforces individual technical controls but not the intended business rules, letting attackers abuse legitimate functionality (pricing, quotas, workflows, discounts) for unintended gain.

**Where it breaks —** Implicit assumptions the code never verifies — negative/overflow quantities, applying discounts/coupons repeatedly, skipping workflow steps, manipulating price or currency client-side, exceeding limits due to missing atomicity, and trusting client-side validation. Overlaps race conditions (limit-overrun via concurrency) and mass-assignment.

**Detection:**
- Model the intended workflow and test every out-of-order / boundary / negative path
- Look for trust in client-supplied prices/quantities/state
- Concurrency testing for limit overruns
- Manual review — automated scanners rarely find these

**WAF —** Invisible to WAFs — every request is individually valid; detection relies on business-level anomaly monitoring (velocity, value thresholds, refund/coupon abuse analytics).

**Real-world:** Countless bounty reports (coupon stacking, price manipulation, gift-card abuse); Starbucks race-condition gift-card balance duplication; Airline/ecommerce currency and quantity abuse cases

**Tools:** burp suite + turbo intruder (race conditions), custom scripts, manual testing

**References:** [link](https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability) · [link](https://portswigger.net/web-security/logic-flaws) · [link](https://portswigger.net/web-security/race-conditions)

### Insecure Deserialization (Java/PHP/.NET/Python/Ruby/Node)
*id:* `insecure-deserialization` · *category:* `deserialization` · *severity:* **critical** · *root cause:* [Insecure Deserialization / Type Confusion](ROOT_CAUSES.md)

Untrusted serialized objects are deserialized into live objects, invoking magic/callback methods that gadget chains abuse to achieve RCE or other impact.

**Where it breaks —** Deserializing attacker-controlled bytes with native/polymorphic deserializers — Java ObjectInputStream/JNDI, PHP unserialize() and phar://, .NET BinaryFormatter/LosFormatter/Json.NET TypeNameHandling, Python pickle/yaml.load, Ruby Marshal/YAML, Node with libraries that revive functions — typically fed from cookies, view state, caches, message queues, or upload parsing.

**Detection:**
- Identify serialized markers (rO0 base64 for Java, O:/a: for PHP, ViewState, AAEAAAD for .NET BinaryFormatter)
- Grep for dangerous sinks (readObject, unserialize, pickle.loads, yaml.load, BinaryFormatter.Deserialize, Marshal.load)
- ysoserial-style gadget probing in a lab
- Dependency scanning for known-vulnerable gadget libraries

**WAF —** WAFs can flag known gadget magic bytes and base64 markers, but object graphs are easily re-encoded/encrypted, so signature detection is unreliable — controls belong at the deserializer (look-ahead allowlists, disabling polymorphic type handling).

**Real-world:** Apache Struts CVE-2017-5638 (Equifax breach); CVE-2015-4852 (WebLogic T3); Log4Shell CVE-2021-44228 (JNDI lookup chain); CVE-2019-18935 (Telerik .NET); CVE-2017-9805 (Struts REST XStream)

**Tools:** ysoserial / ysoserial.net, phpggc, gadgetprobe, marshalsec, freddy (burp extension)

**References:** [link](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data) · [link](https://portswigger.net/web-security/deserialization) · [link](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html) · [link](https://github.com/frohoff/ysoserial)

### Malicious File Upload leading to RCE
*id:* `file-upload-rce` · *category:* `file-upload` · *severity:* **critical** · *root cause:* [Confused Deputy / Trust-Boundary Violation](ROOT_CAUSES.md)

An upload feature accepts an executable or interpretable file (or a valid file with a dangerous extension/content) that the server later executes or serves, yielding code execution.

**Where it breaks —** Validation relies on client-supplied Content-Type or extension only, files land inside the webroot with executable handlers enabled, or double-extension/null-byte/case tricks slip past filters; also archive extraction (zip-slip), polyglot files, and image libraries with parsing bugs (ImageTragick) that turn any upload into RCE.

**Detection:**
- Grep upload handlers for extension/MIME allowlist vs blocklist and storage path
- Check whether upload directory is web-served and script-executable
- Test extension bypasses and content sniffing in a lab
- Review server config for handler mappings (.php, .jsp, .aspx, .phtml)

**WAF —** WAFs inspect multipart bodies for script signatures and dangerous extensions; conceptual evasion uses polyglots, benign-looking content with malicious handlers, and chunked/encoded uploads. Real defense is server-side content validation and non-executable storage, not payload signatures.

**Real-world:** ImageTragick CVE-2016-3714; CVE-2017-12615 (Tomcat PUT JSP); CVE-2021-22005 (vCenter file upload); CVE-2023-22515 adjacent; GhostScript CVE-2018-16509

**Tools:** burp suite, fuxploider, upload scanners, exiftool for polyglot crafting analysis

**References:** [link](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload) · [link](https://portswigger.net/web-security/file-upload) · [link](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)

### Host Header Injection
*id:* `host-header-injection` · *category:* `header-injection` · *severity:* **high** · *root cause:* [Confused Deputy / Trust-Boundary Violation](ROOT_CAUSES.md)

Apps that trust the Host (or X-Forwarded-Host) header to build absolute URLs enable poisoned password-reset links, cache poisoning, and routing-based bypasses.

**Where it breaks —** Frameworks generate absolute links, reset tokens, and redirects from the incoming Host/X-Forwarded-Host without validating it against an allowlist, so an attacker-supplied host ends up in emails, cached responses, or SSRF-style routing.

**Detection:**
- Change Host / add X-Forwarded-Host to a canary and check reflection in reset emails, links, redirects, and cached responses
- Test duplicate Host headers, absolute-URI request lines, and port injection
- Trigger password reset and inspect the generated link's host

**WAF —** The Host header is legitimate metadata; injecting an attacker domain isn't a classic signature hit. Defense: validate Host against an allowlist, use a fixed canonical hostname for link generation.

**Real-world:** Numerous password-reset poisoning bounty reports; PortSwigger Host-header attack labs and research

**Tools:** burp suite, param miner

**References:** [link](https://portswigger.net/web-security/host-header) · [link](https://portswigger.net/web-security/host-header/exploiting) · [link](https://cheatsheetseries.owasp.org/cheatsheets/OWASP_Application_Security_Verification_Standard.html)

### JWT / JWS Attacks
*id:* `jwt-attacks` · *category:* `jwt` · *severity:* **high** · *root cause:* [Confused Deputy / Trust-Boundary Violation](ROOT_CAUSES.md)

Weaknesses in how JSON Web Tokens are validated let attackers forge or tamper with tokens to impersonate users or escalate privileges.

**Where it breaks —** Verification that trusts the token's own alg header — alg:none acceptance, RS256-to-HS256 confusion (verifying an asymmetric token with the public key as an HMAC secret), weak/guessable HMAC secrets, unvalidated kid (path traversal / SQLi / SSRF via jku/x5u), missing signature verification, and not checking exp/aud/iss.

**Detection:**
- Decode tokens and inspect alg/kid/jku/x5u headers
- Test alg:none and algorithm confusion in a lab
- Brute-force weak HMAC secrets (hashcat)
- Check server-side enforcement of expected algorithm and claims
- Review kid/jku handling for injection/SSRF

**WAF —** WAFs rarely inspect JWT internals; alg:none and confusion attacks pass as normal Authorization headers, so validation must be enforced in the app/library configuration.

**Real-world:** CVE-2015-9235 (jsonwebtoken alg confusion); CVE-2016-5431 adjacent; CVE-2022-21449 (Java ECDSA psychic signatures); Auth0 and multiple library alg:none disclosures

**Tools:** jwt_tool, hashcat, burp jwt editor, jwt.io (analysis)

**References:** [link](https://portswigger.net/web-security/jwt) · [link](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html) · [link](https://datatracker.ietf.org/doc/html/rfc8725)

### NoSQL Injection
*id:* `nosql-injection` · *category:* `nosql` · *severity:* **high** · *root cause:* [Code/Data Confusion (In-Band Control)](ROOT_CAUSES.md)

Attacker-controlled operators or JavaScript passed into NoSQL queries (MongoDB $where/$ne/$gt, $regex) bypass authentication and extract data without classic SQL syntax.

**Where it breaks —** Document stores that accept query operators from JSON bodies or coerce query-string params into objects let clients replace a scalar with an operator object ({"$ne":null}) or supply server-side JS ($where) that runs in the DB, subverting filters and auth.

**Detection:**
- Send operator objects ($ne, $gt, $regex, $where) in login/filter fields and observe auth bypass or boolean differences
- Test param[$ne]=x query-string-to-object coercion in Express/PHP
- Use $regex/$where for blind boolean/timing extraction
- Look for server-side JavaScript evaluation sinks

**WAF —** JSON operator payloads and array-bracket param coercion evade SQLi-focused WAFs; the dollar-sign operators look benign. Defense: type-check/cast inputs, disable $where/JS, use query allowlists.

**Real-world:** Numerous MongoDB auth-bypass bounty reports; PayloadsAllTheThings NoSQL section documents real cases

**Tools:** nosqlmap, burp suite, nosqli

**References:** [link](https://owasp.org/www-community/Injection_Flaws) · [link](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html) · [link](https://portswigger.net/web-security/nosql-injection)

### OAuth / OIDC & SAML Federation Flaws
*id:* `oauth-oidc-saml-flaws` · *category:* `oauth-saml` · *severity:* **high** · *root cause:* [Confused Deputy / Trust-Boundary Violation](ROOT_CAUSES.md)

Misimplementations of delegated auth and SSO protocols allow account takeover, token theft, or authentication bypass.

**Where it breaks —** OAuth: unvalidated/loosely-matched redirect_uri, missing or non-verified state (CSRF), implicit-flow token leakage, missing PKCE on public clients, authorization-code injection/mix-up, and over-trusting client-supplied identity. SAML: signature-not-verified or partial verification, XML Signature Wrapping (XSW), canonicalization/comment-injection, and IdP-confusion; OIDC adds nonce/aud/iss and id_token validation gaps.

**Detection:**
- Test redirect_uri matching strictness and open-redirect chains
- Check state/nonce presence and server-side validation
- SAML response tampering and XSW testing (SAML Raider)
- Verify signature coverage of the whole assertion and audience/issuer checks
- Confirm PKCE enforcement

**WAF —** Protocol messages look legitimate to WAFs; XSW and redirect abuses are logic flaws, so correctness lives in the SSO library configuration and strict validation, not signatures.

**Real-world:** Microsoft/Okta and Sign in with Apple (CVE-2020, nonce) research; SAML XSW research (Somorovsky et al.); CVE-2017-11427/11428 (OneLogin/python-saml comment injection, aka SAMLStorm-era); CVE-2022-21703 adjacent; Multiple OAuth account-takeover bounties

**Tools:** burp suite + saml raider, espresso, oauth testing scripts, samltool

**References:** [link](https://portswigger.net/web-security/oauth) · [link](https://portswigger.net/web-security/saml) · [link](https://oauth.net/2/security-best-current-practice/) · [link](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html)

### Path Traversal / Local File Inclusion / Remote File Inclusion
*id:* `path-traversal-lfi-rfi` · *category:* `path-traversal` · *severity:* **high** · *root cause:* [Confused Deputy / Trust-Boundary Violation](ROOT_CAUSES.md)

User input controls a filesystem path or include target, letting attackers read/write files outside the intended directory (LFI/traversal) or include remote code (RFI).

**Where it breaks —** Building paths by concatenating request input into file reads, template/include statements, or archive extraction without canonicalizing and confining to a base directory; ../ sequences, absolute paths, URL/double-URL/unicode encoding, and null bytes escape the intended root. RFI arises when include targets accept remote URLs (allow_url_include).

**Detection:**
- Grep file APIs (open, readFile, include/require, sendFile, File(), fs.readFile) fed by request data
- Canonicalization checks — does the code realpath and verify prefix?
- Traversal fuzzing with encodings
- Detect LFI via known files (/etc/passwd, web.config, wrappers php://filter)

**WAF —** WAFs match ../ and known file names; conceptual evasion uses encoding layers, mixed slashes, overlong UTF-8, and wrapper schemes. Canonicalize-then-confine on the server is the reliable control.

**Real-world:** CVE-2021-41773 / CVE-2021-42013 (Apache HTTP Server path traversal → RCE); CVE-2018-1000861 adjacent; CVE-2019-11510 (Pulse Secure arbitrary file read); CVE-2024-3400 (PAN-OS path traversal chain)

**Tools:** burp suite, ffuf / dotdotpwn, lfisuite, semgrep

**References:** [link](https://owasp.org/www-community/attacks/Path_Traversal) · [link](https://portswigger.net/web-security/file-path-traversal) · [link](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)

### OS Command Injection
*id:* `os-command-injection` · *category:* `rce` · *severity:* **critical** · *root cause:* [Code/Data Confusion (In-Band Control)](ROOT_CAUSES.md)

User input reaches a shell or command interpreter, letting an attacker append or alter commands executed by the host OS.

**Where it breaks —** Calls that spawn a shell (system, exec with shell=True, popen, Runtime.exec of a string, child_process.exec, backticks) with concatenated input — commonly in ping/traceroute utilities, file conversion (ImageMagick/ffmpeg wrappers), archive handling, and admin/diagnostic endpoints. Argument-injection is a subtler variant where separate args are safe but a value becomes a flag.

**Detection:**
- Grep for shell-spawning APIs with dynamic strings
- OOB detection for blind cases (DNS/HTTP callback from injected command)
- Time-delay probes (sleep)
- Taint analysis to command sinks

**WAF —** WAFs flag metacharacters and common binaries (cat, /etc/passwd, nc); conceptual evasion uses shell expansion, variable indirection, quoting, and whitespace alternatives (IFS). Signature matching is brittle — safe argv-based execution is the durable control.

**Real-world:** Shellshock CVE-2014-6271; CVE-2021-44228 adjacent tooling; CVE-2014-3120 (Elasticsearch); CVE-2021-22205 (GitLab ExifTool → RCE); CVE-2024-4577 (PHP-CGI argument injection on Windows)

**Tools:** burp + collaborator, commix, semgrep/codeql

**References:** [link](https://owasp.org/www-community/attacks/Command_Injection) · [link](https://portswigger.net/web-security/os-command-injection) · [link](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)

### HTTP Request Smuggling / Desync
*id:* `http-request-smuggling` · *category:* `request-smuggling` · *severity:* **high** · *root cause:* [Parser Differential / Impedance Mismatch](ROOT_CAUSES.md)

Front-end and back-end servers disagree on where one HTTP request ends, letting an attacker prepend data to the next user's request and poison the connection.

**Where it breaks —** Chains of proxies/CDNs/app servers that parse Content-Length vs Transfer-Encoding differently (CL.TE, TE.CL, TE.TE), or newer HTTP/2-to-HTTP/1 downgrade desync and CL.0 / client-side desync — arising when intermediaries and origins normalize headers inconsistently or forward ambiguous framing.

**Detection:**
- Timing-based probes for CL.TE/TE.CL discrepancies
- HTTP/2 downgrade and CL.0 testing
- Burp HTTP Request Smuggler extension
- Review proxy/origin header-parsing configs and duplicate/obfuscated header handling

**WAF —** The desync often happens before or around the WAF, so front-end filtering can be bypassed entirely; some WAFs now detect obfuscated Transfer-Encoding, but robust framing normalization at every hop is the real defense.

**Real-world:** PortSwigger/James Kettle research (2019 revival, HTTP/2 desync 2021, browser-powered desync 2022); Multiple large-bounty reports against major CDNs and SaaS; CVE-2019-18277 (HAProxy) and related; CVE-2021-33193 (Apache mod_http2)

**Tools:** burp suite + http request smuggler, turbo intruder, h2csmuggler, smuggler.py

**References:** [link](https://portswigger.net/web-security/request-smuggling) · [link](https://portswigger.net/research/http2) · [link](https://portswigger.net/research/browser-powered-desync-attacks) · [link](https://cwe.mitre.org/data/definitions/444.html)

### SQL Injection (classic, blind, boolean/time-based, second-order)
*id:* `sql-injection` · *category:* `sqli` · *severity:* **critical** · *root cause:* [Code/Data Confusion (In-Band Control)](ROOT_CAUSES.md)

Untrusted input is concatenated into SQL so the parser treats attacker data as query syntax, allowing data exfiltration, authentication bypass, and sometimes RCE via database features.

**Where it breaks —** String-built queries anywhere an ORM or driver's parameterization is bypassed — dynamic ORDER BY / column / table names (which cannot be parameterized), LIKE clauses, IN() lists built by concatenation, raw query escape hatches, and second-order cases where data is stored safely then later concatenated into a query.

**Detection:**
- Grep for string concatenation/format into query APIs (execute, rawQuery, createQuery, f-strings, +)
- Error-based fingerprinting from DB error messages
- Boolean and time-based differential testing (blind)
- Static analysis / CodeQL taint tracking source→sink
- sqlmap on suspect parameters

**WAF —** WAFs match keyword/comment/quote signatures (UNION SELECT, OR 1=1, --); conceptual evasion uses inline comments, case/whitespace variation, alternative encodings, and logically equivalent syntax — which is why parameterized queries, not signatures, are the fix. Defensive teams should alert on DB errors and anomalous query shapes.

**Real-world:** MOVEit Transfer CVE-2023-34362 (Cl0p mass exploitation); CVE-2022-21661 (WordPress core WP_Query); Heartland/7-Eleven breaches (Albert Gonzalez); CVE-2019-15107 (Webmin adjacent)

**Tools:** sqlmap, burp suite, codeql / semgrep, nosqlmap (for nosql variants)

**References:** [link](https://owasp.org/www-community/attacks/SQL_Injection) · [link](https://portswigger.net/web-security/sql-injection) · [link](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

### SSRF via PDF/SVG/Image/Webhook Renderers
*id:* `ssrf-renderer-pdf-svg-image` · *category:* `ssrf` · *severity:* **critical** · *root cause:* [Network-Position Abuse / Implicit Network Trust](ROOT_CAUSES.md)

Server-side document/image renderers and user-configurable webhooks fetch attacker-controlled URLs, letting requests reach internal services and cloud metadata endpoints.

**Where it breaks —** Headless-Chrome/wkhtmltopdf PDF export, SVG rasterizers (ImageMagick/librsvg), image-from-URL features, and webhook/callback configs perform outbound fetches from inside the trust boundary, often following redirects and honoring file://, http://169.254.169.254, and internal hostnames.

**Detection:**
- Supply external URLs (Burp Collaborator) in HTML-to-PDF content, SVG <image>/<use>, image-URL fields, and webhook targets; watch for callbacks
- Test redirect-following, DNS rebinding, and alternate schemes/IP encodings to reach metadata/internal ranges
- Probe for blind SSRF via timing and out-of-band interactions

**WAF —** Egress WAFs often only watch inbound payloads; the malicious request originates server-side. IP-encoding tricks, DNS rebinding, and redirects bypass naive allow/deny lists — defense is IMDSv2, egress filtering, and URL validation after resolution.

**Real-world:** Capital One 2019 breach (SSRF to AWS metadata); Numerous HTML-to-PDF SSRF bounty reports; ImageMagick/'ImageTragick' CVE-2016-3714 SSRF/RCE via image handling

**Tools:** burp collaborator, ssrfmap, gopherus (for gopher pivots), interactsh

**References:** [link](https://portswigger.net/web-security/ssrf) · [link](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) · [link](https://blog.assetnote.io/2021/01/13/blind-ssrf-chains/)

### Server-Side Request Forgery (SSRF), including blind/OOB
*id:* `ssrf-server-side-request-forgery` · *category:* `ssrf` · *severity:* **critical** · *root cause:* [Network-Position Abuse / Implicit Network Trust](ROOT_CAUSES.md)

The server can be coerced into making HTTP(S) or other-protocol requests to attacker-chosen destinations, typically internal services, cloud metadata endpoints, or link-local addresses that are unreachable from the outside.

**Where it breaks —** Any feature that fetches a user-supplied URL/host — webhooks, URL preview/unfurling, PDF/HTML-to-image renderers, image proxies, import-from-URL, XML/SVG parsers, file fetchers, and open-redirect chains — where the app validates the URL with a blocklist or a single DNS resolution instead of resolving-then-pinning to a vetted IP.

**Detection:**
- Grep for outbound HTTP clients (curl, requests, HttpClient, URL.openConnection, file_get_contents, axios, net/http) fed with request-derived URLs
- Out-of-band interaction testing via Burp Collaborator / interactsh for blind cases
- Inspect responses for differential timing/errors when pointing at internal ports
- Watch for DNS lookups to attacker domains and requests to 169.254.169.254 / metadata.google.internal / fd00:ec2::254

**WAF —** WAFs key on literal internal IPs and metadata hostnames in parameters; evasion is conceptual — decimal/octal/hex IP encoding, DNS rebinding, redirect chains, and userinfo/@ tricks defeat naive string matching. Robust defense is not a WAF but resolve-and-pin plus egress network controls (IMDSv2, blocking link-local from workloads).

**Real-world:** Capital One 2019 breach (SSRF to AWS IMDS, 100M+ records); CVE-2021-26855 (Exchange ProxyLogon SSRF); CVE-2021-21985 (VMware vCenter); CVE-2022-1388 (F5 BIG-IP iControl REST SSRF-adjacent); GitLab CVE-2021-22214

**Tools:** burp suite + collaborator, interactsh / oast, ssrfmap, gopherus, ffuf for internal port discovery

**References:** [link](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery) · [link](https://portswigger.net/web-security/ssrf) · [link](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) · [link](https://www.capitalone.com/digital/facts2019/)

### Open Redirect (and Redirect-to-SSRF / auth-token leak chains)
*id:* `open-redirect-ssrf-chain` · *category:* `ssrf` · *severity:* **medium** · *root cause:* [Confused Deputy / Trust-Boundary Violation](ROOT_CAUSES.md)

The application redirects to a user-controlled URL without validation, enabling phishing, OAuth token/credential leakage, and bypass of SSRF/allowlist filters via redirect following.

**Where it breaks —** Redirect/return/next/callback parameters echoed into a Location header without allowlisting; also server-side fetchers that follow redirects, so an attacker passes an allowlisted URL that 30x-redirects to an internal target (TOCTOU/filter bypass). URL-parser confusion (backslashes, @, //, whitespace) defeats naive origin checks.

**Detection:**
- Grep redirect sinks (sendRedirect, Location header, res.redirect, window.location on server-rendered) fed by request params
- Test open-redirect payloads and parser confusion
- Check whether server-side clients follow redirects and re-validate the final IP
- Review OAuth redirect_uri handling

**WAF —** WAFs may flag http:// in redirect params; conceptual evasion uses protocol-relative //, backslashes, @-userinfo, and encoding — so URL parsing must be normalized and destinations allowlisted, not filtered by substrings.

**Real-world:** Numerous OAuth token-theft bounties via redirect_uri + open redirect; CVE-2019-11510 chains; Well-known open-redirect + SSRF bypass writeups against cloud image proxies; Google/Facebook open-redirect bounty history

**Tools:** burp suite, oralyzer, nuclei open-redirect templates

**References:** [link](https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards) · [link](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html) · [link](https://portswigger.net/web-security/ssrf)

### Server-Side Template Injection (SSTI)
*id:* `ssti-server-side-template-injection` · *category:* `ssti` · *severity:* **critical** · *root cause:* [Code/Data Confusion (In-Band Control)](ROOT_CAUSES.md)

User input is embedded into a server-side template that is then evaluated, allowing template-language expression execution that frequently escalates to RCE.

**Where it breaks —** Concatenating user input into the template source (not the data context) — e.g., rendering a string built from input in Jinja2/Twig/Freemarker/Velocity/ERB/Handlebars/Thymeleaf — common in email/notification templating, CMS themes, and report generators that let users supply template snippets.

**Detection:**
- Polyglot probes evaluating arithmetic (e.g., {{7*7}} style across engines) to fingerprint the engine
- Grep for render_template_string / new Template(userInput) / eval-like template APIs
- Differential responses indicating evaluation vs literal echo

**WAF —** WAFs look for {{ }} / ${ } and engine builtins; conceptual evasion uses attribute-access indirection, string concatenation of dangerous names, and encoding. Because payloads are engine-specific and highly variable, architectural separation of code and data is the real control.

**Real-world:** CVE-2016-4977 (Spring EL); CVE-2019-3396 (Confluence Widget Connector Velocity); CVE-2021-26084 (Confluence OGNL); CVE-2022-22954 (VMware Workspace ONE freemarker/EL)

**Tools:** tplmap, burp suite, semgrep

**References:** [link](https://portswigger.net/web-security/server-side-template-injection) · [link](https://owasp.org/www-community/attacks/Server_Side_Template_Injection) · [link](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)

### Dependency Confusion
*id:* `dependency-confusion` · *category:* `supply-chain` · *severity:* **critical** · *root cause:* [Supply Chain / Transitive Trust](ROOT_CAUSES.md)

Publishing a public package with the same name as an org's private internal package causes build tooling to pull the attacker's higher-versioned public copy, achieving code execution in CI/prod.

**Where it breaks —** Package managers (npm/pip/gem/Maven/NuGet) that search public and private registries without scoping or explicit source pinning resolve by highest version across all configured sources, so a public namesake with version 99.0.0 wins over the internal 1.x.

**Detection:**
- Enumerate internal package names leaked in source maps, package.json, error messages, or public artifacts
- Check whether those names are unclaimed on public registries
- Audit registry/config for source pinning, scopes, and repository priority

**WAF —** Not a WAF-facing attack at all — it's a build-time supply-chain issue. Defense: scoped packages, registry allowlists, verified/pinned sources, and reserving internal names publicly.

**Real-world:** Alex Birsan 'Dependency Confusion' (2021) — breached Apple, Microsoft, PayPal, Shopify, etc.; Subsequent widespread npm/PyPI namesquatting incidents

**Tools:** confused (dependency-confusion scanner), snyk, internal registry audits

**References:** [link](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610) · [link](https://github.com/visma-prodsec/confused) · [link](https://owasp.org/www-project-top-ten/)

### Software Supply-Chain / Dependency Attacks (incl. dependency confusion)
*id:* `supply-chain-dependency` · *category:* `supply-chain` · *severity:* **critical** · *root cause:* [Supply Chain / Transitive Trust](ROOT_CAUSES.md)

Compromise reaches the server through trusted build/dependency channels rather than a direct request — malicious or hijacked packages, dependency confusion, and poisoned build pipelines.

**Where it breaks —** Installing packages by name without namespace/registry pinning (public registry shadows an internal name — dependency confusion), typosquats, unpinned/unverified dependencies, compromised maintainer accounts, and CI/CD secrets or build steps that execute untrusted code (install scripts, GitHub Actions).

**Detection:**
- Inventory dependencies and internal package names that could be shadowed publicly
- SBOM generation and SCA scanning for known-malicious/vulnerable versions
- Lockfile and integrity-hash verification
- Monitor for install-time scripts and unexpected network egress during build
- Registry scoping/namespacing review

**WAF —** Out of scope for request WAFs entirely — this is a build/runtime trust problem addressed by SCA, registry configuration, artifact signing (Sigstore), and pipeline hardening.

**Real-world:** Alex Birsan dependency confusion research (2021, 35+ major companies); event-stream npm backdoor (2018); SolarWinds SUNBURST (2020); Codecov bash uploader (2021); ua-parser-js / colors / node-ipc incidents; XZ Utils backdoor CVE-2024-3094 (2024)

**Tools:** snyk / dependabot / osv-scanner, syft/grype (sbom), sigstore/cosign, socket.dev

**References:** [link](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610) · [link](https://owasp.org/www-project-top-ten/2021/A06_2021-Vulnerable_and_Outdated_Components) · [link](https://slsa.dev/) · [link](https://www.cisa.gov/news-events/alerts/2024/03/29/reported-supply-chain-compromise-affecting-xz-utils-data-compression-library-cve-2024-3094)

### XML External Entity (XXE) Injection
*id:* `xxe-xml-external-entity` · *category:* `xxe` · *severity:* **high** · *root cause:* [Insecure Defaults & Misconfiguration](ROOT_CAUSES.md)

An XML parser configured to resolve external entities processes attacker-controlled XML, enabling file read, SSRF, and sometimes RCE or DoS.

**Where it breaks —** XML parsers left at insecure defaults (external general/parameter entities and DTDs enabled) processing user input — SOAP endpoints, SAML, SVG/Office/document uploads (which are XML zips), RSS/XML APIs, and configuration importers. Blind/OOB XXE uses parameter entities and external DTDs when direct output is not reflected.

**Detection:**
- Identify XML parsers and whether DTD/external entities are disabled (DocumentBuilderFactory features, libxml_disable_entity_loader, XmlResolver=null)
- Inject entities referencing local files or OOB URLs in a lab
- Test file-upload endpoints that parse XML-based formats (docx, svg, xlsx)
- OOB DTD callback for blind detection

**WAF —** WAFs flag <!DOCTYPE / <!ENTITY / SYSTEM keywords; conceptual evasion uses UTF-16/encoding tricks, parameter-entity indirection, and moving the payload into uploaded XML formats. The parser-level disable is the fix, not signatures.

**Real-world:** CVE-2014-3660 (libxml2); CVE-2017-9805 adjacent; Facebook 2014 XXE bug bounty; CVE-2018-1000840 (SAML); CVE-2019-0227 (Apache Axis)

**Tools:** burp suite (+ collaborator), xxeinjector, oxml_xxe, semgrep

**References:** [link](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing) · [link](https://portswigger.net/web-security/xxe) · [link](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)


## Uncommon (18)

### Argument / Parameter Injection
*id:* `argument-parameter-injection` · *category:* `business-logic` · *severity:* **high** · *root cause:* [Code/Data Confusion (In-Band Control)](ROOT_CAUSES.md)

Passing user input as arguments to CLI tools or system utilities lets attackers inject extra flags/options that change behavior (file write, config override) even without a shell metacharacter.

**Where it breaks —** Apps that invoke binaries (git, curl, tar, ffmpeg, gpg, find, ImageMagick) with user input as an argument — even via safe argv (no shell) — don't separate options from operands, so input starting with - is parsed as a flag, enabling dangerous options.

**Detection:**
- Supply inputs beginning with - or -- (e.g. --output, --upload-pack, -o) where a filename/value is expected
- Check whether the app inserts a -- end-of-options separator
- Enumerate the target binary's dangerous flags reachable via the injected position

**WAF —** No shell metacharacters means metachar-focused WAF rules miss it; the payload is a plain hyphenated token. Defense: -- separators, strict value validation, and allowlisted arguments.

**Real-world:** git '--upload-pack'/'--output' argument-injection CVEs; curl -o/-K and ImageMagick option-injection cases documented by Semgrep/PortSwigger

**Tools:** burp suite, semgrep (argument-injection rules), manual binary flag review

**References:** [link](https://sonarsource.github.io/argument-injection-vectors/) · [link](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html) · [link](https://owasp.org/www-community/attacks/Command_Injection)

### HTTP/2 Rapid Reset
*id:* `http2-rapid-reset` · *category:* `business-logic` · *severity:* **high** · *root cause:* [State Desynchronization & Race Conditions](ROOT_CAUSES.md)

Rapidly opening and immediately cancelling (RST_STREAM) HTTP/2 streams forces the server to do request work without hitting concurrency limits, enabling record-breaking DoS.

**Where it breaks —** HTTP/2 lets a client open a stream and instantly reset it; many servers begin processing (and allocate resources for) the request before the cancel and don't count reset streams against MAX_CONCURRENT_STREAMS, so a client can create unbounded in-flight work over one connection.

**Detection:**
- Monitor for high volumes of quickly-reset streams / abnormal RST_STREAM rates
- Check server versions against CVE-2023-44487 patches and mitigation configs
- Load-test with rapid open+reset patterns in a controlled environment

**WAF —** Traffic is protocol-valid HTTP/2 frames, not malicious payloads; L7 signature WAFs miss it. Defense: cap total/reset streams per connection, patch server stacks, rate-limit resets.

**Real-world:** CVE-2023-44487 'HTTP/2 Rapid Reset' — largest-ever DDoS disclosed by Google/Cloudflare/AWS (Oct 2023)

**Tools:** controlled load generators, nghttp2, server telemetry

**References:** [link](https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/) · [link](https://cloud.google.com/blog/products/identity-security/how-it-works-the-novel-http2-rapid-reset-ddos-attack) · [link](https://nvd.nist.gov/vuln/detail/CVE-2023-44487)

### ORM Injection / ORM Leak
*id:* `orm-injection` · *category:* `business-logic` · *severity:* **high** · *root cause:* [Code/Data Confusion (In-Band Control)](ROOT_CAUSES.md)

Passing attacker-controlled structures into ORM query builders (operators, relations, field selectors) lets attackers craft unintended queries, bypass filters, or exfiltrate data via relational operators.

**Where it breaks —** ORMs (Sequelize, TypeORM, Prisma, Django ORM, Hibernate HQL, ActiveRecord) that accept nested objects or raw fragments from request bodies let clients inject operators ($gt, OR, LIKE, relation traversal) or HQL/JPQL strings, turning a filter into an arbitrary predicate or exposing related tables.

**Detection:**
- Send operator objects (e.g. {"password":{"$ne":null}} style or Sequelize [Op] equivalents) where a scalar is expected
- Test relation/field selectors for traversal to sibling tenants or sensitive columns
- Look for raw()/HQL string concatenation and where-clause passthrough
- Boolean/inference oracles via ORM-leak (character-by-character via relation filters)

**WAF —** Structured JSON operators don't match SQLi signatures; the injection is at the ORM DSL layer. Defense: strict input schemas, explicit field allowlists, parameterized raw queries.

**Real-world:** Alvaro Muñoz / others on Hibernate HQL injection; 'ORM Leak' research on relational-operator data exfiltration (2023); Sequelize operator-injection advisories

**Tools:** burp suite, custom operator fuzzers, semgrep orm rules

**References:** [link](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html) · [link](https://www.elttam.com/blog/plormbing-your-django-orm/) · [link](https://owasp.org/www-community/attacks/SQL_Injection)

### Second-Order (Stored) Injection
*id:* `second-order-injection` · *category:* `business-logic` · *severity:* **high** · *root cause:* [Confused Deputy / Trust-Boundary Violation](ROOT_CAUSES.md)

Input stored safely in one context is later used unsafely in another (SQL, command, template, LDAP), so the injection fires on a subsequent operation that skips validation.

**Where it breaks —** Data validated/escaped at the entry point is trusted when re-read from the database or another store and concatenated into a query/command/template elsewhere (batch jobs, admin views, reporting), because developers assume stored data is safe.

**Detection:**
- Seed fields with injection markers, then exercise every downstream feature that reads them (profile display, reports, admin panels, background jobs)
- Trace data flow from storage to sinks rather than only testing the input endpoint
- Look for reuse of stored usernames/filenames/values in dynamic queries

**WAF —** The malicious request that plants the payload may look benign or be normalized on entry; the sink fires internally with no HTTP request to inspect. Defense: parameterize/escape at every sink, treat stored data as untrusted.

**Real-world:** Classic second-order SQLi in password-reset/username flows; OWASP and PortSwigger documented stored-then-executed cases

**Tools:** burp suite, sqlmap (--second-order), manual data-flow tracing

**References:** [link](https://portswigger.net/web-security/sql-injection) · [link](https://owasp.org/www-community/attacks/SQL_Injection) · [link](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)

### Cross-Site WebSocket Hijacking (CSWSH)
*id:* `websocket-cross-site-hijacking` · *category:* `business-logic` · *severity:* **high** · *root cause:* [Missing or Broken Authorization](ROOT_CAUSES.md)

WebSocket handshakes authenticated solely by cookies and lacking Origin validation let a malicious page open a cross-site socket in the victim's context and read/send messages.

**Where it breaks —** The WebSocket upgrade is a normal HTTP request that carries cookies but is not protected by CORS or CSRF tokens; if the server authenticates via ambient cookies and doesn't check the Origin header, any origin can establish an authenticated socket.

**Detection:**
- Check whether the WS handshake validates Origin and uses a CSRF token/non-cookie auth
- From a test page on another origin, attempt to open the socket with the victim's cookies and exchange messages
- Inspect handshake for Sec-WebSocket-* only vs. real authz

**WAF —** The handshake looks like a legitimate upgrade; WAFs rarely enforce Origin on WS. Defense: validate Origin, require a CSRF token or non-cookie auth on the handshake.

**Real-world:** PortSwigger CSWSH labs and research; Assorted chat/notification WebSocket hijacking bounty reports

**Tools:** burp suite (websocket tools), custom test pages

**References:** [link](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking) · [link](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html) · [link](https://christian-schneider.net/CrossSiteWebSocketHijacking.html)

### Web Cache Deception
*id:* `web-cache-deception` · *category:* `cache-poisoning` · *severity:* **high** · *root cause:* [Parser Differential / Impedance Mismatch](ROOT_CAUSES.md)

Tricking a cache into storing a victim's authenticated dynamic response under a static-looking URL, then retrieving it to leak private data.

**Where it breaks —** The cache and origin disagree about whether a URL is static: origin routes /account/profile.css to the profile page (ignoring the extension), while the CDN caches by extension and stores the personalized response as if it were a public .css file.

**Detection:**
- Append static-looking suffixes/path segments (/nonexistent.css, ;.js, %2f..) to authenticated pages and check for caching
- Compare origin routing vs. cache extension parsing for path-confusion (delimiter, encoded slash, path parameter)
- Inspect cache-status headers after requesting the crafted URL from a second session

**WAF —** Not a payload attack — nothing malicious in bytes; WAFs don't model cache/origin path-parsing differentials. Mitigation is cache-rule and normalization alignment, not filtering.

**Real-world:** Omer Gil original 'Web Cache Deception' (2017), PayPal case; PortSwigger 2024 'Gotta cache 'em all' delimiter/normalization research (Martin Doyhenard)

**Tools:** burp suite, cache-status inspection, custom path fuzzers

**References:** [link](https://portswigger.net/web-security/web-cache-deception) · [link](https://portswigger.net/research/gotta-cache-em-all) · [link](https://omergil.blogspot.com/2017/02/web-cache-deception-attack.html)

### Web Cache Poisoning
*id:* `web-cache-poisoning` · *category:* `cache-poisoning` · *severity:* **high** · *root cause:* [State Desynchronization & Race Conditions](ROOT_CAUSES.md)

Unkeyed inputs (headers, cookies, params) that influence a response but aren't part of the cache key let an attacker store a malicious response served to all users.

**Where it breaks —** CDNs/reverse proxies cache by a subset of the request (the cache key) while the origin reflects unkeyed inputs (X-Forwarded-Host, X-Forwarded-Scheme, custom headers, fat GET params) into responses; the poisoned response is then replayed to victims.

**Detection:**
- Identify cache hits/misses via Age, X-Cache, CF-Cache-Status headers
- Probe unkeyed headers with a canary value and check if it's reflected AND cached
- Use Param Miner to discover unkeyed inputs/secret headers
- Test cache-key normalization (case, ports, encoded chars) for keyed/unkeyed discrepancies

**WAF —** WAFs rarely inspect the interaction between cache key and reflected input; benign-looking headers pass through, and the harm manifests only after caching. Defense requires cache-key hygiene, not signatures.

**Real-world:** PortSwigger 'Practical Web Cache Poisoning' and 'Web Cache Entanglement' (James Kettle); Multiple bug bounty reports poisoning JS/redirects on major CDNs

**Tools:** burp param miner, burp suite, custom header fuzzers

**References:** [link](https://portswigger.net/research/practical-web-cache-poisoning) · [link](https://portswigger.net/research/web-cache-entanglement) · [link](https://portswigger.net/web-security/web-cache-poisoning)

### GraphQL Batching, Alias Abuse & Introspection
*id:* `graphql-batching-alias-abuse` · *category:* `graphql` · *severity:* **high** · *root cause:* [Missing or Broken Authorization](ROOT_CAUSES.md)

GraphQL aliasing and query batching let one HTTP request run thousands of operations (brute-force/rate-limit bypass, DoS), while enabled introspection and field suggestions leak the schema.

**Where it breaks —** Rate limiting and cost controls are applied per-HTTP-request, but a single GraphQL document can contain hundreds of aliased fields or an array of batched operations; introspection/'did you mean' suggestions expose hidden types even when disabled.

**Detection:**
- Query __schema/__type for introspection; if disabled, probe field-suggestion leakage
- Send aliased duplicate mutations (login attempts) in one request to test rate-limit bypass
- Send batched query arrays; measure amplification and depth/cost handling
- Map deep nested/circular queries for DoS potential

**WAF —** WAFs treat the request as one POST and rarely parse GraphQL ASTs, so per-request throttling and body-size limits miss alias/batch amplification. Defense needs query cost analysis, depth limits, disabled introspection, and persisted queries.

**Real-world:** Multiple bug bounty disclosures of OTP/2FA brute force via GraphQL aliasing; OWASP GraphQL cheat sheet documented alias/batch abuse

**Tools:** inql (burp), graphql-cop, clairvoyance (schema recovery), graphql voyager

**References:** [link](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html) · [link](https://portswigger.net/web-security/graphql) · [link](https://github.com/nikitastupin/clairvoyance)

### Email Header Injection
*id:* `email-header-injection` · *category:* `header-injection` · *severity:* **medium** · *root cause:* [Code/Data Confusion (In-Band Control)](ROOT_CAUSES.md)

CRLF in user input reflected into email headers lets attackers add recipients (Bcc/Cc), spoof headers, or inject a body, enabling spam relay and phishing from the app.

**Where it breaks —** Contact/feedback/reset forms that place user input into To/From/Subject/headers via mail() or raw SMTP without stripping CR/LF allow injection of extra header lines and, after a blank line, a new body.

**Detection:**
- Inject %0d%0a followed by Bcc:/Cc:/Subject: into name/subject/email fields and check for extra recipients or headers
- Test encoded newline variants and header/body separation
- Review mail-sending code for CRLF sanitization

**WAF —** Encoded CRLF may pass generic filters, and the header injection happens at the mail layer; content WAFs seldom model it. Defense: strip/reject CR/LF, use hardened mail libraries with separate header APIs.

**Real-world:** Widespread PHP mail() header-injection spam-relay cases; OWASP and Acunetix documented email-injection incidents

**Tools:** burp suite, custom crlf fuzzers

**References:** [link](https://owasp.org/www-community/vulnerabilities/CRLF_Injection) · [link](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html) · [link](https://www.acunetix.com/websitesecurity/email-header-injection/)

### LDAP Injection
*id:* `ldap-injection` · *category:* `ldap` · *severity:* **high** · *root cause:* [Code/Data Confusion (In-Band Control)](ROOT_CAUSES.md)

Unescaped input in LDAP search filters lets attackers alter filter logic to bypass authentication or enumerate directory attributes.

**Where it breaks —** Apps that build LDAP filters like (&(uid=INPUT)(...)) via string concatenation without escaping filter metacharacters (*, (, ), \, NUL) allow injection of extra clauses, wildcards, or always-true conditions ((uid=*)) into the directory query.

**Detection:**
- Inject * and )( sequences into username/search fields and watch for auth bypass or broadened results
- Test blind boolean extraction via filter manipulation on attributes
- Look for LDAP bind/search built from concatenated input

**WAF —** LDAP metacharacters overlap with benign input and don't trip SQLi rules; blind boolean variants send no obvious payload. Defense: RFC-4515 filter escaping and parameterized directory APIs.

**Real-world:** OWASP LDAP injection documentation and testing guide cases; Various enterprise SSO/LDAP auth-bypass disclosures

**Tools:** burp suite, ldapsearch, custom filter fuzzers

**References:** [link](https://owasp.org/www-community/attacks/LDAP_Injection) · [link](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html) · [link](https://portswigger.net/web-security/all-labs#ldap-injection)

### Mass Assignment / Auto-binding (Object Property Injection)
*id:* `mass-assignment-autobinding` · *category:* `mass-assignment` · *severity:* **high** · *root cause:* [Implicit Trust of Client-Controlled Input & Metadata](ROOT_CAUSES.md)

Frameworks that automatically bind request parameters to object fields let attackers set properties they should not control, such as role, isAdmin, balance, or ownership.

**Where it breaks —** Blindly binding request bodies to ORM models/DTOs (Rails, Spring, Django, Laravel, ASP.NET model binding, Node/Mongoose) without an explicit allowlist — so extra JSON fields like is_admin, verified, price, or user_id get persisted; nested binding and JSON make hidden fields easy to inject.

**Detection:**
- Grep for whole-object binding (Model.create(params), @ModelAttribute, ORM save of request-derived objects) without field allowlists
- Add unexpected fields to requests and check persistence/authz effects
- Review models for sensitive attributes and which are bindable

**WAF —** The extra parameters look benign to WAFs; this is an application binding-configuration issue, so allowlisting at the model layer is the control.

**Real-world:** GitHub 2012 mass-assignment (Rails, public-key injection); CVE-2021-22112 adjacent; Multiple API mass-assignment bounties (OWASP API6:2019); Uber and other privilege-escalation reports

**Tools:** burp suite, param miner, semgrep, arjun (param discovery)

**References:** [link](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html) · [link](https://owasp.org/API-Security/editions/2019/en/0xa6-mass-assignment/) · [link](https://portswigger.net/web-security/api-testing)

### Zip Slip / Archive Extraction Path Traversal
*id:* `zip-slip-path-traversal-extraction` · *category:* `path-traversal` · *severity:* **high** · *root cause:* [Confused Deputy / Trust-Boundary Violation](ROOT_CAUSES.md)

Archive entries containing ../ or absolute paths let extraction routines write files outside the intended directory, overwriting configs, web roots, or startup scripts for RCE.

**Where it breaks —** Zip/tar/rar/7z extractors that concatenate the entry name to a base directory without canonicalizing and validating the resolved path allow entries like ../../etc/cron.d/x or absolute paths (and symlink entries) to escape the target folder.

**Detection:**
- Craft archives with ../ traversal and absolute-path entries and observe write location
- Test symlink entries and Windows backslash variants
- Review extraction code for path canonicalization + prefix check before write

**WAF —** The archive is a binary blob; content WAFs don't parse entry names. Defense is code-level: resolve each entry against the base dir and reject anything escaping it, ignore absolute paths and symlinks.

**Real-world:** Snyk 'Zip Slip' disclosure (2018) affecting thousands of projects/libraries; Numerous CVEs across unarchivers and language stdlibs

**Tools:** snyk, evilarc, custom archive builders

**References:** [link](https://security.snyk.io/research/zip-slip-vulnerability) · [link](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html) · [link](https://owasp.org/www-community/attacks/Path_Traversal)

### Server-Side Prototype Pollution to RCE
*id:* `server-side-prototype-pollution-rce` · *category:* `prototype-pollution` · *severity:* **critical** · *root cause:* [Implicit Trust of Client-Controlled Input & Metadata](ROOT_CAUSES.md)

Polluting Object.prototype on a Node.js server injects properties into every object, corrupting control flow and reaching gadgets that pass attacker data into child_process/spawn options for RCE.

**Where it breaks —** Recursive merge/clone/extend, query-string parsers, and config loaders that walk attacker JSON and assign __proto__/constructor.prototype keys without filtering. Gadget chains (e.g. spawn's shell/NODE_OPTIONS/env, EJS/handlebars options) turn pollution into code execution.

**Detection:**
- Send __proto__/constructor.prototype keys and probe for a reflected polluted property (e.g. a status code or added header) via the SSPP detection technique
- Look for deep-merge libraries (lodash.merge<4.17.5, older set/defaultsDeep, hoek)
- Grep for child_process with option objects influenced by config; look for NODE_OPTIONS gadgets
- Fuzz JSON/query params with polluting keys and watch for behavior changes

**WAF —** __proto__ literals are a weak signature and easily blocked, but constructor.prototype and nested/array-notation variants, or the key arriving JSON-encoded, evade naive filters; the malicious effect is second-order so payload inspection alone misses it.

**Real-world:** PortSwigger 'Server-side prototype pollution' research (Gareth Heyes, 2022); Kibana CVE-2019-7609 (prototype pollution to RCE); Multiple lodash merge CVEs (CVE-2018-3721, CVE-2019-10744)

**Tools:** burp 'server-side prototype pollution scanner' extension, proto-pollution nodejs gadgets research, semgrep rules for merge sinks

**References:** [link](https://portswigger.net/research/server-side-prototype-pollution) · [link](https://github.com/HoLyVieR/prototype-pollution-nsec18) · [link](https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html)

### Race Conditions / TOCTOU (limit-overrun, double-spend)
*id:* `race-condition-toctou` · *category:* `race-condition` · *severity:* **high** · *root cause:* [State Desynchronization & Race Conditions](ROOT_CAUSES.md)

Concurrent requests exploit the window between a check and its use, letting attackers exceed limits, double-spend, or bypass single-use constraints.

**Where it breaks —** Non-atomic check-then-act on shared state — redeeming a one-time coupon/gift card, withdrawing funds, applying rate/quota limits, or promoting state — where reads and writes are not serialized (missing DB transactions, row locks, or idempotency keys). PortSwigger's single-packet attack made these highly reliable to trigger.

**Detection:**
- Identify check-then-act sequences on money/quota/uniqueness
- Send parallel requests (Turbo Intruder single-packet / HTTP/2) and observe overrun
- Review for DB transactions, SELECT ... FOR UPDATE, unique constraints, idempotency
- Look for time gaps between validation and mutation

**WAF —** Each request is valid, so WAFs don't detect it; velocity anomaly detection helps but correctness must come from atomic server-side state handling.

**Real-world:** PortSwigger 'Smashing the state machine' / single-packet attack research (2023); Starbucks gift-card duplication; numerous exchange/wallet double-spend and coupon-abuse bounties

**Tools:** burp suite + turbo intruder (single-packet attack), custom concurrent clients

**References:** [link](https://portswigger.net/web-security/race-conditions) · [link](https://portswigger.net/research/smashing-the-state-machine) · [link](https://owasp.org/www-community/vulnerabilities/Race_Conditions)

### Single-Packet Race Conditions / TOCTOU
*id:* `single-packet-race-toctou` · *category:* `race-condition` · *severity:* **high** · *root cause:* [State Desynchronization & Race Conditions](ROOT_CAUSES.md)

The single-packet-attack technique removes network jitter to land many requests in the same processing window, exploiting time-of-check/time-of-use gaps for limit-overrun and state races.

**Where it breaks —** Business logic checks a condition (coupon unused, balance sufficient, invite unclaimed) then acts on it non-atomically; concurrent requests all pass the check before any commits. HTTP/2's single-packet attack synchronizes ~20-30 requests server-side to defeat jitter.

**Detection:**
- Send a burst of identical requests via Turbo Intruder single-packet / gate mode and check for over-limit effects
- Look for non-transactional check-then-act flows (redeem, withdraw, apply-once, register-unique)
- Watch for duplicated side effects: multiple redemptions, negative balances, duplicate resources

**WAF —** Each individual request is legitimate; rate-limit and signature WAFs see normal traffic. Only atomicity (locks, DB constraints, idempotency keys) defends — evasion is inherent because volume, not payload, is the vector.

**Real-world:** PortSwigger 'Smashing the state machine' / single-packet attack (James Kettle, 2023); Numerous bounty reports: coupon/gift-card multi-redemption, invite-code reuse

**Tools:** turbo intruder (single-packet, race-single-packet.py), burp repeater 'send group in parallel'

**References:** [link](https://portswigger.net/research/smashing-the-state-machine) · [link](https://portswigger.net/web-security/race-conditions) · [link](https://portswigger.net/web-security/race-conditions/lab-race-conditions-limit-overrun)

### CL.0 / Client-Side Desync Request Smuggling
*id:* `cl0-client-side-desync` · *category:* `request-smuggling` · *severity:* **high** · *root cause:* [Parser Differential / Impedance Mismatch](ROOT_CAUSES.md)

Servers that ignore Content-Length on certain endpoints (CL.0) or browsers that can be coerced into desync (client-side desync) let a request body be reinterpreted as a new request, smuggling into victims.

**Where it breaks —** A front-end forwards a request whose body the back-end (or a specific vulnerable endpoint) treats as ignored, so the leftover bytes prefix the next request on the reused keep-alive connection. Client-side desync uses the victim's own browser to poison its connection to the origin.

**Detection:**
- Timing-based smuggling probes (Burp HTTP Request Smuggler) for CL.0/0.CL discrepancies per-endpoint
- Send a request with a body to endpoints that should ignore it (redirects, static, error paths) and watch for connection-level poisoning
- For client-side desync, test whether the browser reuses a poisoned connection with a follow-up navigation

**WAF —** Front-end WAFs inspect the request as a whole and miss the reparse on the back-end; discrepancies live in framing, not content. Defense is HTTP/1.1 normalization, connection non-reuse, and rejecting ambiguous framing.

**Real-world:** PortSwigger 'Browser-Powered Desync Attacks' (James Kettle, 2022) introducing CL.0 and client-side desync; Numerous CDN/load-balancer smuggling disclosures

**Tools:** burp http request smuggler, turbo intruder, h2csmuggler

**References:** [link](https://portswigger.net/research/browser-powered-desync-attacks) · [link](https://portswigger.net/web-security/request-smuggling) · [link](https://portswigger.net/web-security/request-smuggling/browser)

### HTTP/2 Downgrade Smuggling (H2.CL / H2.TE)
*id:* `h2-downgrade-smuggling` · *category:* `request-smuggling` · *severity:* **high** · *root cause:* [Parser Differential / Impedance Mismatch](ROOT_CAUSES.md)

Front-ends that downgrade HTTP/2 to HTTP/1.1 without re-deriving framing let attacker-supplied Content-Length/Transfer-Encoding or injected pseudo-header/CRLF values desync the back-end.

**Where it breaks —** HTTP/2 uses length-prefixed frames so framing is unambiguous, but many proxies rewrite requests to HTTP/1.1 for the origin and trust the H2 message's declared length or copy header values containing CRLF/colon, reintroducing classic smuggling (H2.CL, H2.TE, and header/pseudo-header splitting).

**Detection:**
- Send HTTP/2 requests with conflicting/invalid Content-Length or Transfer-Encoding and observe back-end desync
- Inject CRLF or extra fields into H2 header values / :path / :authority and check for splitting after downgrade
- Use HTTP Request Smuggler's HTTP/2 tests and response-queue probing

**WAF —** Many WAFs only fully parse HTTP/1.1 or normalize inconsistently across protocol versions; H2-native malformed inputs slip past and manifest only after downgrade. Defense: validate H2 messages, strip length headers, reject CRLF in values.

**Real-world:** PortSwigger 'HTTP/2: The Sequel is Always Worse' (James Kettle, 2021); Real disclosures against Netflix/Imperva-style stacks and multiple CDNs

**Tools:** burp http request smuggler, turbo intruder, h2csmuggler, nghttp2

**References:** [link](https://portswigger.net/research/http2) · [link](https://portswigger.net/web-security/request-smuggling/advanced) · [link](https://portswigger.net/web-security/request-smuggling/advanced/http2)

### Gopher/Dict SSRF to Internal Service RCE
*id:* `gopher-dict-ssrf-internal-rce` · *category:* `ssrf` · *severity:* **critical** · *root cause:* [Network-Position Abuse / Implicit Network Trust](ROOT_CAUSES.md)

SSRF sinks that allow gopher:// or dict:// let attackers craft raw TCP payloads to internal services (Redis, Memcached, SMTP, MySQL, FastCGI), escalating SSRF into arbitrary command execution.

**Where it breaks —** URL fetchers (often libcurl-backed) that don't restrict schemes permit gopher://, which encodes an arbitrary byte stream sent to any host:port; internal line-based protocols (Redis, FastCGI, SMTP) then execute attacker-crafted commands, turning a fetch into RCE.

**Detection:**
- Test whether SSRF sinks accept gopher://, dict://, file://, ftp:// schemes
- Probe internal ports for line-oriented services reachable from the server
- Check libcurl scheme allowlists and redirect handling

**WAF —** The outer request looks like a normal URL param; scheme-based abuse happens server-side beyond inbound inspection. Defense: scheme allowlists (http/https only), egress firewalling, authenticated internal services.

**Real-world:** Redis-via-gopher SSRF-to-RCE writeups and CTF/bounty cases; FastCGI gopher exploitation research

**Tools:** gopherus, ssrfmap, burp collaborator

**References:** [link](https://blog.chaitin.cn/gopher-attack-surfaces/) · [link](https://github.com/tarunkant/Gopherus) · [link](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)


## Rare (5)

### Connection-String / DSN Injection
*id:* `connection-string-dsn-injection` · *category:* `business-logic` · *severity:* **high** · *root cause:* [Code/Data Confusion (In-Band Control)](ROOT_CAUSES.md)

User input concatenated into a database/service connection string or DSN lets an attacker add or override parameters, redirecting connections or enabling dangerous provider features.

**Where it breaks —** Apps that build ADO.NET/JDBC/ODBC/PDO connection strings or DSNs from user-supplied host, database, or option fields without escaping the delimiter (;) allow injection of extra key=value pairs (Trusted_Connection, Data Source, LOAD DATA LOCAL, allowLoadLocalInfile, ssl-mode) that change target or behavior.

**Detection:**
- Inject ; key=value into any field that feeds a connection string (server, db name, integrated-auth toggles)
- Look for admin/multi-tenant DB configuration UIs that accept host/options
- Test provider-specific dangerous options (local-infile, extended features, alternate auth)

**WAF —** Payloads are plain key=value pairs indistinguishable from config; generic WAF rules don't model driver semantics. Defense: strict validation/allowlists per field and safe connection-builder APIs.

**Real-world:** Chris Anley / NGSSoftware 'Connection String Parameter Pollution' research; MySQL LOCAL INFILE / rogue-server credential theft incidents

**Tools:** burp suite, manual driver-parameter testing

**References:** [link](https://www.blackhat.com/presentations/bh-usa-08/Anley/BH_US_08_Anley_Advanced_SQL_Injection.pdf) · [link](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html) · [link](https://portswigger.net/kb/issues/00100200_sql-injection)

### SSI / ESI Injection
*id:* `ssi-esi-injection` · *category:* `header-injection` · *severity:* **high** · *root cause:* [Code/Data Confusion (In-Band Control)](ROOT_CAUSES.md)

Server-Side Includes and Edge-Side Includes directives injected into content processed by web servers or caching proxies enable file read, SSRF, command execution, or cache abuse.

**Where it breaks —** Web servers with SSI enabled parse <!--#exec/#include--> in served files, and CDN/proxy layers (Varnish, Akamai, Squid) that process ESI parse <esi:include>/<esi:vars> in upstream responses; if attacker input reaches such content it's executed as a directive.

**Detection:**
- Inject SSI (<!--#echo/#exec/#include-->) into stored/reflected content and check for execution
- Inject ESI (<esi:include src=...>) and observe whether the proxy fetches attacker URLs (SSRF) or reflects vars
- Fingerprint ESI support via <esi:vars> and surrogate headers

**WAF —** ESI/SSI tags look like harmless markup and are often processed after the WAF by the caching layer; downstream parsing defeats inbound inspection. Defense: disable SSI/ESI where unneeded, escape angle brackets, restrict ESI to trusted origins.

**Real-world:** GoSecure 'Beyond XSS: Edge Side Include Injection' research (2018); Classic Apache SSI #exec RCE cases

**Tools:** burp suite, manual directive probes

**References:** [link](https://www.gosecure.net/blog/2018/04/03/beyond-xss-edge-side-include-injection/) · [link](https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection) · [link](https://portswigger.net/kb/issues/00100b00_server-side-include-injection)

### HTTP Response Splitting / Range Abuse
*id:* `crlf-response-splitting-range` · *category:* `header-injection` · *severity:* **medium** · *root cause:* [Code/Data Confusion (In-Band Control)](ROOT_CAUSES.md)

CRLF injected into response headers splits one response into two (cache poisoning, XSS, redirect), while malformed Range requests can cause DoS or info leaks.

**Where it breaks —** Apps that reflect user input into response headers (Location, Set-Cookie, custom) without stripping CR/LF let attackers terminate the header block early and inject a second crafted response; separately, servers mishandling Range/If-Range can over-allocate memory or leak/duplicate content.

**Detection:**
- Inject %0d%0a into inputs reflected in headers (redirect URLs, cookie values) and check for header/body splitting
- Test large/overlapping/multiple Range headers for memory blowup or abnormal 206 responses
- Review header-writing code for newline sanitization

**WAF —** Encoded newlines can slip past filters and modern servers block many raw variants; Range abuse uses valid-looking headers. Defense: reject CR/LF in header values, cap/validate Range, patch server stacks.

**Real-world:** Classic HTTP response-splitting CVEs across app servers; CVE-2011-3192 Apache 'Killer' Range-header DoS

**Tools:** burp suite, custom crlf/range fuzzers

**References:** [link](https://owasp.org/www-community/attacks/HTTP_Response_Splitting) · [link](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html) · [link](https://nvd.nist.gov/vuln/detail/CVE-2011-3192)

### SAML Signature Wrapping (XSW)
*id:* `saml-signature-wrapping-xsw` · *category:* `oauth-saml` · *severity:* **critical** · *root cause:* [Parser Differential / Impedance Mismatch](ROOT_CAUSES.md)

XML Signature Wrapping exploits the gap between the signed element a validator checks and the assertion the application actually consumes, forging authenticated identities.

**Where it breaks —** SAML responses are XML with a detached signature referencing an element by ID; if signature validation and business logic resolve different elements (due to XPath/ID handling, multiple assertions, or moved signatures), an attacker wraps a valid signed blob around a forged assertion the app trusts.

**Detection:**
- Insert a second (forged) assertion and relocate/duplicate the Signature element; check if login succeeds
- Test whether the SP validates the signature over the exact assertion it consumes (ID references, first-vs-last element)
- Fuzz XML structure: extra Assertion, Object wrappers, comment truncation in NameID

**WAF —** WAFs can't validate XML signature/reference binding; the SAML blob is base64 and structurally valid. Defense is library-level: schema-hardening, single-assertion enforcement, validating signature over the consumed element.

**Real-world:** Duo Labs 'The road to hell is paved with SAML assertions' (2017) — comment-truncation auth bypass across many SPs; CVE-2017-11427 (python-saml), CVE-2018-0489 (Shibboleth), original XSW research by Somorovsky et al.

**Tools:** saml raider (burp), samltool, custom xml editors

**References:** [link](https://web-in-security.blogspot.com/2014/11/detecting-and-exploiting-xml-signature.html) · [link](https://duo.com/blog/duo-finds-saml-vulnerabilities-affecting-multiple-implementations) · [link](https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91.pdf)

### XPath / XQuery Injection
*id:* `xpath-injection` · *category:* `xpath` · *severity:* **high** · *root cause:* [Code/Data Confusion (In-Band Control)](ROOT_CAUSES.md)

Unescaped input in XPath queries over XML data stores lets attackers alter node selection to bypass auth or blind-extract the entire document.

**Where it breaks —** Apps querying XML (auth files, config, XML DBs) build XPath expressions by concatenating user input without quoting, so ' or '1'='1 style injections and boolean/position predicates change which nodes are returned.

**Detection:**
- Inject XPath metacharacters (', or, and, position()) into fields backed by XML and observe auth bypass or differing results
- Use boolean/blind oracles (substring(), string-length()) to traverse the document
- Identify XML-backed queries with no parameterization

**WAF —** XPath syntax resembles generic quotes/keywords; blind extraction sends innocuous-looking predicates. Defense: parameterized XPath (variable binding) and strict input escaping.

**Real-world:** OWASP XPath injection testing guide examples; Assorted XML-auth bypass disclosures

**Tools:** burp suite, xcat (blind xpath extraction)

**References:** [link](https://owasp.org/www-community/attacks/XPATH_Injection) · [link](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html) · [link](https://github.com/orf/xcat)


## Tooling

| Tool | Category | Targets | Link |
| --- | --- | --- | --- |
| **marshalsec** | deserialization | Java deser across JSON/YAML/XML (Jackson, Fastjson, SnakeYAM | [github.com/mbechler/marshalsec](https://github.com/mbechler/marshalsec) |
| **ysoserial** | deserialization | Java insecure deserialization (gadget-chain RCE) | [github.com/frohoff/ysoserial](https://github.com/frohoff/ysoserial) |
| **ysoserial.net** | deserialization | .NET insecure deserialization (BinaryFormatter, Json.NET Typ | [github.com/pwntester/ysoserial.n](https://github.com/pwntester/ysoserial.net) |
| **feroxbuster** | fuzzing | Recursive content discovery (directories/files) | [github.com/epi052/feroxbuster](https://github.com/epi052/feroxbuster) |
| **ffuf** | fuzzing | Content/endpoint discovery, virtual-host fuzzing, parameter/ | [github.com/ffuf/ffuf](https://github.com/ffuf/ffuf) |
| **kiterunner** | fuzzing | API/route discovery for modern REST/GraphQL apps and API gat | [github.com/assetnote/kiterunner](https://github.com/assetnote/kiterunner) |
| **smuggler.py / http-request-smuggler** | fuzzing | HTTP request smuggling / desync (CL.TE, TE.CL, TE.TE, CL.0,  | [github.com/PortSwigger/http-requ](https://github.com/PortSwigger/http-request-smuggler) |
| **Turbo Intruder** | fuzzing | Race conditions (single-packet attack), high-rate fuzzing, t | [github.com/PortSwigger/turbo-int](https://github.com/PortSwigger/turbo-intruder) |
| **Commix** | injection | OS command injection (results-based, blind, time-based, file | [github.com/commixproject/commix](https://github.com/commixproject/commix) |
| **NoSQLMap** | injection | NoSQL injection (MongoDB and similar), Mongo/Node misconfig  | [github.com/codingo/NoSQLMap](https://github.com/codingo/NoSQLMap) |
| **jwt_tool / jwt-cracker** | jwt | JWT flaws: alg:none, RS256->HS256 key confusion, weak HMAC s | [github.com/ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool) |
| **interactsh / Burp Collaborator** | oast | Out-of-band testing: blind SSRF, blind XXE, blind injection/ | [github.com/projectdiscovery/inte](https://github.com/projectdiscovery/interactsh) |
| **Arjun / ParamSpider / x8** | param-discovery | Hidden GET/POST/JSON parameters and historical parameter sur | [github.com/s0md3v/Arjun](https://github.com/s0md3v/Arjun) |
| **Param Miner** | param-discovery | Hidden request parameters/headers/cookies; web cache poisoni | [github.com/PortSwigger/param-min](https://github.com/PortSwigger/param-miner) |
| **Burp Suite** | proxy | General web application testing platform (proxy, scanner, In | [portswigger.net/burp](https://portswigger.net/burp) |
| **mitmproxy** | proxy | Interactive TLS-capable HTTP(S) interception, scripting, tra | [github.com/mitmproxy/mitmproxy](https://github.com/mitmproxy/mitmproxy) |
| **GraphQLmap / clairvoyance / InQL** | recon | GraphQL: schema/introspection recovery, field/injection test | [github.com/nikitastupin/clairvoy](https://github.com/nikitastupin/clairvoyance) |
| **PayloadsAllTheThings / HackTricks / PortSwigger Web Security Academy / SecLists** | reference-db | Cross-cutting reference: payload patterns, methodology, root | [github.com/swisskyrepo/PayloadsA](https://github.com/swisskyrepo/PayloadsAllTheThings) |
| **Corsy** | scanner | CORS misconfigurations (reflected origin, null origin, wildc | [github.com/s0md3v/Corsy](https://github.com/s0md3v/Corsy) |
| **Dalfox** | scanner | Cross-Site Scripting (reflected/stored/DOM), parameter analy | [github.com/hahwul/dalfox](https://github.com/hahwul/dalfox) |
| **Nuclei** | scanner | Known CVEs, misconfigurations, exposures, default creds, tak | [github.com/projectdiscovery/nucl](https://github.com/projectdiscovery/nuclei) |
| **Ghauri** | sqli | SQL injection (boolean/time/error/UNION), incl. some WAF/CSR | [github.com/r0oth3x49/ghauri](https://github.com/r0oth3x49/ghauri) |
| **sqlmap** | sqli | SQL injection (MySQL, PostgreSQL, MSSQL, Oracle, SQLite, etc | [github.com/sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap) |
| **Gopherus** | ssrf | SSRF-to-RCE/data theft against internal services via gopher: | [github.com/tarunkant/Gopherus](https://github.com/tarunkant/Gopherus) |
| **tplmap / SSTImap** | ssti | Server-Side Template Injection (Jinja2, Twig, Freemarker, Ve | [github.com/vladko312/SSTImap](https://github.com/vladko312/SSTImap) |
| **nowafpls** | waf | WAF request-size/inspection-limit blind spots (conceptual ev | [github.com/assetnote/nowafpls](https://github.com/assetnote/nowafpls) |
| **CloudFail / bypass-firewalls-by-DNS-history** | waf | Uncovering the real origin IP behind a WAF/CDN so the proxy  | [github.com/vincentcox/bypass-fir](https://github.com/vincentcox/bypass-firewalls-by-DNS-history) |
| **wafw00f** | waf | WAF/WAAP fingerprinting (identifies which WAF/CDN fronts a s | [github.com/EnableSecurity/wafw00](https://github.com/EnableSecurity/wafw00f) |
| **XXEinjector / oxml_xxe** | xxe | XML External Entity injection: file disclosure, SSRF, OOB ex | [github.com/enjoiz/XXEinjector](https://github.com/enjoiz/XXEinjector) |

