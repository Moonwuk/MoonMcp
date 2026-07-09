"""Server-side vulnerability catalog + root-cause taxonomy — structured data.

A REFERENCED catalog for authorised security research: popular *and* obscure
server-side vulnerability classes, each mapped to the ROOT CAUSE it derives from
and the concrete point where real apps get it wrong (``where_it_breaks``), plus
detection guidance, notable real-world incidents and the tooling used to find it.
The ROOT_CAUSES taxonomy is the intellectual centrepiece — the ~13 fundamental
causes from which nearly all of these vulnerabilities spring. Conceptual only:
descriptions and public links, NO weaponized exploit code.

Compiled from OWASP (WSTG, Top 10, Cheat Sheets), PortSwigger Research & the Web
Security Academy, PayloadsAllTheThings, HackTricks, MITRE CWE and public CVE/incident write-ups.
"""

from __future__ import annotations

SERVER_SIDE_VULNS: list[dict] = [   {   'id': 'broken-access-control-idor-bola',
        'name': 'Broken Access Control / IDOR / BOLA',
        'category': 'access-control',
        'severity': 'high',
        'popularity': 'common',
        'summary': 'The application fails to enforce that the authenticated user is authorized for '
                   "the specific object or action, letting users read/modify other users' data or "
                   'reach privileged functions.',
        'root_cause': 'broken-authorization',
        'where_it_breaks': 'Endpoints that trust a client-supplied object identifier (IDOR/BOLA) '
                           'without an ownership/tenant check, missing function-level checks on '
                           'admin routes, relying on hidden UI or unguessable IDs (security by '
                           'obscurity), and horizontal/vertical privilege gaps in multi-tenant '
                           'APIs. The #1 API risk per OWASP API Top 10.',
        'detection': [   'Enumerate object IDs across two accounts and diff access',
                         'Map every endpoint to required role/ownership and test negative cases',
                         'Automated authz differential testing (Autorize/AuthMatrix)',
                         'Review for per-object checks vs per-endpoint-only checks'],
        'exploitation_notes': 'Increment/replace identifiers (numeric, UUID, GUID, encoded) to '
                              "access other tenants' resources; call privileged actions directly; "
                              'abuse mass endpoints (export, admin) lacking function-level authz. '
                              'Fix: enforce authorization server-side on every request against the '
                              'authenticated principal and the specific resource, ideally with a '
                              'centralized policy layer and deny-by-default.',
        'waf_notes': 'Effectively undetectable by generic WAFs because requests are well-formed '
                     'and authenticated; defense requires application-layer policy enforcement and '
                     'per-tenant anomaly monitoring.',
        'real_world': [   'Facebook/Instagram, Uber, and many bug-bounty BOLA reports',
                          'CVE-2021-22986 adjacent',
                          'USPS Informed Visibility IDOR (60M users, 2018)',
                          'T-Mobile API BOLA incidents',
                          'Optus 2022 breach (unauthenticated API)'],
        'tools': ['burp suite + autorize/authmatrix', 'custom fuzzers', 'postman', 'nuclei'],
        'references': [   'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
                          'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/',
                          'https://portswigger.net/web-security/access-control/idor',
                          'https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html']},
    {   'id': 'cors-misconfiguration',
        'name': 'CORS Misconfiguration',
        'category': 'access-control',
        'severity': 'medium',
        'popularity': 'common',
        'summary': 'Overly permissive Cross-Origin Resource Sharing lets malicious origins read '
                   'authenticated cross-origin responses, exposing user data.',
        'root_cause': 'insecure-defaults-misconfiguration',
        'where_it_breaks': 'Reflecting the request Origin into Access-Control-Allow-Origin while '
                           'also sending Access-Control-Allow-Credentials: true, weak Origin '
                           'allowlists (substring/suffix/prefix matching, null origin trusted, '
                           'http allowed), and wildcarding sensitive APIs — turning any attacker '
                           "page into an authenticated reader of the victim's data.",
        'detection': [   'Send varied Origin headers and inspect ACAO/ACAC reflection',
                         'Test null origin (sandboxed iframe), subdomain and suffix bypasses',
                         'Grep CORS middleware config for Origin reflection and credentials true',
                         'Automated CORS scanners'],
        'exploitation_notes': 'If ACAO reflects arbitrary origins with credentials allowed, an '
                              "attacker's site can issue credentialed cross-origin requests and "
                              'read the responses (tokens, PII, CSRF secrets). null-origin trust '
                              'and flawed regex/substring matching are common bypasses. Fix: '
                              'strict exact-match allowlist, never reflect arbitrary origins with '
                              'credentials, avoid trusting null, and scope per-endpoint.',
        'waf_notes': "Not a payload class — WAFs don't help; the misconfiguration is in response "
                     'headers, so review and test the CORS policy directly.',
        'real_world': [   'Numerous bug-bounty CORS data-exfiltration reports',
                          "James Kettle 'Exploiting CORS Misconfigurations' research",
                          'Multiple SaaS API credentialed-CORS disclosures'],
        'tools': ['burp suite', 'corscanner', 'corsy', 'nuclei'],
        'references': [   'https://portswigger.net/web-security/cors',
                          'https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#cross-origin-resource-sharing',
                          'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS']},
    {   'id': 'authentication-bypass',
        'name': 'Authentication Bypass',
        'category': 'auth-bypass',
        'severity': 'critical',
        'popularity': 'common',
        'summary': 'Flaws in login, session, or credential-verification logic let an attacker '
                   'authenticate as another user or skip authentication entirely.',
        'root_cause': 'broken-authorization',
        'where_it_breaks': 'Logic errors in auth flows — verification that returns early or trusts '
                           'client-supplied identity, insecure password-reset tokens, response '
                           'manipulation on multi-step login/2FA, default/hardcoded credentials, '
                           'type-juggling in comparisons, SQLi in the login query, and forgotten '
                           'pre-auth admin endpoints or debug backdoors.',
        'detection': [   "Review auth state machine and each step's server-side enforcement",
                         'Test forced browsing to post-auth endpoints',
                         'Check password-reset token entropy/expiry/binding',
                         'Look for loose comparisons and default creds',
                         'Fuzz 2FA/OTP for rate limits and response tampering'],
        'exploitation_notes': 'Common patterns: manipulating a step response to mark login '
                              'complete, reusing/predicting reset tokens, magic values, or '
                              'reaching functionality before the auth check runs. Type-juggling '
                              'and non-constant-time comparisons weaken credential checks. Fix: '
                              'centralize auth, verify server-side at every step, use strong '
                              'random tokens bound to user+expiry, and constant-time secret '
                              'comparison.',
        'waf_notes': 'Largely invisible to WAFs since requests look legitimate; detection depends '
                     'on anomaly monitoring (impossible travel, credential stuffing volume, '
                     'reset-token abuse) rather than signatures.',
        'real_world': [   'CVE-2022-40684 (Fortinet auth bypass)',
                          'CVE-2023-46805 / CVE-2024-21887 (Ivanti auth bypass chain)',
                          'CVE-2021-44529 adjacent',
                          'CVE-2020-1938 (Ghostcat) adjacent',
                          'CVE-2018-13379 (Fortinet)'],
        'tools': ['burp suite', 'hydra (rate-limit testing)', 'custom scripts', 'nuclei templates'],
        'references': [   'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
                          'https://portswigger.net/web-security/authentication',
                          'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html']},
    {   'id': 'argument-parameter-injection',
        'name': 'Argument / Parameter Injection',
        'category': 'business-logic',
        'severity': 'high',
        'popularity': 'uncommon',
        'summary': 'Passing user input as arguments to CLI tools or system utilities lets '
                   'attackers inject extra flags/options that change behavior (file write, config '
                   'override) even without a shell metacharacter.',
        'root_cause': 'code-data-confusion',
        'where_it_breaks': 'Apps that invoke binaries (git, curl, tar, ffmpeg, gpg, find, '
                           'ImageMagick) with user input as an argument — even via safe argv (no '
                           "shell) — don't separate options from operands, so input starting with "
                           '- is parsed as a flag, enabling dangerous options.',
        'detection': [   'Supply inputs beginning with - or -- (e.g. --output, --upload-pack, -o) '
                         'where a filename/value is expected',
                         'Check whether the app inserts a -- end-of-options separator',
                         "Enumerate the target binary's dangerous flags reachable via the injected "
                         'position'],
        'exploitation_notes': 'Conceptually: because argument parsing treats leading dashes as '
                              "options, an attacker-controlled 'filename' like --upload-pack=... "
                              '(git) or -o /path (curl) redirects behavior to write files, '
                              'exfiltrate, or execute helpers — all without a shell or '
                              'metacharacters. Distinct from classic command injection.',
        'waf_notes': 'No shell metacharacters means metachar-focused WAF rules miss it; the '
                     'payload is a plain hyphenated token. Defense: -- separators, strict value '
                     'validation, and allowlisted arguments.',
        'real_world': [   "git '--upload-pack'/'--output' argument-injection CVEs",
                          'curl -o/-K and ImageMagick option-injection cases documented by '
                          'Semgrep/PortSwigger'],
        'tools': ['burp suite', 'semgrep (argument-injection rules)', 'manual binary flag review'],
        'references': [   'https://sonarsource.github.io/argument-injection-vectors/',
                          'https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html',
                          'https://owasp.org/www-community/attacks/Command_Injection']},
    {   'id': 'business-logic-abuse',
        'name': 'Business Logic Flaws / Mass Abuse',
        'category': 'business-logic',
        'severity': 'high',
        'popularity': 'common',
        'summary': 'The application enforces individual technical controls but not the intended '
                   'business rules, letting attackers abuse legitimate functionality (pricing, '
                   'quotas, workflows, discounts) for unintended gain.',
        'root_cause': 'broken-authorization',
        'where_it_breaks': 'Implicit assumptions the code never verifies — negative/overflow '
                           'quantities, applying discounts/coupons repeatedly, skipping workflow '
                           'steps, manipulating price or currency client-side, exceeding limits '
                           'due to missing atomicity, and trusting client-side validation. '
                           'Overlaps race conditions (limit-overrun via concurrency) and '
                           'mass-assignment.',
        'detection': [   'Model the intended workflow and test every out-of-order / boundary / '
                         'negative path',
                         'Look for trust in client-supplied prices/quantities/state',
                         'Concurrency testing for limit overruns',
                         'Manual review — automated scanners rarely find these'],
        'exploitation_notes': 'Exploits are context-specific: bypassing multi-step enforcement, '
                              'replaying single-use actions, forcing negative totals, or racing to '
                              'redeem a one-time benefit multiple times. Fix: enforce invariants '
                              'server-side, make critical operations atomic/idempotent, and '
                              'validate the whole workflow state, not just individual requests.',
        'waf_notes': 'Invisible to WAFs — every request is individually valid; detection relies on '
                     'business-level anomaly monitoring (velocity, value thresholds, refund/coupon '
                     'abuse analytics).',
        'real_world': [   'Countless bounty reports (coupon stacking, price manipulation, '
                          'gift-card abuse)',
                          'Starbucks race-condition gift-card balance duplication',
                          'Airline/ecommerce currency and quantity abuse cases'],
        'tools': [   'burp suite + turbo intruder (race conditions)',
                     'custom scripts',
                     'manual testing'],
        'references': [   'https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability',
                          'https://portswigger.net/web-security/logic-flaws',
                          'https://portswigger.net/web-security/race-conditions']},
    {   'id': 'connection-string-dsn-injection',
        'name': 'Connection-String / DSN Injection',
        'category': 'business-logic',
        'severity': 'high',
        'popularity': 'rare',
        'summary': 'User input concatenated into a database/service connection string or DSN lets '
                   'an attacker add or override parameters, redirecting connections or enabling '
                   'dangerous provider features.',
        'root_cause': 'code-data-confusion',
        'where_it_breaks': 'Apps that build ADO.NET/JDBC/ODBC/PDO connection strings or DSNs from '
                           'user-supplied host, database, or option fields without escaping the '
                           'delimiter (;) allow injection of extra key=value pairs '
                           '(Trusted_Connection, Data Source, LOAD DATA LOCAL, '
                           'allowLoadLocalInfile, ssl-mode) that change target or behavior.',
        'detection': [   'Inject ; key=value into any field that feeds a connection string '
                         '(server, db name, integrated-auth toggles)',
                         'Look for admin/multi-tenant DB configuration UIs that accept '
                         'host/options',
                         'Test provider-specific dangerous options (local-infile, extended '
                         'features, alternate auth)'],
        'exploitation_notes': 'Conceptually: append a semicolon and override Data Source to your '
                              'own server (credential capture) or enable client-side '
                              'file-read/local-infile features, or force integrated auth to leak '
                              "NTLM. Effect depends on the driver's parameter precedence "
                              '(last-wins vs first-wins).',
        'waf_notes': 'Payloads are plain key=value pairs indistinguishable from config; generic '
                     "WAF rules don't model driver semantics. Defense: strict "
                     'validation/allowlists per field and safe connection-builder APIs.',
        'real_world': [   "Chris Anley / NGSSoftware 'Connection String Parameter Pollution' "
                          'research',
                          'MySQL LOCAL INFILE / rogue-server credential theft incidents'],
        'tools': ['burp suite', 'manual driver-parameter testing'],
        'references': [   'https://www.blackhat.com/presentations/bh-usa-08/Anley/BH_US_08_Anley_Advanced_SQL_Injection.pdf',
                          'https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html',
                          'https://portswigger.net/kb/issues/00100200_sql-injection']},
    {   'id': 'http2-rapid-reset',
        'name': 'HTTP/2 Rapid Reset',
        'category': 'business-logic',
        'severity': 'high',
        'popularity': 'uncommon',
        'summary': 'Rapidly opening and immediately cancelling (RST_STREAM) HTTP/2 streams forces '
                   'the server to do request work without hitting concurrency limits, enabling '
                   'record-breaking DoS.',
        'root_cause': 'state-desync-race',
        'where_it_breaks': 'HTTP/2 lets a client open a stream and instantly reset it; many '
                           'servers begin processing (and allocate resources for) the request '
                           "before the cancel and don't count reset streams against "
                           'MAX_CONCURRENT_STREAMS, so a client can create unbounded in-flight '
                           'work over one connection.',
        'detection': [   'Monitor for high volumes of quickly-reset streams / abnormal RST_STREAM '
                         'rates',
                         'Check server versions against CVE-2023-44487 patches and mitigation '
                         'configs',
                         'Load-test with rapid open+reset patterns in a controlled environment'],
        'exploitation_notes': 'Conceptually: repeatedly send HEADERS then immediate RST_STREAM so '
                              'the server keeps starting work while the client stays under stream '
                              'limits, amplifying resource consumption far beyond normal request '
                              'rates and exhausting CPU/memory. Purely availability impact.',
        'waf_notes': 'Traffic is protocol-valid HTTP/2 frames, not malicious payloads; L7 '
                     'signature WAFs miss it. Defense: cap total/reset streams per connection, '
                     'patch server stacks, rate-limit resets.',
        'real_world': [   "CVE-2023-44487 'HTTP/2 Rapid Reset' — largest-ever DDoS disclosed by "
                          'Google/Cloudflare/AWS (Oct 2023)'],
        'tools': ['controlled load generators', 'nghttp2', 'server telemetry'],
        'references': [   'https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/',
                          'https://cloud.google.com/blog/products/identity-security/how-it-works-the-novel-http2-rapid-reset-ddos-attack',
                          'https://nvd.nist.gov/vuln/detail/CVE-2023-44487']},
    {   'id': 'orm-injection',
        'name': 'ORM Injection / ORM Leak',
        'category': 'business-logic',
        'severity': 'high',
        'popularity': 'uncommon',
        'summary': 'Passing attacker-controlled structures into ORM query builders (operators, '
                   'relations, field selectors) lets attackers craft unintended queries, bypass '
                   'filters, or exfiltrate data via relational operators.',
        'root_cause': 'code-data-confusion',
        'where_it_breaks': 'ORMs (Sequelize, TypeORM, Prisma, Django ORM, Hibernate HQL, '
                           'ActiveRecord) that accept nested objects or raw fragments from request '
                           'bodies let clients inject operators ($gt, OR, LIKE, relation '
                           'traversal) or HQL/JPQL strings, turning a filter into an arbitrary '
                           'predicate or exposing related tables.',
        'detection': [   'Send operator objects (e.g. {"password":{"$ne":null}} style or Sequelize '
                         '[Op] equivalents) where a scalar is expected',
                         'Test relation/field selectors for traversal to sibling tenants or '
                         'sensitive columns',
                         'Look for raw()/HQL string concatenation and where-clause passthrough',
                         'Boolean/inference oracles via ORM-leak (character-by-character via '
                         'relation filters)'],
        'exploitation_notes': 'Conceptually: supply a structured filter that the ORM compiles into '
                              'an over-broad query (bypassing auth checks) or a boolean oracle '
                              'enabling blind extraction of adjacent records; HQL/JPQL injection '
                              'can reach arbitrary entity fields. Related to but broader than '
                              'SQLi.',
        'waf_notes': "Structured JSON operators don't match SQLi signatures; the injection is at "
                     'the ORM DSL layer. Defense: strict input schemas, explicit field allowlists, '
                     'parameterized raw queries.',
        'real_world': [   'Alvaro Muñoz / others on Hibernate HQL injection',
                          "'ORM Leak' research on relational-operator data exfiltration (2023)",
                          'Sequelize operator-injection advisories'],
        'tools': ['burp suite', 'custom operator fuzzers', 'semgrep orm rules'],
        'references': [   'https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html',
                          'https://www.elttam.com/blog/plormbing-your-django-orm/',
                          'https://owasp.org/www-community/attacks/SQL_Injection']},
    {   'id': 'second-order-injection',
        'name': 'Second-Order (Stored) Injection',
        'category': 'business-logic',
        'severity': 'high',
        'popularity': 'uncommon',
        'summary': 'Input stored safely in one context is later used unsafely in another (SQL, '
                   'command, template, LDAP), so the injection fires on a subsequent operation '
                   'that skips validation.',
        'root_cause': 'confused-deputy-trust-boundary',
        'where_it_breaks': 'Data validated/escaped at the entry point is trusted when re-read from '
                           'the database or another store and concatenated into a '
                           'query/command/template elsewhere (batch jobs, admin views, reporting), '
                           'because developers assume stored data is safe.',
        'detection': [   'Seed fields with injection markers, then exercise every downstream '
                         'feature that reads them (profile display, reports, admin panels, '
                         'background jobs)',
                         'Trace data flow from storage to sinks rather than only testing the input '
                         'endpoint',
                         'Look for reuse of stored usernames/filenames/values in dynamic queries'],
        'exploitation_notes': 'Conceptually: register a username or value containing a '
                              'SQL/command/template payload that is inert on write but is '
                              'concatenated into a query when an admin views it or a cron '
                              'processes it, executing then. The delay and different endpoint '
                              'defeat point-of-entry defenses.',
        'waf_notes': 'The malicious request that plants the payload may look benign or be '
                     'normalized on entry; the sink fires internally with no HTTP request to '
                     'inspect. Defense: parameterize/escape at every sink, treat stored data as '
                     'untrusted.',
        'real_world': [   'Classic second-order SQLi in password-reset/username flows',
                          'OWASP and PortSwigger documented stored-then-executed cases'],
        'tools': ['burp suite', 'sqlmap (--second-order)', 'manual data-flow tracing'],
        'references': [   'https://portswigger.net/web-security/sql-injection',
                          'https://owasp.org/www-community/attacks/SQL_Injection',
                          'https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html']},
    {   'id': 'websocket-cross-site-hijacking',
        'name': 'Cross-Site WebSocket Hijacking (CSWSH)',
        'category': 'business-logic',
        'severity': 'high',
        'popularity': 'uncommon',
        'summary': 'WebSocket handshakes authenticated solely by cookies and lacking Origin '
                   "validation let a malicious page open a cross-site socket in the victim's "
                   'context and read/send messages.',
        'root_cause': 'broken-authorization',
        'where_it_breaks': 'The WebSocket upgrade is a normal HTTP request that carries cookies '
                           'but is not protected by CORS or CSRF tokens; if the server '
                           "authenticates via ambient cookies and doesn't check the Origin header, "
                           'any origin can establish an authenticated socket.',
        'detection': [   'Check whether the WS handshake validates Origin and uses a CSRF '
                         'token/non-cookie auth',
                         'From a test page on another origin, attempt to open the socket with the '
                         "victim's cookies and exchange messages",
                         'Inspect handshake for Sec-WebSocket-* only vs. real authz'],
        'exploitation_notes': 'Conceptually: a victim visiting attacker.com triggers a '
                              'cross-origin WebSocket to the target; because cookies ride along '
                              "and Origin isn't enforced, the attacker's JS reads private messages "
                              'or issues privileged actions over the socket, like a CSRF that also '
                              'exfiltrates data.',
        'waf_notes': 'The handshake looks like a legitimate upgrade; WAFs rarely enforce Origin on '
                     'WS. Defense: validate Origin, require a CSRF token or non-cookie auth on the '
                     'handshake.',
        'real_world': [   'PortSwigger CSWSH labs and research',
                          'Assorted chat/notification WebSocket hijacking bounty reports'],
        'tools': ['burp suite (websocket tools)', 'custom test pages'],
        'references': [   'https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking',
                          'https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html',
                          'https://christian-schneider.net/CrossSiteWebSocketHijacking.html']},
    {   'id': 'web-cache-deception',
        'name': 'Web Cache Deception',
        'category': 'cache-poisoning',
        'severity': 'high',
        'popularity': 'uncommon',
        'summary': "Tricking a cache into storing a victim's authenticated dynamic response under "
                   'a static-looking URL, then retrieving it to leak private data.',
        'root_cause': 'parser-differential',
        'where_it_breaks': 'The cache and origin disagree about whether a URL is static: origin '
                           'routes /account/profile.css to the profile page (ignoring the '
                           'extension), while the CDN caches by extension and stores the '
                           'personalized response as if it were a public .css file.',
        'detection': [   'Append static-looking suffixes/path segments (/nonexistent.css, ;.js, '
                         '%2f..) to authenticated pages and check for caching',
                         'Compare origin routing vs. cache extension parsing for path-confusion '
                         '(delimiter, encoded slash, path parameter)',
                         'Inspect cache-status headers after requesting the crafted URL from a '
                         'second session'],
        'exploitation_notes': 'Conceptually: lure a victim to a URL that looks static to the CDN '
                              'but resolves to their private page at origin; the personalized '
                              'response gets cached publicly and the attacker fetches it. Path '
                              'delimiters and normalization differences broaden the technique.',
        'waf_notes': "Not a payload attack — nothing malicious in bytes; WAFs don't model "
                     'cache/origin path-parsing differentials. Mitigation is cache-rule and '
                     'normalization alignment, not filtering.',
        'real_world': [   "Omer Gil original 'Web Cache Deception' (2017), PayPal case",
                          "PortSwigger 2024 'Gotta cache 'em all' delimiter/normalization research "
                          '(Martin Doyhenard)'],
        'tools': ['burp suite', 'cache-status inspection', 'custom path fuzzers'],
        'references': [   'https://portswigger.net/web-security/web-cache-deception',
                          'https://portswigger.net/research/gotta-cache-em-all',
                          'https://omergil.blogspot.com/2017/02/web-cache-deception-attack.html']},
    {   'id': 'web-cache-poisoning',
        'name': 'Web Cache Poisoning',
        'category': 'cache-poisoning',
        'severity': 'high',
        'popularity': 'uncommon',
        'summary': "Unkeyed inputs (headers, cookies, params) that influence a response but aren't "
                   'part of the cache key let an attacker store a malicious response served to all '
                   'users.',
        'root_cause': 'state-desync-race',
        'where_it_breaks': 'CDNs/reverse proxies cache by a subset of the request (the cache key) '
                           'while the origin reflects unkeyed inputs (X-Forwarded-Host, '
                           'X-Forwarded-Scheme, custom headers, fat GET params) into responses; '
                           'the poisoned response is then replayed to victims.',
        'detection': [   'Identify cache hits/misses via Age, X-Cache, CF-Cache-Status headers',
                         "Probe unkeyed headers with a canary value and check if it's reflected "
                         'AND cached',
                         'Use Param Miner to discover unkeyed inputs/secret headers',
                         'Test cache-key normalization (case, ports, encoded chars) for '
                         'keyed/unkeyed discrepancies'],
        'exploitation_notes': 'Conceptually: send a request with an unkeyed header that makes the '
                              'origin reflect an attacker-controlled resource (script src, '
                              'redirect Host) into a cacheable response; subsequent victims on the '
                              'same key receive stored XSS/redirect. Cache-key flaws also enable '
                              'DoS (poison with 400/oversized).',
        'waf_notes': 'WAFs rarely inspect the interaction between cache key and reflected input; '
                     'benign-looking headers pass through, and the harm manifests only after '
                     'caching. Defense requires cache-key hygiene, not signatures.',
        'real_world': [   "PortSwigger 'Practical Web Cache Poisoning' and 'Web Cache "
                          "Entanglement' (James Kettle)",
                          'Multiple bug bounty reports poisoning JS/redirects on major CDNs'],
        'tools': ['burp param miner', 'burp suite', 'custom header fuzzers'],
        'references': [   'https://portswigger.net/research/practical-web-cache-poisoning',
                          'https://portswigger.net/research/web-cache-entanglement',
                          'https://portswigger.net/web-security/web-cache-poisoning']},
    {   'id': 'insecure-deserialization',
        'name': 'Insecure Deserialization (Java/PHP/.NET/Python/Ruby/Node)',
        'category': 'deserialization',
        'severity': 'critical',
        'popularity': 'common',
        'summary': 'Untrusted serialized objects are deserialized into live objects, invoking '
                   'magic/callback methods that gadget chains abuse to achieve RCE or other '
                   'impact.',
        'root_cause': 'insecure-deserialization',
        'where_it_breaks': 'Deserializing attacker-controlled bytes with native/polymorphic '
                           'deserializers — Java ObjectInputStream/JNDI, PHP unserialize() and '
                           'phar://, .NET BinaryFormatter/LosFormatter/Json.NET TypeNameHandling, '
                           'Python pickle/yaml.load, Ruby Marshal/YAML, Node with libraries that '
                           'revive functions — typically fed from cookies, view state, caches, '
                           'message queues, or upload parsing.',
        'detection': [   'Identify serialized markers (rO0 base64 for Java, O:/a: for PHP, '
                         'ViewState, AAEAAAD for .NET BinaryFormatter)',
                         'Grep for dangerous sinks (readObject, unserialize, pickle.loads, '
                         'yaml.load, BinaryFormatter.Deserialize, Marshal.load)',
                         'ysoserial-style gadget probing in a lab',
                         'Dependency scanning for known-vulnerable gadget libraries'],
        'exploitation_notes': 'Impact depends on available gadget chains in the '
                              'classpath/dependency set; a benign-looking object graph triggers '
                              'method calls during/after deserialization that chain to command '
                              'execution or file operations. Even without a full RCE gadget, DoS '
                              'and property-oriented attacks are possible. Fix: avoid native '
                              'deserialization of untrusted data, use data-only formats with '
                              'strict schemas, and enforce type allowlists.',
        'waf_notes': 'WAFs can flag known gadget magic bytes and base64 markers, but object graphs '
                     'are easily re-encoded/encrypted, so signature detection is unreliable — '
                     'controls belong at the deserializer (look-ahead allowlists, disabling '
                     'polymorphic type handling).',
        'real_world': [   'Apache Struts CVE-2017-5638 (Equifax breach)',
                          'CVE-2015-4852 (WebLogic T3)',
                          'Log4Shell CVE-2021-44228 (JNDI lookup chain)',
                          'CVE-2019-18935 (Telerik .NET)',
                          'CVE-2017-9805 (Struts REST XStream)'],
        'tools': [   'ysoserial / ysoserial.net',
                     'phpggc',
                     'gadgetprobe',
                     'marshalsec',
                     'freddy (burp extension)'],
        'references': [   'https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data',
                          'https://portswigger.net/web-security/deserialization',
                          'https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html',
                          'https://github.com/frohoff/ysoserial']},
    {   'id': 'file-upload-rce',
        'name': 'Malicious File Upload leading to RCE',
        'category': 'file-upload',
        'severity': 'critical',
        'popularity': 'common',
        'summary': 'An upload feature accepts an executable or interpretable file (or a valid file '
                   'with a dangerous extension/content) that the server later executes or serves, '
                   'yielding code execution.',
        'root_cause': 'confused-deputy-trust-boundary',
        'where_it_breaks': 'Validation relies on client-supplied Content-Type or extension only, '
                           'files land inside the webroot with executable handlers enabled, or '
                           'double-extension/null-byte/case tricks slip past filters; also archive '
                           'extraction (zip-slip), polyglot files, and image libraries with '
                           'parsing bugs (ImageTragick) that turn any upload into RCE.',
        'detection': [   'Grep upload handlers for extension/MIME allowlist vs blocklist and '
                         'storage path',
                         'Check whether upload directory is web-served and script-executable',
                         'Test extension bypasses and content sniffing in a lab',
                         'Review server config for handler mappings (.php, .jsp, .aspx, .phtml)'],
        'exploitation_notes': 'Goal is to place an interpretable payload where the server will '
                              'execute it, or to abuse a downstream parser. Bypasses include '
                              'content-type spoofing, alternate/uncommon executable extensions, '
                              'appending valid magic bytes (polyglots), path traversal in the '
                              'filename, and archive extraction escaping the target directory. '
                              'Fix: store outside webroot, randomize names, validate by content, '
                              'disable execution, serve via a separate sandboxed domain.',
        'waf_notes': 'WAFs inspect multipart bodies for script signatures and dangerous '
                     'extensions; conceptual evasion uses polyglots, benign-looking content with '
                     'malicious handlers, and chunked/encoded uploads. Real defense is server-side '
                     'content validation and non-executable storage, not payload signatures.',
        'real_world': [   'ImageTragick CVE-2016-3714',
                          'CVE-2017-12615 (Tomcat PUT JSP)',
                          'CVE-2021-22005 (vCenter file upload)',
                          'CVE-2023-22515 adjacent',
                          'GhostScript CVE-2018-16509'],
        'tools': [   'burp suite',
                     'fuxploider',
                     'upload scanners',
                     'exiftool for polyglot crafting analysis'],
        'references': [   'https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload',
                          'https://portswigger.net/web-security/file-upload',
                          'https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html']},
    {   'id': 'graphql-batching-alias-abuse',
        'name': 'GraphQL Batching, Alias Abuse & Introspection',
        'category': 'graphql',
        'severity': 'high',
        'popularity': 'uncommon',
        'summary': 'GraphQL aliasing and query batching let one HTTP request run thousands of '
                   'operations (brute-force/rate-limit bypass, DoS), while enabled introspection '
                   'and field suggestions leak the schema.',
        'root_cause': 'broken-authorization',
        'where_it_breaks': 'Rate limiting and cost controls are applied per-HTTP-request, but a '
                           'single GraphQL document can contain hundreds of aliased fields or an '
                           "array of batched operations; introspection/'did you mean' suggestions "
                           'expose hidden types even when disabled.',
        'detection': [   'Query __schema/__type for introspection; if disabled, probe '
                         'field-suggestion leakage',
                         'Send aliased duplicate mutations (login attempts) in one request to test '
                         'rate-limit bypass',
                         'Send batched query arrays; measure amplification and depth/cost handling',
                         'Map deep nested/circular queries for DoS potential'],
        'exploitation_notes': 'Conceptually: alias the same mutation many times (alias1: '
                              'login(...), alias2: login(...)) to brute-force OTP/credentials '
                              'under one request; deeply nested or batched queries amplify load; '
                              'introspection reveals admin-only fields for IDOR/authorization '
                              'testing.',
        'waf_notes': 'WAFs treat the request as one POST and rarely parse GraphQL ASTs, so '
                     'per-request throttling and body-size limits miss alias/batch amplification. '
                     'Defense needs query cost analysis, depth limits, disabled introspection, and '
                     'persisted queries.',
        'real_world': [   'Multiple bug bounty disclosures of OTP/2FA brute force via GraphQL '
                          'aliasing',
                          'OWASP GraphQL cheat sheet documented alias/batch abuse'],
        'tools': [   'inql (burp)',
                     'graphql-cop',
                     'clairvoyance (schema recovery)',
                     'graphql voyager'],
        'references': [   'https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html',
                          'https://portswigger.net/web-security/graphql',
                          'https://github.com/nikitastupin/clairvoyance']},
    {   'id': 'host-header-injection',
        'name': 'Host Header Injection',
        'category': 'header-injection',
        'severity': 'high',
        'popularity': 'common',
        'summary': 'Apps that trust the Host (or X-Forwarded-Host) header to build absolute URLs '
                   'enable poisoned password-reset links, cache poisoning, and routing-based '
                   'bypasses.',
        'root_cause': 'confused-deputy-trust-boundary',
        'where_it_breaks': 'Frameworks generate absolute links, reset tokens, and redirects from '
                           'the incoming Host/X-Forwarded-Host without validating it against an '
                           'allowlist, so an attacker-supplied host ends up in emails, cached '
                           'responses, or SSRF-style routing.',
        'detection': [   'Change Host / add X-Forwarded-Host to a canary and check reflection in '
                         'reset emails, links, redirects, and cached responses',
                         'Test duplicate Host headers, absolute-URI request lines, and port '
                         'injection',
                         "Trigger password reset and inspect the generated link's host"],
        'exploitation_notes': 'Conceptually: request a password reset with your host in the Host '
                              'header so the emailed reset link points to your server, capturing '
                              "the victim's token when they click; the same trust enables web "
                              'cache poisoning and open-redirect/routing abuse.',
        'waf_notes': "The Host header is legitimate metadata; injecting an attacker domain isn't a "
                     'classic signature hit. Defense: validate Host against an allowlist, use a '
                     'fixed canonical hostname for link generation.',
        'real_world': [   'Numerous password-reset poisoning bounty reports',
                          'PortSwigger Host-header attack labs and research'],
        'tools': ['burp suite', 'param miner'],
        'references': [   'https://portswigger.net/web-security/host-header',
                          'https://portswigger.net/web-security/host-header/exploiting',
                          'https://cheatsheetseries.owasp.org/cheatsheets/OWASP_Application_Security_Verification_Standard.html']},
    {   'id': 'ssi-esi-injection',
        'name': 'SSI / ESI Injection',
        'category': 'header-injection',
        'severity': 'high',
        'popularity': 'rare',
        'summary': 'Server-Side Includes and Edge-Side Includes directives injected into content '
                   'processed by web servers or caching proxies enable file read, SSRF, command '
                   'execution, or cache abuse.',
        'root_cause': 'code-data-confusion',
        'where_it_breaks': 'Web servers with SSI enabled parse <!--#exec/#include--> in served '
                           'files, and CDN/proxy layers (Varnish, Akamai, Squid) that process ESI '
                           'parse <esi:include>/<esi:vars> in upstream responses; if attacker '
                           "input reaches such content it's executed as a directive.",
        'detection': [   'Inject SSI (<!--#echo/#exec/#include-->) into stored/reflected content '
                         'and check for execution',
                         'Inject ESI (<esi:include src=...>) and observe whether the proxy fetches '
                         'attacker URLs (SSRF) or reflects vars',
                         'Fingerprint ESI support via <esi:vars> and surrogate headers'],
        'exploitation_notes': 'Conceptually: SSI #exec/#include can read files or run commands '
                              'where the server evaluates includes; ESI <esi:include> triggers '
                              'proxy-side SSRF and can bypass HttpOnly by reflecting cookies, or '
                              'poison caches. Success depends on which layer parses the directive.',
        'waf_notes': 'ESI/SSI tags look like harmless markup and are often processed after the WAF '
                     'by the caching layer; downstream parsing defeats inbound inspection. '
                     'Defense: disable SSI/ESI where unneeded, escape angle brackets, restrict ESI '
                     'to trusted origins.',
        'real_world': [   "GoSecure 'Beyond XSS: Edge Side Include Injection' research (2018)",
                          'Classic Apache SSI #exec RCE cases'],
        'tools': ['burp suite', 'manual directive probes'],
        'references': [   'https://www.gosecure.net/blog/2018/04/03/beyond-xss-edge-side-include-injection/',
                          'https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection',
                          'https://portswigger.net/kb/issues/00100b00_server-side-include-injection']},
    {   'id': 'crlf-response-splitting-range',
        'name': 'HTTP Response Splitting / Range Abuse',
        'category': 'header-injection',
        'severity': 'medium',
        'popularity': 'rare',
        'summary': 'CRLF injected into response headers splits one response into two (cache '
                   'poisoning, XSS, redirect), while malformed Range requests can cause DoS or '
                   'info leaks.',
        'root_cause': 'code-data-confusion',
        'where_it_breaks': 'Apps that reflect user input into response headers (Location, '
                           'Set-Cookie, custom) without stripping CR/LF let attackers terminate '
                           'the header block early and inject a second crafted response; '
                           'separately, servers mishandling Range/If-Range can over-allocate '
                           'memory or leak/duplicate content.',
        'detection': [   'Inject %0d%0a into inputs reflected in headers (redirect URLs, cookie '
                         'values) and check for header/body splitting',
                         'Test large/overlapping/multiple Range headers for memory blowup or '
                         'abnormal 206 responses',
                         'Review header-writing code for newline sanitization'],
        'exploitation_notes': 'Conceptually: a CRLF-injected Location or cookie value adds '
                              'attacker headers and a full second response that a downstream cache '
                              'may store and serve to others (poisoning/XSS/redirect). Range abuse '
                              '(e.g. Apache-Killer-style overlapping ranges) targets availability '
                              'or content confusion.',
        'waf_notes': 'Encoded newlines can slip past filters and modern servers block many raw '
                     'variants; Range abuse uses valid-looking headers. Defense: reject CR/LF in '
                     'header values, cap/validate Range, patch server stacks.',
        'real_world': [   'Classic HTTP response-splitting CVEs across app servers',
                          "CVE-2011-3192 Apache 'Killer' Range-header DoS"],
        'tools': ['burp suite', 'custom crlf/range fuzzers'],
        'references': [   'https://owasp.org/www-community/attacks/HTTP_Response_Splitting',
                          'https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html',
                          'https://nvd.nist.gov/vuln/detail/CVE-2011-3192']},
    {   'id': 'email-header-injection',
        'name': 'Email Header Injection',
        'category': 'header-injection',
        'severity': 'medium',
        'popularity': 'uncommon',
        'summary': 'CRLF in user input reflected into email headers lets attackers add recipients '
                   '(Bcc/Cc), spoof headers, or inject a body, enabling spam relay and phishing '
                   'from the app.',
        'root_cause': 'code-data-confusion',
        'where_it_breaks': 'Contact/feedback/reset forms that place user input into '
                           'To/From/Subject/headers via mail() or raw SMTP without stripping CR/LF '
                           'allow injection of extra header lines and, after a blank line, a new '
                           'body.',
        'detection': [   'Inject %0d%0a followed by Bcc:/Cc:/Subject: into name/subject/email '
                         'fields and check for extra recipients or headers',
                         'Test encoded newline variants and header/body separation',
                         'Review mail-sending code for CRLF sanitization'],
        'exploitation_notes': 'Conceptually: appending CRLF plus Bcc: lets the attacker send mail '
                              'to arbitrary recipients through the trusted app (spam/phishing), '
                              'spoof headers, or overwrite the body — abusing the app as an open '
                              'relay branded as the victim domain.',
        'waf_notes': 'Encoded CRLF may pass generic filters, and the header injection happens at '
                     'the mail layer; content WAFs seldom model it. Defense: strip/reject CR/LF, '
                     'use hardened mail libraries with separate header APIs.',
        'real_world': [   'Widespread PHP mail() header-injection spam-relay cases',
                          'OWASP and Acunetix documented email-injection incidents'],
        'tools': ['burp suite', 'custom crlf fuzzers'],
        'references': [   'https://owasp.org/www-community/vulnerabilities/CRLF_Injection',
                          'https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html',
                          'https://www.acunetix.com/websitesecurity/email-header-injection/']},
    {   'id': 'jwt-attacks',
        'name': 'JWT / JWS Attacks',
        'category': 'jwt',
        'severity': 'high',
        'popularity': 'common',
        'summary': 'Weaknesses in how JSON Web Tokens are validated let attackers forge or tamper '
                   'with tokens to impersonate users or escalate privileges.',
        'root_cause': 'confused-deputy-trust-boundary',
        'where_it_breaks': "Verification that trusts the token's own alg header — alg:none "
                           'acceptance, RS256-to-HS256 confusion (verifying an asymmetric token '
                           'with the public key as an HMAC secret), weak/guessable HMAC secrets, '
                           'unvalidated kid (path traversal / SQLi / SSRF via jku/x5u), missing '
                           'signature verification, and not checking exp/aud/iss.',
        'detection': [   'Decode tokens and inspect alg/kid/jku/x5u headers',
                         'Test alg:none and algorithm confusion in a lab',
                         'Brute-force weak HMAC secrets (hashcat)',
                         'Check server-side enforcement of expected algorithm and claims',
                         'Review kid/jku handling for injection/SSRF'],
        'exploitation_notes': 'Forge tokens by downgrading the algorithm, abusing key-confusion '
                              'where the public key doubles as the HMAC key, cracking weak '
                              'secrets, or pointing jku/kid at attacker-controlled keys/resources. '
                              'Fix: pin the expected algorithm server-side, use strong '
                              'secrets/managed keys, validate all standard claims, and never '
                              'derive the verification key from attacker-controlled header fields.',
        'waf_notes': 'WAFs rarely inspect JWT internals; alg:none and confusion attacks pass as '
                     'normal Authorization headers, so validation must be enforced in the '
                     'app/library configuration.',
        'real_world': [   'CVE-2015-9235 (jsonwebtoken alg confusion)',
                          'CVE-2016-5431 adjacent',
                          'CVE-2022-21449 (Java ECDSA psychic signatures)',
                          'Auth0 and multiple library alg:none disclosures'],
        'tools': ['jwt_tool', 'hashcat', 'burp jwt editor', 'jwt.io (analysis)'],
        'references': [   'https://portswigger.net/web-security/jwt',
                          'https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html',
                          'https://datatracker.ietf.org/doc/html/rfc8725']},
    {   'id': 'ldap-injection',
        'name': 'LDAP Injection',
        'category': 'ldap',
        'severity': 'high',
        'popularity': 'uncommon',
        'summary': 'Unescaped input in LDAP search filters lets attackers alter filter logic to '
                   'bypass authentication or enumerate directory attributes.',
        'root_cause': 'code-data-confusion',
        'where_it_breaks': 'Apps that build LDAP filters like (&(uid=INPUT)(...)) via string '
                           'concatenation without escaping filter metacharacters (*, (, ), \\, '
                           'NUL) allow injection of extra clauses, wildcards, or always-true '
                           'conditions ((uid=*)) into the directory query.',
        'detection': [   'Inject * and )( sequences into username/search fields and watch for auth '
                         'bypass or broadened results',
                         'Test blind boolean extraction via filter manipulation on attributes',
                         'Look for LDAP bind/search built from concatenated input'],
        'exploitation_notes': 'Conceptually: supply a wildcard or an injected clause that makes '
                              'the bind/search filter always true (login bypass) or that ANDs/ORs '
                              'additional attribute predicates to blind-enumerate values like '
                              'passwords stored as attributes.',
        'waf_notes': "LDAP metacharacters overlap with benign input and don't trip SQLi rules; "
                     'blind boolean variants send no obvious payload. Defense: RFC-4515 filter '
                     'escaping and parameterized directory APIs.',
        'real_world': [   'OWASP LDAP injection documentation and testing guide cases',
                          'Various enterprise SSO/LDAP auth-bypass disclosures'],
        'tools': ['burp suite', 'ldapsearch', 'custom filter fuzzers'],
        'references': [   'https://owasp.org/www-community/attacks/LDAP_Injection',
                          'https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html',
                          'https://portswigger.net/web-security/all-labs#ldap-injection']},
    {   'id': 'mass-assignment-autobinding',
        'name': 'Mass Assignment / Auto-binding (Object Property Injection)',
        'category': 'mass-assignment',
        'severity': 'high',
        'popularity': 'uncommon',
        'summary': 'Frameworks that automatically bind request parameters to object fields let '
                   'attackers set properties they should not control, such as role, isAdmin, '
                   'balance, or ownership.',
        'root_cause': 'implicit-trust-client-metadata',
        'where_it_breaks': 'Blindly binding request bodies to ORM models/DTOs (Rails, Spring, '
                           'Django, Laravel, ASP.NET model binding, Node/Mongoose) without an '
                           'explicit allowlist — so extra JSON fields like is_admin, verified, '
                           'price, or user_id get persisted; nested binding and JSON make hidden '
                           'fields easy to inject.',
        'detection': [   'Grep for whole-object binding (Model.create(params), @ModelAttribute, '
                         'ORM save of request-derived objects) without field allowlists',
                         'Add unexpected fields to requests and check persistence/authz effects',
                         'Review models for sensitive attributes and which are bindable'],
        'exploitation_notes': 'Submit additional parameters mapping to privileged fields to '
                              'escalate privileges, alter prices, or reassign ownership. Fix: '
                              'explicit allowlists (strong params / DTOs with only user-editable '
                              'fields), mark sensitive fields non-bindable, and separate input '
                              'models from persistence models.',
        'waf_notes': 'The extra parameters look benign to WAFs; this is an application '
                     'binding-configuration issue, so allowlisting at the model layer is the '
                     'control.',
        'real_world': [   'GitHub 2012 mass-assignment (Rails, public-key injection)',
                          'CVE-2021-22112 adjacent',
                          'Multiple API mass-assignment bounties (OWASP API6:2019)',
                          'Uber and other privilege-escalation reports'],
        'tools': ['burp suite', 'param miner', 'semgrep', 'arjun (param discovery)'],
        'references': [   'https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html',
                          'https://owasp.org/API-Security/editions/2019/en/0xa6-mass-assignment/',
                          'https://portswigger.net/web-security/api-testing']},
    {   'id': 'nosql-injection',
        'name': 'NoSQL Injection',
        'category': 'nosql',
        'severity': 'high',
        'popularity': 'common',
        'summary': 'Attacker-controlled operators or JavaScript passed into NoSQL queries (MongoDB '
                   '$where/$ne/$gt, $regex) bypass authentication and extract data without classic '
                   'SQL syntax.',
        'root_cause': 'code-data-confusion',
        'where_it_breaks': 'Document stores that accept query operators from JSON bodies or coerce '
                           'query-string params into objects let clients replace a scalar with an '
                           'operator object ({"$ne":null}) or supply server-side JS ($where) that '
                           'runs in the DB, subverting filters and auth.',
        'detection': [   'Send operator objects ($ne, $gt, $regex, $where) in login/filter fields '
                         'and observe auth bypass or boolean differences',
                         'Test param[$ne]=x query-string-to-object coercion in Express/PHP',
                         'Use $regex/$where for blind boolean/timing extraction',
                         'Look for server-side JavaScript evaluation sinks'],
        'exploitation_notes': 'Conceptually: replace password value with {"$ne":null} to match any '
                              'record, or use $regex/$where oracles to exfiltrate secrets '
                              'character-by-character; $where with JS can enable heavier logic and '
                              'timing side channels. Auth bypass is the classic impact.',
        'waf_notes': 'JSON operator payloads and array-bracket param coercion evade SQLi-focused '
                     'WAFs; the dollar-sign operators look benign. Defense: type-check/cast '
                     'inputs, disable $where/JS, use query allowlists.',
        'real_world': [   'Numerous MongoDB auth-bypass bounty reports',
                          'PayloadsAllTheThings NoSQL section documents real cases'],
        'tools': ['nosqlmap', 'burp suite', 'nosqli'],
        'references': [   'https://owasp.org/www-community/Injection_Flaws',
                          'https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html',
                          'https://portswigger.net/web-security/nosql-injection']},
    {   'id': 'saml-signature-wrapping-xsw',
        'name': 'SAML Signature Wrapping (XSW)',
        'category': 'oauth-saml',
        'severity': 'critical',
        'popularity': 'rare',
        'summary': 'XML Signature Wrapping exploits the gap between the signed element a validator '
                   'checks and the assertion the application actually consumes, forging '
                   'authenticated identities.',
        'root_cause': 'parser-differential',
        'where_it_breaks': 'SAML responses are XML with a detached signature referencing an '
                           'element by ID; if signature validation and business logic resolve '
                           'different elements (due to XPath/ID handling, multiple assertions, or '
                           'moved signatures), an attacker wraps a valid signed blob around a '
                           'forged assertion the app trusts.',
        'detection': [   'Insert a second (forged) assertion and relocate/duplicate the Signature '
                         'element; check if login succeeds',
                         'Test whether the SP validates the signature over the exact assertion it '
                         'consumes (ID references, first-vs-last element)',
                         'Fuzz XML structure: extra Assertion, Object wrappers, comment truncation '
                         'in NameID'],
        'exploitation_notes': 'Conceptually: keep the original signed assertion so the signature '
                              'verifies, but add an unsigned attacker assertion positioned where '
                              'the SP reads identity, granting arbitrary user/admin login. '
                              'XML-comment and canonicalization quirks (e.g. NameID truncation) '
                              'are related variants.',
        'waf_notes': "WAFs can't validate XML signature/reference binding; the SAML blob is base64 "
                     'and structurally valid. Defense is library-level: schema-hardening, '
                     'single-assertion enforcement, validating signature over the consumed '
                     'element.',
        'real_world': [   "Duo Labs 'The road to hell is paved with SAML assertions' (2017) — "
                          'comment-truncation auth bypass across many SPs',
                          'CVE-2017-11427 (python-saml), CVE-2018-0489 (Shibboleth), original XSW '
                          'research by Somorovsky et al.'],
        'tools': ['saml raider (burp)', 'samltool', 'custom xml editors'],
        'references': [   'https://web-in-security.blogspot.com/2014/11/detecting-and-exploiting-xml-signature.html',
                          'https://duo.com/blog/duo-finds-saml-vulnerabilities-affecting-multiple-implementations',
                          'https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91.pdf']},
    {   'id': 'oauth-oidc-saml-flaws',
        'name': 'OAuth / OIDC & SAML Federation Flaws',
        'category': 'oauth-saml',
        'severity': 'high',
        'popularity': 'common',
        'summary': 'Misimplementations of delegated auth and SSO protocols allow account takeover, '
                   'token theft, or authentication bypass.',
        'root_cause': 'confused-deputy-trust-boundary',
        'where_it_breaks': 'OAuth: unvalidated/loosely-matched redirect_uri, missing or '
                           'non-verified state (CSRF), implicit-flow token leakage, missing PKCE '
                           'on public clients, authorization-code injection/mix-up, and '
                           'over-trusting client-supplied identity. SAML: signature-not-verified '
                           'or partial verification, XML Signature Wrapping (XSW), '
                           'canonicalization/comment-injection, and IdP-confusion; OIDC adds '
                           'nonce/aud/iss and id_token validation gaps.',
        'detection': [   'Test redirect_uri matching strictness and open-redirect chains',
                         'Check state/nonce presence and server-side validation',
                         'SAML response tampering and XSW testing (SAML Raider)',
                         'Verify signature coverage of the whole assertion and audience/issuer '
                         'checks',
                         'Confirm PKCE enforcement'],
        'exploitation_notes': 'Steal authorization codes/tokens via lax redirect_uri or open '
                              'redirects, replay/inject codes across clients (mix-up), or forge '
                              'SAML assertions by wrapping signed elements so the app reads '
                              'attacker-injected identity while signature validation passes over '
                              'the original. Fix: exact-match redirect URIs, enforce '
                              'state+PKCE+nonce, fully validate signatures/audience/issuer/expiry, '
                              'and reject assertions with ambiguous structure.',
        'waf_notes': 'Protocol messages look legitimate to WAFs; XSW and redirect abuses are logic '
                     'flaws, so correctness lives in the SSO library configuration and strict '
                     'validation, not signatures.',
        'real_world': [   'Microsoft/Okta and Sign in with Apple (CVE-2020, nonce) research',
                          'SAML XSW research (Somorovsky et al.)',
                          'CVE-2017-11427/11428 (OneLogin/python-saml comment injection, aka '
                          'SAMLStorm-era)',
                          'CVE-2022-21703 adjacent',
                          'Multiple OAuth account-takeover bounties'],
        'tools': ['burp suite + saml raider', 'espresso', 'oauth testing scripts', 'samltool'],
        'references': [   'https://portswigger.net/web-security/oauth',
                          'https://portswigger.net/web-security/saml',
                          'https://oauth.net/2/security-best-current-practice/',
                          'https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html']},
    {   'id': 'path-traversal-lfi-rfi',
        'name': 'Path Traversal / Local File Inclusion / Remote File Inclusion',
        'category': 'path-traversal',
        'severity': 'high',
        'popularity': 'common',
        'summary': 'User input controls a filesystem path or include target, letting attackers '
                   'read/write files outside the intended directory (LFI/traversal) or include '
                   'remote code (RFI).',
        'root_cause': 'confused-deputy-trust-boundary',
        'where_it_breaks': 'Building paths by concatenating request input into file reads, '
                           'template/include statements, or archive extraction without '
                           'canonicalizing and confining to a base directory; ../ sequences, '
                           'absolute paths, URL/double-URL/unicode encoding, and null bytes escape '
                           'the intended root. RFI arises when include targets accept remote URLs '
                           '(allow_url_include).',
        'detection': [   'Grep file APIs (open, readFile, include/require, sendFile, File(), '
                         'fs.readFile) fed by request data',
                         'Canonicalization checks — does the code realpath and verify prefix?',
                         'Traversal fuzzing with encodings',
                         'Detect LFI via known files (/etc/passwd, web.config, wrappers '
                         'php://filter)'],
        'exploitation_notes': 'Read sensitive files (configs, keys, source), reach log files or '
                              'session stores to chain into LFI-to-RCE, or use PHP '
                              'wrappers/filters for source disclosure and payload smuggling. RFI '
                              '(rarer today) directly includes attacker-hosted code. Fix: resolve '
                              'to canonical path and assert it stays under an allowed base; prefer '
                              'opaque IDs mapped server-side to paths.',
        'waf_notes': 'WAFs match ../ and known file names; conceptual evasion uses encoding '
                     'layers, mixed slashes, overlong UTF-8, and wrapper schemes. '
                     'Canonicalize-then-confine on the server is the reliable control.',
        'real_world': [   'CVE-2021-41773 / CVE-2021-42013 (Apache HTTP Server path traversal → '
                          'RCE)',
                          'CVE-2018-1000861 adjacent',
                          'CVE-2019-11510 (Pulse Secure arbitrary file read)',
                          'CVE-2024-3400 (PAN-OS path traversal chain)'],
        'tools': ['burp suite', 'ffuf / dotdotpwn', 'lfisuite', 'semgrep'],
        'references': [   'https://owasp.org/www-community/attacks/Path_Traversal',
                          'https://portswigger.net/web-security/file-path-traversal',
                          'https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html']},
    {   'id': 'zip-slip-path-traversal-extraction',
        'name': 'Zip Slip / Archive Extraction Path Traversal',
        'category': 'path-traversal',
        'severity': 'high',
        'popularity': 'uncommon',
        'summary': 'Archive entries containing ../ or absolute paths let extraction routines write '
                   'files outside the intended directory, overwriting configs, web roots, or '
                   'startup scripts for RCE.',
        'root_cause': 'confused-deputy-trust-boundary',
        'where_it_breaks': 'Zip/tar/rar/7z extractors that concatenate the entry name to a base '
                           'directory without canonicalizing and validating the resolved path '
                           'allow entries like ../../etc/cron.d/x or absolute paths (and symlink '
                           'entries) to escape the target folder.',
        'detection': [   'Craft archives with ../ traversal and absolute-path entries and observe '
                         'write location',
                         'Test symlink entries and Windows backslash variants',
                         'Review extraction code for path canonicalization + prefix check before '
                         'write'],
        'exploitation_notes': 'Conceptually: an uploaded archive contains an entry whose name '
                              'traverses to a sensitive location (web-accessible dir, SSH '
                              'authorized_keys, service config); on extraction the file lands '
                              'there, enabling overwrite-to-RCE or persistence. Symlink and '
                              'nested-archive variants extend reach.',
        'waf_notes': "The archive is a binary blob; content WAFs don't parse entry names. Defense "
                     'is code-level: resolve each entry against the base dir and reject anything '
                     'escaping it, ignore absolute paths and symlinks.',
        'real_world': [   "Snyk 'Zip Slip' disclosure (2018) affecting thousands of "
                          'projects/libraries',
                          'Numerous CVEs across unarchivers and language stdlibs'],
        'tools': ['snyk', 'evilarc', 'custom archive builders'],
        'references': [   'https://security.snyk.io/research/zip-slip-vulnerability',
                          'https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html',
                          'https://owasp.org/www-community/attacks/Path_Traversal']},
    {   'id': 'server-side-prototype-pollution-rce',
        'name': 'Server-Side Prototype Pollution to RCE',
        'category': 'prototype-pollution',
        'severity': 'critical',
        'popularity': 'uncommon',
        'summary': 'Polluting Object.prototype on a Node.js server injects properties into every '
                   'object, corrupting control flow and reaching gadgets that pass attacker data '
                   'into child_process/spawn options for RCE.',
        'root_cause': 'implicit-trust-client-metadata',
        'where_it_breaks': 'Recursive merge/clone/extend, query-string parsers, and config loaders '
                           'that walk attacker JSON and assign __proto__/constructor.prototype '
                           "keys without filtering. Gadget chains (e.g. spawn's "
                           'shell/NODE_OPTIONS/env, EJS/handlebars options) turn pollution into '
                           'code execution.',
        'detection': [   'Send __proto__/constructor.prototype keys and probe for a reflected '
                         'polluted property (e.g. a status code or added header) via the SSPP '
                         'detection technique',
                         'Look for deep-merge libraries (lodash.merge<4.17.5, older '
                         'set/defaultsDeep, hoek)',
                         'Grep for child_process with option objects influenced by config; look '
                         'for NODE_OPTIONS gadgets',
                         'Fuzz JSON/query params with polluting keys and watch for behavior '
                         'changes'],
        'exploitation_notes': 'Conceptually: pollute a prototype property that a downstream sink '
                              'reads as a default (e.g. spawn options, template compiler options, '
                              'shell path), causing the server to execute attacker-influenced '
                              "commands or load an attacker file via NODE_OPTIONS='--require'.",
        'waf_notes': '__proto__ literals are a weak signature and easily blocked, but '
                     'constructor.prototype and nested/array-notation variants, or the key '
                     'arriving JSON-encoded, evade naive filters; the malicious effect is '
                     'second-order so payload inspection alone misses it.',
        'real_world': [   "PortSwigger 'Server-side prototype pollution' research (Gareth Heyes, "
                          '2022)',
                          'Kibana CVE-2019-7609 (prototype pollution to RCE)',
                          'Multiple lodash merge CVEs (CVE-2018-3721, CVE-2019-10744)'],
        'tools': [   "burp 'server-side prototype pollution scanner' extension",
                     'proto-pollution nodejs gadgets research',
                     'semgrep rules for merge sinks'],
        'references': [   'https://portswigger.net/research/server-side-prototype-pollution',
                          'https://github.com/HoLyVieR/prototype-pollution-nsec18',
                          'https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html']},
    {   'id': 'race-condition-toctou',
        'name': 'Race Conditions / TOCTOU (limit-overrun, double-spend)',
        'category': 'race-condition',
        'severity': 'high',
        'popularity': 'uncommon',
        'summary': 'Concurrent requests exploit the window between a check and its use, letting '
                   'attackers exceed limits, double-spend, or bypass single-use constraints.',
        'root_cause': 'state-desync-race',
        'where_it_breaks': 'Non-atomic check-then-act on shared state — redeeming a one-time '
                           'coupon/gift card, withdrawing funds, applying rate/quota limits, or '
                           'promoting state — where reads and writes are not serialized (missing '
                           "DB transactions, row locks, or idempotency keys). PortSwigger's "
                           'single-packet attack made these highly reliable to trigger.',
        'detection': [   'Identify check-then-act sequences on money/quota/uniqueness',
                         'Send parallel requests (Turbo Intruder single-packet / HTTP/2) and '
                         'observe overrun',
                         'Review for DB transactions, SELECT ... FOR UPDATE, unique constraints, '
                         'idempotency',
                         'Look for time gaps between validation and mutation'],
        'exploitation_notes': 'Fire many simultaneous requests so multiple pass the check before '
                              'any commits, duplicating a limited action. Fix: atomic operations '
                              '(single UPDATE with conditions), database-level constraints/locks, '
                              'idempotency keys, and avoiding read-modify-write across round '
                              'trips.',
        'waf_notes': "Each request is valid, so WAFs don't detect it; velocity anomaly detection "
                     'helps but correctness must come from atomic server-side state handling.',
        'real_world': [   "PortSwigger 'Smashing the state machine' / single-packet attack "
                          'research (2023)',
                          'Starbucks gift-card duplication',
                          'numerous exchange/wallet double-spend and coupon-abuse bounties'],
        'tools': [   'burp suite + turbo intruder (single-packet attack)',
                     'custom concurrent clients'],
        'references': [   'https://portswigger.net/web-security/race-conditions',
                          'https://portswigger.net/research/smashing-the-state-machine',
                          'https://owasp.org/www-community/vulnerabilities/Race_Conditions']},
    {   'id': 'single-packet-race-toctou',
        'name': 'Single-Packet Race Conditions / TOCTOU',
        'category': 'race-condition',
        'severity': 'high',
        'popularity': 'uncommon',
        'summary': 'The single-packet-attack technique removes network jitter to land many '
                   'requests in the same processing window, exploiting time-of-check/time-of-use '
                   'gaps for limit-overrun and state races.',
        'root_cause': 'state-desync-race',
        'where_it_breaks': 'Business logic checks a condition (coupon unused, balance sufficient, '
                           'invite unclaimed) then acts on it non-atomically; concurrent requests '
                           "all pass the check before any commits. HTTP/2's single-packet attack "
                           'synchronizes ~20-30 requests server-side to defeat jitter.',
        'detection': [   'Send a burst of identical requests via Turbo Intruder single-packet / '
                         'gate mode and check for over-limit effects',
                         'Look for non-transactional check-then-act flows (redeem, withdraw, '
                         'apply-once, register-unique)',
                         'Watch for duplicated side effects: multiple redemptions, negative '
                         'balances, duplicate resources'],
        'exploitation_notes': 'Conceptually: fire the same action many times in one synchronized '
                              'volley so all executions read the pre-mutation state, e.g. redeem a '
                              'single-use voucher N times, bypass a rate/limit, or double-spend. '
                              'TOCTOU also spans file/permission checks.',
        'waf_notes': 'Each individual request is legitimate; rate-limit and signature WAFs see '
                     'normal traffic. Only atomicity (locks, DB constraints, idempotency keys) '
                     'defends — evasion is inherent because volume, not payload, is the vector.',
        'real_world': [   "PortSwigger 'Smashing the state machine' / single-packet attack (James "
                          'Kettle, 2023)',
                          'Numerous bounty reports: coupon/gift-card multi-redemption, invite-code '
                          'reuse'],
        'tools': [   'turbo intruder (single-packet, race-single-packet.py)',
                     "burp repeater 'send group in parallel'"],
        'references': [   'https://portswigger.net/research/smashing-the-state-machine',
                          'https://portswigger.net/web-security/race-conditions',
                          'https://portswigger.net/web-security/race-conditions/lab-race-conditions-limit-overrun']},
    {   'id': 'os-command-injection',
        'name': 'OS Command Injection',
        'category': 'rce',
        'severity': 'critical',
        'popularity': 'common',
        'summary': 'User input reaches a shell or command interpreter, letting an attacker append '
                   'or alter commands executed by the host OS.',
        'root_cause': 'code-data-confusion',
        'where_it_breaks': 'Calls that spawn a shell (system, exec with shell=True, popen, '
                           'Runtime.exec of a string, child_process.exec, backticks) with '
                           'concatenated input — commonly in ping/traceroute utilities, file '
                           'conversion (ImageMagick/ffmpeg wrappers), archive handling, and '
                           'admin/diagnostic endpoints. Argument-injection is a subtler variant '
                           'where separate args are safe but a value becomes a flag.',
        'detection': [   'Grep for shell-spawning APIs with dynamic strings',
                         'OOB detection for blind cases (DNS/HTTP callback from injected command)',
                         'Time-delay probes (sleep)',
                         'Taint analysis to command sinks'],
        'exploitation_notes': 'Confirm via shell metacharacters (;, |, &&, $(), backticks, '
                              'newlines) producing side effects; blind confirmation relies on OOB '
                              'callbacks or timing. Argument injection abuses tools that interpret '
                              'leading dashes as options. Fix is to avoid the shell entirely and '
                              'pass argument vectors, with strict allowlists for any values that '
                              'must be interpolated.',
        'waf_notes': 'WAFs flag metacharacters and common binaries (cat, /etc/passwd, nc); '
                     'conceptual evasion uses shell expansion, variable indirection, quoting, and '
                     'whitespace alternatives (IFS). Signature matching is brittle — safe '
                     'argv-based execution is the durable control.',
        'real_world': [   'Shellshock CVE-2014-6271',
                          'CVE-2021-44228 adjacent tooling',
                          'CVE-2014-3120 (Elasticsearch)',
                          'CVE-2021-22205 (GitLab ExifTool → RCE)',
                          'CVE-2024-4577 (PHP-CGI argument injection on Windows)'],
        'tools': ['burp + collaborator', 'commix', 'semgrep/codeql'],
        'references': [   'https://owasp.org/www-community/attacks/Command_Injection',
                          'https://portswigger.net/web-security/os-command-injection',
                          'https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html']},
    {   'id': 'cl0-client-side-desync',
        'name': 'CL.0 / Client-Side Desync Request Smuggling',
        'category': 'request-smuggling',
        'severity': 'high',
        'popularity': 'uncommon',
        'summary': 'Servers that ignore Content-Length on certain endpoints (CL.0) or browsers '
                   'that can be coerced into desync (client-side desync) let a request body be '
                   'reinterpreted as a new request, smuggling into victims.',
        'root_cause': 'parser-differential',
        'where_it_breaks': 'A front-end forwards a request whose body the back-end (or a specific '
                           'vulnerable endpoint) treats as ignored, so the leftover bytes prefix '
                           'the next request on the reused keep-alive connection. Client-side '
                           "desync uses the victim's own browser to poison its connection to the "
                           'origin.',
        'detection': [   'Timing-based smuggling probes (Burp HTTP Request Smuggler) for CL.0/0.CL '
                         'discrepancies per-endpoint',
                         'Send a request with a body to endpoints that should ignore it '
                         '(redirects, static, error paths) and watch for connection-level '
                         'poisoning',
                         'For client-side desync, test whether the browser reuses a poisoned '
                         'connection with a follow-up navigation'],
        'exploitation_notes': 'Conceptually: append a partial second request in the body; if the '
                              "back-end parses it as a standalone request, the next user's request "
                              'is captured or prefixed, enabling credential theft, cache '
                              'poisoning, or forced redirects — client-side variants need no proxy '
                              'at all.',
        'waf_notes': 'Front-end WAFs inspect the request as a whole and miss the reparse on the '
                     'back-end; discrepancies live in framing, not content. Defense is HTTP/1.1 '
                     'normalization, connection non-reuse, and rejecting ambiguous framing.',
        'real_world': [   "PortSwigger 'Browser-Powered Desync Attacks' (James Kettle, 2022) "
                          'introducing CL.0 and client-side desync',
                          'Numerous CDN/load-balancer smuggling disclosures'],
        'tools': ['burp http request smuggler', 'turbo intruder', 'h2csmuggler'],
        'references': [   'https://portswigger.net/research/browser-powered-desync-attacks',
                          'https://portswigger.net/web-security/request-smuggling',
                          'https://portswigger.net/web-security/request-smuggling/browser']},
    {   'id': 'h2-downgrade-smuggling',
        'name': 'HTTP/2 Downgrade Smuggling (H2.CL / H2.TE)',
        'category': 'request-smuggling',
        'severity': 'high',
        'popularity': 'uncommon',
        'summary': 'Front-ends that downgrade HTTP/2 to HTTP/1.1 without re-deriving framing let '
                   'attacker-supplied Content-Length/Transfer-Encoding or injected '
                   'pseudo-header/CRLF values desync the back-end.',
        'root_cause': 'parser-differential',
        'where_it_breaks': 'HTTP/2 uses length-prefixed frames so framing is unambiguous, but many '
                           'proxies rewrite requests to HTTP/1.1 for the origin and trust the H2 '
                           "message's declared length or copy header values containing CRLF/colon, "
                           'reintroducing classic smuggling (H2.CL, H2.TE, and '
                           'header/pseudo-header splitting).',
        'detection': [   'Send HTTP/2 requests with conflicting/invalid Content-Length or '
                         'Transfer-Encoding and observe back-end desync',
                         'Inject CRLF or extra fields into H2 header values / :path / :authority '
                         'and check for splitting after downgrade',
                         "Use HTTP Request Smuggler's HTTP/2 tests and response-queue probing"],
        'exploitation_notes': "Conceptually: because H2 doesn't require length headers, supplying "
                              'a bogus one that the downgrading proxy trusts causes the back-end '
                              'to mis-split the stream; header-injection variants smuggle whole '
                              'requests via CRLF in a header value. Yields request hijacking, '
                              'cache poisoning, and header spoofing.',
        'waf_notes': 'Many WAFs only fully parse HTTP/1.1 or normalize inconsistently across '
                     'protocol versions; H2-native malformed inputs slip past and manifest only '
                     'after downgrade. Defense: validate H2 messages, strip length headers, reject '
                     'CRLF in values.',
        'real_world': [   "PortSwigger 'HTTP/2: The Sequel is Always Worse' (James Kettle, 2021)",
                          'Real disclosures against Netflix/Imperva-style stacks and multiple '
                          'CDNs'],
        'tools': ['burp http request smuggler', 'turbo intruder', 'h2csmuggler', 'nghttp2'],
        'references': [   'https://portswigger.net/research/http2',
                          'https://portswigger.net/web-security/request-smuggling/advanced',
                          'https://portswigger.net/web-security/request-smuggling/advanced/http2']},
    {   'id': 'http-request-smuggling',
        'name': 'HTTP Request Smuggling / Desync',
        'category': 'request-smuggling',
        'severity': 'high',
        'popularity': 'common',
        'summary': 'Front-end and back-end servers disagree on where one HTTP request ends, '
                   "letting an attacker prepend data to the next user's request and poison the "
                   'connection.',
        'root_cause': 'parser-differential',
        'where_it_breaks': 'Chains of proxies/CDNs/app servers that parse Content-Length vs '
                           'Transfer-Encoding differently (CL.TE, TE.CL, TE.TE), or newer '
                           'HTTP/2-to-HTTP/1 downgrade desync and CL.0 / client-side desync — '
                           'arising when intermediaries and origins normalize headers '
                           'inconsistently or forward ambiguous framing.',
        'detection': [   'Timing-based probes for CL.TE/TE.CL discrepancies',
                         'HTTP/2 downgrade and CL.0 testing',
                         'Burp HTTP Request Smuggler extension',
                         'Review proxy/origin header-parsing configs and duplicate/obfuscated '
                         'header handling'],
        'exploitation_notes': "A smuggled prefix is attached to another user's request, enabling "
                              'request hijacking, credential/session capture, cache poisoning, '
                              'bypass of front-end security controls, and forced browsing. HTTP/2 '
                              'desync and client-side desync broaden the impact. Fix: use HTTP/2 '
                              'end-to-end, reject ambiguous framing, normalize at the edge, and '
                              'disable connection reuse where risky.',
        'waf_notes': 'The desync often happens before or around the WAF, so front-end filtering '
                     'can be bypassed entirely; some WAFs now detect obfuscated Transfer-Encoding, '
                     'but robust framing normalization at every hop is the real defense.',
        'real_world': [   'PortSwigger/James Kettle research (2019 revival, HTTP/2 desync 2021, '
                          'browser-powered desync 2022)',
                          'Multiple large-bounty reports against major CDNs and SaaS',
                          'CVE-2019-18277 (HAProxy) and related',
                          'CVE-2021-33193 (Apache mod_http2)'],
        'tools': [   'burp suite + http request smuggler',
                     'turbo intruder',
                     'h2csmuggler',
                     'smuggler.py'],
        'references': [   'https://portswigger.net/web-security/request-smuggling',
                          'https://portswigger.net/research/http2',
                          'https://portswigger.net/research/browser-powered-desync-attacks',
                          'https://cwe.mitre.org/data/definitions/444.html']},
    {   'id': 'sql-injection',
        'name': 'SQL Injection (classic, blind, boolean/time-based, second-order)',
        'category': 'sqli',
        'severity': 'critical',
        'popularity': 'common',
        'summary': 'Untrusted input is concatenated into SQL so the parser treats attacker data as '
                   'query syntax, allowing data exfiltration, authentication bypass, and sometimes '
                   'RCE via database features.',
        'root_cause': 'code-data-confusion',
        'where_it_breaks': "String-built queries anywhere an ORM or driver's parameterization is "
                           'bypassed — dynamic ORDER BY / column / table names (which cannot be '
                           'parameterized), LIKE clauses, IN() lists built by concatenation, raw '
                           'query escape hatches, and second-order cases where data is stored '
                           'safely then later concatenated into a query.',
        'detection': [   'Grep for string concatenation/format into query APIs (execute, rawQuery, '
                         'createQuery, f-strings, +)',
                         'Error-based fingerprinting from DB error messages',
                         'Boolean and time-based differential testing (blind)',
                         'Static analysis / CodeQL taint tracking source→sink',
                         'sqlmap on suspect parameters'],
        'exploitation_notes': 'Confirm via a query that changes result truthiness or induces '
                              'measurable delay; escalate with UNION-based extraction, stacked '
                              'queries where the driver allows, and reading DB metadata/schema. '
                              'Certain DBs expose file read/write or command execution (e.g., '
                              'xp_cmdshell, COPY TO PROGRAM, LOAD_FILE/INTO OUTFILE) turning SQLi '
                              'into RCE or file access. Second-order requires tracing stored '
                              'values into later sinks.',
        'waf_notes': 'WAFs match keyword/comment/quote signatures (UNION SELECT, OR 1=1, --); '
                     'conceptual evasion uses inline comments, case/whitespace variation, '
                     'alternative encodings, and logically equivalent syntax — which is why '
                     'parameterized queries, not signatures, are the fix. Defensive teams should '
                     'alert on DB errors and anomalous query shapes.',
        'real_world': [   'MOVEit Transfer CVE-2023-34362 (Cl0p mass exploitation)',
                          'CVE-2022-21661 (WordPress core WP_Query)',
                          'Heartland/7-Eleven breaches (Albert Gonzalez)',
                          'CVE-2019-15107 (Webmin adjacent)'],
        'tools': ['sqlmap', 'burp suite', 'codeql / semgrep', 'nosqlmap (for nosql variants)'],
        'references': [   'https://owasp.org/www-community/attacks/SQL_Injection',
                          'https://portswigger.net/web-security/sql-injection',
                          'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html']},
    {   'id': 'gopher-dict-ssrf-internal-rce',
        'name': 'Gopher/Dict SSRF to Internal Service RCE',
        'category': 'ssrf',
        'severity': 'critical',
        'popularity': 'uncommon',
        'summary': 'SSRF sinks that allow gopher:// or dict:// let attackers craft raw TCP '
                   'payloads to internal services (Redis, Memcached, SMTP, MySQL, FastCGI), '
                   'escalating SSRF into arbitrary command execution.',
        'root_cause': 'network-position-abuse',
        'where_it_breaks': "URL fetchers (often libcurl-backed) that don't restrict schemes permit "
                           'gopher://, which encodes an arbitrary byte stream sent to any '
                           'host:port; internal line-based protocols (Redis, FastCGI, SMTP) then '
                           'execute attacker-crafted commands, turning a fetch into RCE.',
        'detection': [   'Test whether SSRF sinks accept gopher://, dict://, file://, ftp:// '
                         'schemes',
                         'Probe internal ports for line-oriented services reachable from the '
                         'server',
                         'Check libcurl scheme allowlists and redirect handling'],
        'exploitation_notes': 'Conceptually: use gopher to send a crafted multi-line payload to an '
                              'unauthenticated internal Redis/FastCGI/SMTP instance (e.g. write a '
                              'cron key or PHP file), converting SSRF into code execution or data '
                              'write. dict:// enables banner grabbing and simple protocol '
                              'interactions.',
        'waf_notes': 'The outer request looks like a normal URL param; scheme-based abuse happens '
                     'server-side beyond inbound inspection. Defense: scheme allowlists '
                     '(http/https only), egress firewalling, authenticated internal services.',
        'real_world': [   'Redis-via-gopher SSRF-to-RCE writeups and CTF/bounty cases',
                          'FastCGI gopher exploitation research'],
        'tools': ['gopherus', 'ssrfmap', 'burp collaborator'],
        'references': [   'https://blog.chaitin.cn/gopher-attack-surfaces/',
                          'https://github.com/tarunkant/Gopherus',
                          'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html']},
    {   'id': 'ssrf-renderer-pdf-svg-image',
        'name': 'SSRF via PDF/SVG/Image/Webhook Renderers',
        'category': 'ssrf',
        'severity': 'critical',
        'popularity': 'common',
        'summary': 'Server-side document/image renderers and user-configurable webhooks fetch '
                   'attacker-controlled URLs, letting requests reach internal services and cloud '
                   'metadata endpoints.',
        'root_cause': 'network-position-abuse',
        'where_it_breaks': 'Headless-Chrome/wkhtmltopdf PDF export, SVG rasterizers '
                           '(ImageMagick/librsvg), image-from-URL features, and webhook/callback '
                           'configs perform outbound fetches from inside the trust boundary, often '
                           'following redirects and honoring file://, http://169.254.169.254, and '
                           'internal hostnames.',
        'detection': [   'Supply external URLs (Burp Collaborator) in HTML-to-PDF content, SVG '
                         '<image>/<use>, image-URL fields, and webhook targets; watch for '
                         'callbacks',
                         'Test redirect-following, DNS rebinding, and alternate schemes/IP '
                         'encodings to reach metadata/internal ranges',
                         'Probe for blind SSRF via timing and out-of-band interactions'],
        'exploitation_notes': 'Conceptually: embed an internal or metadata URL in content the '
                              'server renders/fetches; the response (or a rendered screenshot) may '
                              'exfiltrate cloud credentials (IMDS), internal admin pages, or '
                              'enable port scanning. SVG/XML also opens XXE-style file reads.',
        'waf_notes': 'Egress WAFs often only watch inbound payloads; the malicious request '
                     'originates server-side. IP-encoding tricks, DNS rebinding, and redirects '
                     'bypass naive allow/deny lists — defense is IMDSv2, egress filtering, and URL '
                     'validation after resolution.',
        'real_world': [   'Capital One 2019 breach (SSRF to AWS metadata)',
                          'Numerous HTML-to-PDF SSRF bounty reports',
                          "ImageMagick/'ImageTragick' CVE-2016-3714 SSRF/RCE via image handling"],
        'tools': ['burp collaborator', 'ssrfmap', 'gopherus (for gopher pivots)', 'interactsh'],
        'references': [   'https://portswigger.net/web-security/ssrf',
                          'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html',
                          'https://blog.assetnote.io/2021/01/13/blind-ssrf-chains/']},
    {   'id': 'ssrf-server-side-request-forgery',
        'name': 'Server-Side Request Forgery (SSRF), including blind/OOB',
        'category': 'ssrf',
        'severity': 'critical',
        'popularity': 'common',
        'summary': 'The server can be coerced into making HTTP(S) or other-protocol requests to '
                   'attacker-chosen destinations, typically internal services, cloud metadata '
                   'endpoints, or link-local addresses that are unreachable from the outside.',
        'root_cause': 'network-position-abuse',
        'where_it_breaks': 'Any feature that fetches a user-supplied URL/host — webhooks, URL '
                           'preview/unfurling, PDF/HTML-to-image renderers, image proxies, '
                           'import-from-URL, XML/SVG parsers, file fetchers, and open-redirect '
                           'chains — where the app validates the URL with a blocklist or a single '
                           'DNS resolution instead of resolving-then-pinning to a vetted IP.',
        'detection': [   'Grep for outbound HTTP clients (curl, requests, HttpClient, '
                         'URL.openConnection, file_get_contents, axios, net/http) fed with '
                         'request-derived URLs',
                         'Out-of-band interaction testing via Burp Collaborator / interactsh for '
                         'blind cases',
                         'Inspect responses for differential timing/errors when pointing at '
                         'internal ports',
                         'Watch for DNS lookups to attacker domains and requests to '
                         '169.254.169.254 / metadata.google.internal / fd00:ec2::254'],
        'exploitation_notes': 'Point the fetcher at internal-only endpoints or the cloud metadata '
                              'service to retrieve credentials/IMDS role tokens; blind SSRF is '
                              'confirmed via OOB DNS/HTTP callbacks and can still be leveraged for '
                              'internal port scanning, reaching Redis/Elasticsearch/internal admin '
                              'panels, or gadget chains. Bypass filters via DNS rebinding (TOCTOU '
                              'between validation and fetch), alternate IP encodings, IPv6-mapped '
                              'addresses, redirect following, and non-HTTP schemes (gopher, dict, '
                              'file) where the client supports them.',
        'waf_notes': 'WAFs key on literal internal IPs and metadata hostnames in parameters; '
                     'evasion is conceptual — decimal/octal/hex IP encoding, DNS rebinding, '
                     'redirect chains, and userinfo/@ tricks defeat naive string matching. Robust '
                     'defense is not a WAF but resolve-and-pin plus egress network controls '
                     '(IMDSv2, blocking link-local from workloads).',
        'real_world': [   'Capital One 2019 breach (SSRF to AWS IMDS, 100M+ records)',
                          'CVE-2021-26855 (Exchange ProxyLogon SSRF)',
                          'CVE-2021-21985 (VMware vCenter)',
                          'CVE-2022-1388 (F5 BIG-IP iControl REST SSRF-adjacent)',
                          'GitLab CVE-2021-22214'],
        'tools': [   'burp suite + collaborator',
                     'interactsh / oast',
                     'ssrfmap',
                     'gopherus',
                     'ffuf for internal port discovery'],
        'references': [   'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery',
                          'https://portswigger.net/web-security/ssrf',
                          'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html',
                          'https://www.capitalone.com/digital/facts2019/']},
    {   'id': 'open-redirect-ssrf-chain',
        'name': 'Open Redirect (and Redirect-to-SSRF / auth-token leak chains)',
        'category': 'ssrf',
        'severity': 'medium',
        'popularity': 'common',
        'summary': 'The application redirects to a user-controlled URL without validation, '
                   'enabling phishing, OAuth token/credential leakage, and bypass of '
                   'SSRF/allowlist filters via redirect following.',
        'root_cause': 'confused-deputy-trust-boundary',
        'where_it_breaks': 'Redirect/return/next/callback parameters echoed into a Location header '
                           'without allowlisting; also server-side fetchers that follow redirects, '
                           'so an attacker passes an allowlisted URL that 30x-redirects to an '
                           'internal target (TOCTOU/filter bypass). URL-parser confusion '
                           '(backslashes, @, //, whitespace) defeats naive origin checks.',
        'detection': [   'Grep redirect sinks (sendRedirect, Location header, res.redirect, '
                         'window.location on server-rendered) fed by request params',
                         'Test open-redirect payloads and parser confusion',
                         'Check whether server-side clients follow redirects and re-validate the '
                         'final IP',
                         'Review OAuth redirect_uri handling'],
        'exploitation_notes': 'Standalone it powers convincing phishing and leaks tokens appended '
                              'to redirect targets (Referer/fragment); chained, it bypasses SSRF '
                              'allowlists by redirecting an approved host to 169.254.169.254 or '
                              'internal services, or hijacks OAuth codes. Fix: allowlist redirect '
                              'destinations to known-safe relative paths/hosts, and for '
                              'server-side fetchers re-validate and pin the post-redirect IP.',
        'waf_notes': 'WAFs may flag http:// in redirect params; conceptual evasion uses '
                     'protocol-relative //, backslashes, @-userinfo, and encoding — so URL parsing '
                     'must be normalized and destinations allowlisted, not filtered by substrings.',
        'real_world': [   'Numerous OAuth token-theft bounties via redirect_uri + open redirect',
                          'CVE-2019-11510 chains',
                          'Well-known open-redirect + SSRF bypass writeups against cloud image '
                          'proxies',
                          'Google/Facebook open-redirect bounty history'],
        'tools': ['burp suite', 'oralyzer', 'nuclei open-redirect templates'],
        'references': [   'https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards',
                          'https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html',
                          'https://portswigger.net/web-security/ssrf']},
    {   'id': 'ssti-server-side-template-injection',
        'name': 'Server-Side Template Injection (SSTI)',
        'category': 'ssti',
        'severity': 'critical',
        'popularity': 'common',
        'summary': 'User input is embedded into a server-side template that is then evaluated, '
                   'allowing template-language expression execution that frequently escalates to '
                   'RCE.',
        'root_cause': 'code-data-confusion',
        'where_it_breaks': 'Concatenating user input into the template source (not the data '
                           'context) — e.g., rendering a string built from input in '
                           'Jinja2/Twig/Freemarker/Velocity/ERB/Handlebars/Thymeleaf — common in '
                           'email/notification templating, CMS themes, and report generators that '
                           'let users supply template snippets.',
        'detection': [   'Polyglot probes evaluating arithmetic (e.g., {{7*7}} style across '
                         'engines) to fingerprint the engine',
                         'Grep for render_template_string / new Template(userInput) / eval-like '
                         'template APIs',
                         'Differential responses indicating evaluation vs literal echo'],
        'exploitation_notes': 'First fingerprint the engine via evaluation differentials, then '
                              'traverse the object/attribute graph exposed by the template '
                              'language to reach OS-level primitives (many engines expose '
                              'subprocess/class loaders). Sandboxes in some engines are bypassable '
                              'via reflection. Fix: never build templates from user input; pass '
                              'user data strictly as bound variables, and sandbox/allowlist if '
                              'templating must be user-facing.',
        'waf_notes': 'WAFs look for {{ }} / ${ } and engine builtins; conceptual evasion uses '
                     'attribute-access indirection, string concatenation of dangerous names, and '
                     'encoding. Because payloads are engine-specific and highly variable, '
                     'architectural separation of code and data is the real control.',
        'real_world': [   'CVE-2016-4977 (Spring EL)',
                          'CVE-2019-3396 (Confluence Widget Connector Velocity)',
                          'CVE-2021-26084 (Confluence OGNL)',
                          'CVE-2022-22954 (VMware Workspace ONE freemarker/EL)'],
        'tools': ['tplmap', 'burp suite', 'semgrep'],
        'references': [   'https://portswigger.net/web-security/server-side-template-injection',
                          'https://owasp.org/www-community/attacks/Server_Side_Template_Injection',
                          'https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html']},
    {   'id': 'dependency-confusion',
        'name': 'Dependency Confusion',
        'category': 'supply-chain',
        'severity': 'critical',
        'popularity': 'common',
        'summary': "Publishing a public package with the same name as an org's private internal "
                   "package causes build tooling to pull the attacker's higher-versioned public "
                   'copy, achieving code execution in CI/prod.',
        'root_cause': 'supply-chain-transitive-trust',
        'where_it_breaks': 'Package managers (npm/pip/gem/Maven/NuGet) that search public and '
                           'private registries without scoping or explicit source pinning resolve '
                           'by highest version across all configured sources, so a public namesake '
                           'with version 99.0.0 wins over the internal 1.x.',
        'detection': [   'Enumerate internal package names leaked in source maps, package.json, '
                         'error messages, or public artifacts',
                         'Check whether those names are unclaimed on public registries',
                         'Audit registry/config for source pinning, scopes, and repository '
                         'priority'],
        'exploitation_notes': 'Conceptually: register the unclaimed internal name publicly with a '
                              'high version and an install/postinstall hook; when a developer or '
                              'CI resolves dependencies, the malicious package installs and its '
                              'lifecycle scripts run inside the build. No user interaction beyond '
                              'a normal install.',
        'waf_notes': "Not a WAF-facing attack at all — it's a build-time supply-chain issue. "
                     'Defense: scoped packages, registry allowlists, verified/pinned sources, and '
                     'reserving internal names publicly.',
        'real_world': [   "Alex Birsan 'Dependency Confusion' (2021) — breached Apple, Microsoft, "
                          'PayPal, Shopify, etc.',
                          'Subsequent widespread npm/PyPI namesquatting incidents'],
        'tools': ['confused (dependency-confusion scanner)', 'snyk', 'internal registry audits'],
        'references': [   'https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610',
                          'https://github.com/visma-prodsec/confused',
                          'https://owasp.org/www-project-top-ten/']},
    {   'id': 'supply-chain-dependency',
        'name': 'Software Supply-Chain / Dependency Attacks (incl. dependency confusion)',
        'category': 'supply-chain',
        'severity': 'critical',
        'popularity': 'common',
        'summary': 'Compromise reaches the server through trusted build/dependency channels rather '
                   'than a direct request — malicious or hijacked packages, dependency confusion, '
                   'and poisoned build pipelines.',
        'root_cause': 'supply-chain-transitive-trust',
        'where_it_breaks': 'Installing packages by name without namespace/registry pinning (public '
                           'registry shadows an internal name — dependency confusion), typosquats, '
                           'unpinned/unverified dependencies, compromised maintainer accounts, and '
                           'CI/CD secrets or build steps that execute untrusted code (install '
                           'scripts, GitHub Actions).',
        'detection': [   'Inventory dependencies and internal package names that could be shadowed '
                         'publicly',
                         'SBOM generation and SCA scanning for known-malicious/vulnerable versions',
                         'Lockfile and integrity-hash verification',
                         'Monitor for install-time scripts and unexpected network egress during '
                         'build',
                         'Registry scoping/namespacing review'],
        'exploitation_notes': 'Attacker publishes a public package matching an internal dependency '
                              'name (higher version) so the resolver pulls theirs, executing '
                              'install-time code in the build/prod environment; or compromises an '
                              'existing package to ship a backdoor to all consumers. Fix: '
                              'scoped/private registries with explicit source pinning, integrity '
                              'hashes, minimal install scripts, and isolated, least-privilege '
                              'build environments.',
        'waf_notes': 'Out of scope for request WAFs entirely — this is a build/runtime trust '
                     'problem addressed by SCA, registry configuration, artifact signing '
                     '(Sigstore), and pipeline hardening.',
        'real_world': [   'Alex Birsan dependency confusion research (2021, 35+ major companies)',
                          'event-stream npm backdoor (2018)',
                          'SolarWinds SUNBURST (2020)',
                          'Codecov bash uploader (2021)',
                          'ua-parser-js / colors / node-ipc incidents',
                          'XZ Utils backdoor CVE-2024-3094 (2024)'],
        'tools': [   'snyk / dependabot / osv-scanner',
                     'syft/grype (sbom)',
                     'sigstore/cosign',
                     'socket.dev'],
        'references': [   'https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610',
                          'https://owasp.org/www-project-top-ten/2021/A06_2021-Vulnerable_and_Outdated_Components',
                          'https://slsa.dev/',
                          'https://www.cisa.gov/news-events/alerts/2024/03/29/reported-supply-chain-compromise-affecting-xz-utils-data-compression-library-cve-2024-3094']},
    {   'id': 'xpath-injection',
        'name': 'XPath / XQuery Injection',
        'category': 'xpath',
        'severity': 'high',
        'popularity': 'rare',
        'summary': 'Unescaped input in XPath queries over XML data stores lets attackers alter '
                   'node selection to bypass auth or blind-extract the entire document.',
        'root_cause': 'code-data-confusion',
        'where_it_breaks': 'Apps querying XML (auth files, config, XML DBs) build XPath '
                           "expressions by concatenating user input without quoting, so ' or "
                           "'1'='1 style injections and boolean/position predicates change which "
                           'nodes are returned.',
        'detection': [   "Inject XPath metacharacters (', or, and, position()) into fields backed "
                         'by XML and observe auth bypass or differing results',
                         'Use boolean/blind oracles (substring(), string-length()) to traverse the '
                         'document',
                         'Identify XML-backed queries with no parameterization'],
        'exploitation_notes': 'Conceptually: an always-true predicate bypasses login; blind '
                              'boolean queries walk the XML tree node-by-node to reconstruct '
                              'sensitive elements. XQuery variants extend to richer data stores.',
        'waf_notes': 'XPath syntax resembles generic quotes/keywords; blind extraction sends '
                     'innocuous-looking predicates. Defense: parameterized XPath (variable '
                     'binding) and strict input escaping.',
        'real_world': [   'OWASP XPath injection testing guide examples',
                          'Assorted XML-auth bypass disclosures'],
        'tools': ['burp suite', 'xcat (blind xpath extraction)'],
        'references': [   'https://owasp.org/www-community/attacks/XPATH_Injection',
                          'https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html',
                          'https://github.com/orf/xcat']},
    {   'id': 'xxe-xml-external-entity',
        'name': 'XML External Entity (XXE) Injection',
        'category': 'xxe',
        'severity': 'high',
        'popularity': 'common',
        'summary': 'An XML parser configured to resolve external entities processes '
                   'attacker-controlled XML, enabling file read, SSRF, and sometimes RCE or DoS.',
        'root_cause': 'insecure-defaults-misconfiguration',
        'where_it_breaks': 'XML parsers left at insecure defaults (external general/parameter '
                           'entities and DTDs enabled) processing user input — SOAP endpoints, '
                           'SAML, SVG/Office/document uploads (which are XML zips), RSS/XML APIs, '
                           'and configuration importers. Blind/OOB XXE uses parameter entities and '
                           'external DTDs when direct output is not reflected.',
        'detection': [   'Identify XML parsers and whether DTD/external entities are disabled '
                         '(DocumentBuilderFactory features, libxml_disable_entity_loader, '
                         'XmlResolver=null)',
                         'Inject entities referencing local files or OOB URLs in a lab',
                         'Test file-upload endpoints that parse XML-based formats (docx, svg, '
                         'xlsx)',
                         'OOB DTD callback for blind detection'],
        'exploitation_notes': 'Retrieve local files via external entities, pivot to SSRF against '
                              'internal services/metadata, or trigger billion-laughs DoS. Blind '
                              'variants exfiltrate file contents through OOB channels using nested '
                              'parameter entities in an external DTD. On some stacks (expect://, '
                              'PHP) it escalates to RCE. Fix: disable DTDs and external entity '
                              'resolution entirely.',
        'waf_notes': 'WAFs flag <!DOCTYPE / <!ENTITY / SYSTEM keywords; conceptual evasion uses '
                     'UTF-16/encoding tricks, parameter-entity indirection, and moving the payload '
                     'into uploaded XML formats. The parser-level disable is the fix, not '
                     'signatures.',
        'real_world': [   'CVE-2014-3660 (libxml2)',
                          'CVE-2017-9805 adjacent',
                          'Facebook 2014 XXE bug bounty',
                          'CVE-2018-1000840 (SAML)',
                          'CVE-2019-0227 (Apache Axis)'],
        'tools': ['burp suite (+ collaborator)', 'xxeinjector', 'oxml_xxe', 'semgrep'],
        'references': [   'https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing',
                          'https://portswigger.net/web-security/xxe',
                          'https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html']}]

ROOT_CAUSES: list[dict] = [   {   'id': 'code-data-confusion',
        'name': 'Code/Data Confusion (In-Band Control)',
        'summary': 'Data supplied by an untrusted party is concatenated into a string that a '
                   'downstream interpreter later parses, so attacker-controlled bytes cross the '
                   'boundary from inert data into executable control tokens. This is the literal '
                   'essence of every injection: there is no out-of-band channel separating the '
                   'trusted control plane (the query structure, the command, the markup grammar) '
                   'from the untrusted data plane (the values), so the interpreter cannot tell the '
                   "developer's intent from the attacker's.",
        'why_it_recurs': 'The default and most ergonomic way to build a command for another '
                         'interpreter is string concatenation/interpolation, which is exactly the '
                         'operation that erases the code/data boundary. Every language ships '
                         'string formatting before it ships safe parameterization, every new '
                         'interpreter (GraphQL, NoSQL, LLM prompts, template engines) '
                         're-introduces an in-band control syntax, and the vulnerability is '
                         'invisible in the common case because benign data never contains control '
                         'tokens. The tool that is easiest to reach is the unsafe one.',
        'derived_vuln_classes': [   'SQL injection',
                                    'NoSQL injection',
                                    'OS command injection',
                                    'argument injection',
                                    'Cross-Site Scripting (reflected/stored/DOM)',
                                    'server-side template injection (SSTI)',
                                    'LDAP injection',
                                    'XPath injection',
                                    'expression-language / OGNL injection',
                                    'log injection / log forging',
                                    'CRLF header injection',
                                    'GraphQL injection',
                                    'prompt injection (LLM)'],
        'systemic_fix': 'Establish a structural, out-of-band separation of code and data so '
                        'untrusted input can never be reinterpreted as control: parameterized '
                        'queries / prepared statements (values shipped over a separate channel '
                        'than the query AST), context-aware auto-escaping template engines that '
                        'encode by output grammar, safe APIs that take arg arrays instead of shell '
                        'strings (execve not system), allow-list-driven typed parsers, and '
                        'contextual output encoding at every sink. Never build a program by '
                        'string-concatenating untrusted input; hand the interpreter a pre-parsed '
                        'structure with data bound as opaque literals.',
        'references': [   'https://owasp.org/Top10/A03_2021-Injection/',
                          'https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html',
                          'https://portswigger.net/web-security/sql-injection',
                          'https://portswigger.net/web-security/server-side-template-injection',
                          'https://cwe.mitre.org/data/definitions/74.html']},
    {   'id': 'confused-deputy-trust-boundary',
        'name': 'Confused Deputy / Trust-Boundary Violation',
        'summary': 'A privileged component (the deputy) performs an action using its own authority '
                   'but under the direction of a less-privileged party, without carrying the '
                   "requester's authority with the request. The deputy's ambient privilege is "
                   'thereby borrowed by an attacker who supplies the object of the action but not '
                   "the right to it. Norm Hardy's 1988 formulation: the deputy is confused about "
                   'whose authority it is exercising because designation (which object) is '
                   'separated from authorization (may this caller touch it).',
        'why_it_recurs': 'Server-side architectures are built out of privileged intermediaries '
                         '(browsers with your cookies, the app server with its DB creds, an '
                         'SSRF-reachable metadata endpoint that trusts the network) whose '
                         'authority is ambient and positional rather than tied to the specific '
                         'request. As long as authority is carried by identity/position (a session '
                         'cookie the browser attaches automatically, a source IP an internal '
                         'service trusts) instead of by an unforgeable per-request capability, any '
                         "component that can steer the deputy inherits its power. The web's "
                         'cookie/same-origin model institutionalizes exactly this ambient '
                         'authority.',
        'derived_vuln_classes': [   'Cross-Site Request Forgery (CSRF)',
                                    'Server-Side Request Forgery (SSRF)',
                                    'clickjacking / UI redressing',
                                    'cloud metadata (IMDS) credential theft',
                                    'OAuth redirect_uri / token substitution abuse',
                                    'cross-service ambient-trust abuse',
                                    'SSO / SAML relay'],
        'systemic_fix': 'Bundle designation with authorization: use unforgeable, request-scoped '
                        'capabilities instead of ambient authority. Anti-CSRF tokens / SameSite '
                        'cookies + Origin/Fetch-Metadata validation so a request must prove '
                        'intent, not just identity; per-request signed tokens (IMDSv2 session '
                        'tokens) instead of trusting network position; the deputy must act with '
                        "the caller's authority, not its own. Adopt capability-security principles "
                        '(POLA) so a component can only reach what it was explicitly handed.',
        'references': [   'http://cap-lore.com/CapTheory/ConfusedDeputy.html',
                          'https://owasp.org/www-community/attacks/csrf',
                          'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/',
                          'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-Site',
                          'https://cwe.mitre.org/data/definitions/441.html']},
    {   'id': 'parser-differential',
        'name': 'Parser Differential / Impedance Mismatch',
        'summary': 'Two or more components in a chain parse the same bytes according to different '
                   '(or differently-configured) grammars, so a message that means one thing to '
                   'component A means something else to component B. Security decisions made by '
                   "the first parser are voided by the second parser's divergent interpretation. "
                   'This is the LangSec insight: input is a language, ad-hoc parsers accept a '
                   'larger/looser language than the spec, and any two hand-rolled parsers of a '
                   'complex format will disagree on edge cases.',
        'why_it_recurs': "Real protocols are underspecified, permissive ('be liberal in what you "
                         "accept'), and re-implemented independently by every proxy, cache, WAF, "
                         "framework, and library in the path. Postel's robustness principle "
                         'actively manufactures differentials, complex formats (HTTP, XML, MIME, '
                         'Unicode, multipart) are effectively Turing-tarpits, and no two '
                         'independent implementations agree on all malformed inputs. The '
                         'differential is emergent from the system, so no single vendor sees or '
                         'owns the bug.',
        'derived_vuln_classes': [   'HTTP request smuggling / desync (CL.TE, TE.CL, TE.TE, CL.0, '
                                    'H2.CL)',
                                    'XML External Entity (XXE) & billion-laughs',
                                    'Content-Type / charset confusion & MIME sniffing',
                                    'Unicode normalization & homoglyph / overlong-encoding '
                                    'bypasses',
                                    'double-decoding & canonicalization bypasses (path traversal '
                                    'via ..%252f)',
                                    'cookie/header parsing discrepancies',
                                    'JSON interoperability (duplicate keys, integer precision)',
                                    'SSRF URL-parser confusion (host vs authority disagreement)'],
        'systemic_fix': 'Collapse the differential: use a single, spec-strict, generated (not '
                        'hand-rolled) parser and reject rather than repair ambiguous input '
                        '(fail-closed on conflicting length/encoding headers, disable HTTP/1.1 '
                        'chunked+CL coexistence, disable XML external entities and DTDs by '
                        'default). Normalize/canonicalize to one representation before any '
                        'security decision, then re-validate. LangSec: define the input language '
                        'formally, parse fully before processing, and make every hop use identical '
                        'parsing semantics (end-to-end HTTP/2, front-end normalization).',
        'references': [   'http://langsec.org/',
                          'https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn',
                          'https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing',
                          'https://portswigger.net/research/http2',
                          'https://cwe.mitre.org/data/definitions/444.html']},
    {   'id': 'broken-authorization',
        'name': 'Missing or Broken Authorization',
        'summary': 'The system authenticates who you are but fails to consistently enforce what '
                   'you may do to a specific object or function. Authorization is a per-request, '
                   'per-object property, but it is enforced (if at all) in scattered, imperative '
                   'checks that are easy to omit; the absence of a check is the vulnerability, and '
                   'absence is invisible in normal use because legitimate users never request '
                   "objects they don't own.",
        'why_it_recurs': 'Authorization is a cross-cutting concern implemented as ad-hoc '
                         'if-statements bolted onto business logic, so it fails open by omission: '
                         'adding a new endpoint, object type, or field silently ships without the '
                         'corresponding check. There is no compiler error for a missing authz '
                         "check, object identifiers are exposed and enumerable, and 'looks fine in "
                         "the UI' hides the fact that the API trusts client-supplied object IDs. "
                         'It is the top web risk precisely because correctness requires '
                         'enforcement at every single access path.',
        'derived_vuln_classes': [   'Insecure Direct Object Reference (IDOR)',
                                    'Broken Object-Level Authorization (BOLA)',
                                    'Broken Function-Level Authorization (BFLA)',
                                    'vertical privilege escalation (accessing admin functions)',
                                    'horizontal privilege escalation (accessing peer objects)',
                                    'Broken Object Property Level Authorization / excessive data '
                                    'exposure',
                                    'forced browsing to unlinked functions',
                                    'multi-tenant isolation bypass'],
        'systemic_fix': 'Make authorization a mandatory, centralized, deny-by-default gate that '
                        'every request must pass, tied to the specific object and action: a policy '
                        'engine / middleware (ABAC/ReBAC, e.g. an OPA/Cedar/Zanzibar-style layer) '
                        'the data layer cannot be reached without, object references scoped to the '
                        'session (query WHERE owner = current_user, or per-user unguessable '
                        'handles), and framework-level enforcement so a new route is unreachable '
                        'until a policy is declared. Fail closed; test authorization as a '
                        'first-class matrix (role x object x action).',
        'references': [   'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/',
                          'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
                          'https://cwe.mitre.org/data/definitions/639.html',
                          'https://cwe.mitre.org/data/definitions/862.html',
                          'https://research.google/pubs/zanzibar-googles-consistent-global-authorization-system/']},
    {   'id': 'insecure-deserialization',
        'name': 'Insecure Deserialization / Type Confusion',
        'summary': 'The application reconstructs rich, typed, in-memory objects (with behavior, '
                   'not just data) from an untrusted serialized byte stream. Because the '
                   'serializer is a general object-graph builder that can instantiate arbitrary '
                   'types and trigger their lifecycle callbacks (constructors, __wakeup, '
                   'readObject, finalizers), the attacker supplies a payload that, upon '
                   "deserialization, chains existing 'gadget' methods in the classpath into "
                   'arbitrary code execution or logic subversion.',
        'why_it_recurs': 'Native serialization formats (Java, .NET, PHP, Python pickle, Ruby '
                         'Marshal) were designed for convenience and trust, conflating data '
                         'transport with object instantiation and executing type-defined callbacks '
                         'during decoding. Developers reach for them because they round-trip '
                         'objects for free, gadget chains live in ubiquitous libraries (so the app '
                         "author never wrote the vulnerable code), and 'just deserialize the "
                         "request' looks innocuous. Type confusion recurs whenever a decoder "
                         'trusts a caller-supplied type tag.',
        'derived_vuln_classes': [   'Java/.NET/PHP object-injection RCE (ysoserial-style gadget '
                                    'chains)',
                                    'Python pickle / PyYAML / Ruby Marshal RCE',
                                    'property-oriented programming (POP) chains',
                                    'type confusion via polymorphic JSON type hints (e.g. Jackson '
                                    'polymorphic deserialization)',
                                    'prototype pollution (JS object-graph corruption)',
                                    'PHP phar:// deserialization'],
        'systemic_fix': 'Never deserialize untrusted data into live objects. Use data-only '
                        'interchange formats with no code/type binding (JSON/Protobuf/CBOR) parsed '
                        'into plain records, then validate against an explicit schema before '
                        'constructing domain objects. If native serialization is unavoidable: '
                        'enforce a strict allow-list of deserializable classes (JEP 290 / '
                        'ObjectInputFilter), disable polymorphic type handling, sign+MAC the blob '
                        'so only server-produced state round-trips, and run decoders with least '
                        'privilege. Separate data decoding from behavior instantiation.',
        'references': [   'https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data',
                          'https://github.com/frohoff/ysoserial',
                          'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/',
                          'https://cwe.mitre.org/data/definitions/502.html',
                          'https://portswigger.net/web-security/deserialization']},
    {   'id': 'state-desync-race',
        'name': 'State Desynchronization & Race Conditions',
        'summary': 'Security decisions assume the system moves through a linear, atomic sequence '
                   'of states, but the check and the use of a resource are separated in time '
                   '(TOCTOU) or the same logical state is mutated concurrently. An attacker '
                   "exploits the sub-state 'window' between validation and action, or drives two "
                   "components' state machines out of sync, so an invariant that held at check "
                   'time is false at use time.',
        'why_it_recurs': 'Distributed and concurrent systems have no free atomicity: every '
                         'check-then-act is two operations across a network, a database, and '
                         "multiple threads, and the developer's mental model is a single-threaded "
                         'state machine that does not exist at runtime. Frameworks hide '
                         'concurrency, connection pooling and async multiply the parallelism, and '
                         'races are non-deterministic so they pass tests and review. Modern '
                         'techniques (single-packet attack) shrink the window to microseconds, '
                         'making races broadly practical rather than theoretical.',
        'derived_vuln_classes': [   'TOCTOU file/permission races',
                                    'limit-overrun / double-spend (redeeming a coupon or '
                                    'withdrawal N times)',
                                    'auth/session state desync & multi-step flow bypass',
                                    'HTTP request smuggling as a state-desync between hops',
                                    'idempotency-key and payment races',
                                    'signup / MFA-enrollment race conditions',
                                    'cache poisoning via response desync'],
        'systemic_fix': 'Make check-and-act atomic and serialized around the invariant: database '
                        'transactions with proper isolation (SELECT ... FOR UPDATE, unique '
                        'constraints, atomic compare-and-swap), idempotency keys, '
                        'optimistic/pessimistic locking, single-owner state machines with explicit '
                        'valid transitions, and rate/limit enforcement inside the same atomic unit '
                        'as the decrement. Enforce invariants in the datastore (constraints) '
                        'rather than by application-level ordering; assume every window can be hit '
                        'concurrently.',
        'references': [   'https://portswigger.net/research/smashing-the-state-machine',
                          'https://cwe.mitre.org/data/definitions/367.html',
                          'https://cwe.mitre.org/data/definitions/362.html',
                          'https://owasp.org/www-community/vulnerabilities/Race_Conditions',
                          'https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack']},
    {   'id': 'insecure-defaults-misconfiguration',
        'name': 'Insecure Defaults & Misconfiguration',
        'summary': 'The vulnerability is not in code the developer wrote but in the configuration '
                   'space of the components they assembled: a default password, an open admin '
                   'panel, a permissive CORS or S3 bucket policy, verbose error pages, an enabled '
                   'debug endpoint, an unauthenticated management port. The insecure state is '
                   "reachable because 'works out of the box' was prioritized over 'safe out of the "
                   "box'.",
        'why_it_recurs': 'Software is optimized for a frictionless first-run, so vendors ship '
                         'permissive defaults (enabled features, wildcard access, sample accounts) '
                         'to minimize support tickets; security is opt-in and the configuration '
                         'surface grows combinatorially with every added component, framework, and '
                         'cloud primitive. Nobody reads every config knob, defaults change '
                         'silently across versions, and the person deploying is rarely the one who '
                         'understands the security implications of each toggle. The safe path '
                         'requires positive effort; the unsafe path is the path of least '
                         'resistance.',
        'derived_vuln_classes': [   'default/blank credentials & sample accounts',
                                    'exposed admin/actuator/debug endpoints',
                                    'overly permissive CORS (Access-Control-Allow-Origin: * with '
                                    'credentials)',
                                    'public cloud storage buckets & IAM over-permission',
                                    'directory listing & verbose stack traces',
                                    'missing security headers (HSTS, CSP, cookie flags)',
                                    'unpatched/EOL components left enabled',
                                    'TLS misconfiguration & weak cipher suites'],
        'systemic_fix': 'Secure-by-default and secure-by-design: ship products locked down '
                        '(deny-by-default, no default creds, features off until enabled), and make '
                        'deployed configuration declarative, version-controlled, and continuously '
                        'verified. Infrastructure-as-code with policy-as-code gates (CSPM, config '
                        'scanners, CIS benchmarks in CI), hardened golden images, automatic drift '
                        "detection, and minimal attack surface (remove, don't just disable). Treat "
                        'configuration as code subject to the same review and testing as source.',
        'references': [   'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
                          'https://cwe.mitre.org/data/definitions/1188.html',
                          'https://cwe.mitre.org/data/definitions/16.html',
                          'https://www.cisecurity.org/cis-benchmarks',
                          'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html']},
    {   'id': 'memory-safety',
        'name': 'Memory Safety (Native Code)',
        'summary': 'In languages without automatic bounds/lifetime enforcement, program-controlled '
                   'operations on memory (indexing, pointer arithmetic, allocation lifetime) can '
                   'read or write outside the intended object, letting attacker-controlled data '
                   'corrupt adjacent memory, control-flow structures, or type invariants. The '
                   "abstraction 'a buffer of size N' is not enforced by the machine, so length is "
                   'just a convention the attacker violates.',
        'why_it_recurs': 'C/C++ deliberately trade safety for control and remain the substrate of '
                         'OSes, runtimes, parsers, and browsers, so decades of new code keep '
                         'entering the unsafe substrate. Manual memory management makes every '
                         'allocation a potential lifetime bug, humans cannot track aliasing and '
                         'bounds across large codebases, and the same properties that make these '
                         'languages fast (no runtime checks) make them unsafe. Microsoft and '
                         'Google independently found ~70% of their critical CVEs are memory-safety '
                         'issues, and legacy code cannot be rewritten wholesale.',
        'derived_vuln_classes': [   'stack/heap buffer overflow',
                                    'use-after-free & double-free',
                                    'out-of-bounds read (e.g. Heartbleed)',
                                    'integer overflow leading to undersized allocation',
                                    'type confusion (native)',
                                    'uninitialized-memory disclosure',
                                    'format-string vulnerabilities',
                                    'off-by-one / boundary errors'],
        'systemic_fix': 'Eliminate the class by construction with memory-safe languages (Rust, Go, '
                        'managed runtimes) for new code and rewrites of critical attack surface; '
                        'where native code must remain, deploy defense-in-depth mitigations that '
                        'raise exploitation cost (ASLR, DEP/NX, stack canaries, CFI, hardware '
                        'memory tagging/MTE, sandboxing) and aggressive detection '
                        '(ASan/fuzzing/formal verification). The strategic fix is a substrate '
                        'migration to languages that enforce bounds and lifetimes at compile time, '
                        'not per-bug patching.',
        'references': [   'https://www.memorysafety.org/docs/memory-safety/',
                          'https://github.com/microsoft/MSRC-Security-Research/blob/master/presentations/2019_02_BlueHatIL/2019_01%20-%20BlueHatIL%20-%20Trends%2C%20challenge%2C%20and%20shifts%20in%20software%20vulnerability%20mitigation.pdf',
                          'https://www.cisa.gov/resources-tools/resources/case-memory-safe-roadmaps',
                          'https://cwe.mitre.org/data/definitions/119.html',
                          'https://cwe.mitre.org/data/definitions/416.html']},
    {   'id': 'cryptographic-misuse',
        'name': 'Cryptographic Misuse',
        'summary': 'The cryptographic primitives are sound but are composed, parameterized, or '
                   'trusted incorrectly: the attacker exploits how crypto is used, not the math. '
                   'This spans trusting attacker-controlled algorithm/parameter fields, leaking a '
                   'decryption/verification oracle, reusing nonces/IVs, predictable randomness, '
                   'and using fast hashes for passwords. Crypto fails at the joints between '
                   'primitives and the application.',
        'why_it_recurs': 'Cryptography has a brutal usability gap: correct construction requires '
                         'understanding of oracles, malleability, nonce discipline, and '
                         'constant-time comparison that general developers lack, while libraries '
                         'historically expose dangerous low-level knobs (raw ECB, caller-selected '
                         'JWT alg, unauthenticated encryption) with footgun defaults. The failure '
                         'modes are silent (the ciphertext still decrypts, the token still '
                         'validates) so misuse passes functional tests, and each new format (JWT, '
                         'JWE, SAML) re-litigates the same algorithm-agility and oracle mistakes.',
        'derived_vuln_classes': [   'JWT alg=none & RS256->HS256 key-confusion',
                                    'padding-oracle attacks (CBC, PKCS#7; POODLE-class)',
                                    'predictable/weak randomness (guessable tokens, IVs, session '
                                    'IDs)',
                                    'nonce/IV reuse (CTR, GCM catastrophic)',
                                    'unauthenticated encryption / ciphertext malleability',
                                    'fast-hash / unsalted password storage',
                                    'timing side channels in comparison/verification',
                                    'hardcoded keys & static IVs'],
        'systemic_fix': 'Use misuse-resistant, high-level APIs that make the wrong thing hard: '
                        "authenticated encryption only (AEAD, libsodium/NaCl 'boxes'), no "
                        'caller-selectable algorithms (pin the alg server-side, reject alg from '
                        'the token), CSPRNGs for all security tokens, memory-hard password hashes '
                        '(argon2/scrypt/bcrypt), and constant-time comparisons. Remove algorithm '
                        'agility where possible, key by role not by attacker input, and prefer '
                        'opinionated libraries over primitive toolkits so the secure path is the '
                        'only path.',
        'references': [   'https://portswigger.net/web-security/jwt',
                          'https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/',
                          'https://en.wikipedia.org/wiki/Padding_oracle_attack',
                          'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
                          'https://cwe.mitre.org/data/definitions/347.html']},
    {   'id': 'network-position-abuse',
        'name': 'Network-Position Abuse / Implicit Network Trust',
        'summary': 'Security is granted based on where a request appears to originate (internal '
                   'network, localhost, a specific source IP, a resolved hostname) rather than on '
                   'a verified, authenticated credential. Because network position is forgeable or '
                   're-bindable, an attacker who can make a request emanate from a trusted vantage '
                   'point, or change what a name resolves to after a check, inherits the trust the '
                   'network placement confers.',
        'why_it_recurs': "The classic perimeter model equates 'inside the firewall' with "
                         "'trusted', so internal services, admin panels, cloud metadata endpoints, "
                         'and databases skip authentication entirely, assuming the network is the '
                         'boundary. Naming is late-bound (DNS is checked once but used again '
                         'later), server-side request initiators run inside that trusted zone, and '
                         'flat internal networks mean one foothold grants broad reach. The '
                         "assumption 'this came from inside, so it's safe' is baked into decades "
                         'of network architecture.',
        'derived_vuln_classes': [   'SSRF pivoting to internal services & cloud metadata (IMDS)',
                                    'DNS rebinding (TOCTOU on name resolution)',
                                    'trust of source IP / X-Forwarded-For for authz',
                                    'unauthenticated internal/east-west services & lateral '
                                    'movement',
                                    'localhost / 127.0.0.1 trust bypass',
                                    'VPN/perimeter over-trust'],
        'systemic_fix': 'Adopt zero-trust: authenticate and authorize every request on its own '
                        "cryptographic merits regardless of network origin, so 'inside' confers "
                        'nothing. Mutually-authenticated TLS (mTLS) and signed service identities '
                        'for east-west traffic, per-request tokens for metadata services (IMDSv2), '
                        'egress filtering + allow-listed outbound destinations for SSRF '
                        'containment, DNS-rebinding defenses (validate resolved IP at connect '
                        'time, pin, reject private ranges), and micro-segmentation. Trust the '
                        'credential, never the location.',
        'references': [   'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/',
                          'https://crypto.stanford.edu/dns/dns-rebinding.pdf',
                          'https://en.wikipedia.org/wiki/DNS_rebinding',
                          'https://csrc.nist.gov/pubs/sp/800/207/final',
                          'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html']},
    {   'id': 'supply-chain-transitive-trust',
        'name': 'Supply Chain / Transitive Trust',
        'summary': 'The application transitively trusts code, artifacts, and build infrastructure '
                   'it did not author and cannot fully audit: third-party dependencies, their '
                   'dependencies, package registries, CI/CD pipelines, and update channels. A '
                   'compromise anywhere in this transitive-trust graph executes with the full '
                   'privilege of the consuming application, and the consumer never wrote or '
                   'reviewed the malicious line.',
        'why_it_recurs': 'Modern software is assembled, not written: a typical app pulls in '
                         'thousands of transitive packages, each an implicit trust decision, and '
                         'the economics reward reuse over auditing. Package managers resolve names '
                         'to code automatically (enabling substitution and typosquatting), build '
                         'systems run untrusted code with high privilege, and the trust is '
                         'transitive and unbounded, so one weak maintainer or one poisoned '
                         "registry entry propagates everywhere. You cannot review what you don't "
                         'know you depend on.',
        'derived_vuln_classes': [   'dependency confusion / namespace substitution',
                                    'typosquatting & malicious packages',
                                    'compromised maintainer / account takeover (protestware, '
                                    'backdoors)',
                                    'build-pipeline / CI compromise (SolarWinds-class)',
                                    'poisoned base images & artifacts',
                                    'malicious/vulnerable transitive dependencies (Log4Shell-class '
                                    'blast radius)',
                                    'compromised update channels / code-signing key theft'],
        'systemic_fix': 'Establish verifiable provenance and least-privilege for the whole '
                        'software lifecycle: pin and lockfile every dependency, generate and '
                        'consume SBOMs, verify signatures/attestations (Sigstore, SLSA provenance '
                        'levels), prefer private-registry namespace ownership to defeat confusion '
                        'attacks, run builds hermetically with minimal permissions and ephemeral '
                        'credentials, and continuously scan (SCA) for known-vuln and anomalous '
                        'packages. Shift from trusting names to trusting cryptographically '
                        'attested artifacts and reproducible builds.',
        'references': [   'https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610',
                          'https://slsa.dev/',
                          'https://www.cisa.gov/news-events/alerts/2021/12/11/apache-log4j-vulnerability-guidance',
                          'https://www.sigstore.dev/',
                          'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/']},
    {   'id': 'implicit-trust-client-metadata',
        'name': 'Implicit Trust of Client-Controlled Input & Metadata',
        'summary': 'The server treats request metadata and structure that are actually '
                   'attacker-controlled as if they were authoritative context: the Host header, '
                   'X-Forwarded-* headers, referer, filenames, content-type, and the very set of '
                   'fields in a request body. Because these look like '
                   "framework/infrastructure-provided context rather than 'user input', developers "
                   'forget they are fully forgeable and use them to make security or routing '
                   'decisions, or to bind data straight into internal objects.',
        'why_it_recurs': 'Everything in an HTTP request is client-controlled, but frameworks '
                         'present metadata (headers, absolute URLs, parsed params) as ambient '
                         'environment, blurring the line between trusted server context and '
                         'untrusted client claims. Convenience features actively invert the safe '
                         'default: ORMs auto-bind every submitted field to model attributes (mass '
                         'assignment), password-reset code trusts the Host header to build links, '
                         "reverse proxies inject spoofable forwarding headers. The framework's "
                         'ergonomics make trusting client metadata the default.',
        'derived_vuln_classes': [   'Host-header attacks (password-reset poisoning, cache '
                                    'poisoning, routing-based SSRF)',
                                    'X-Forwarded-For / -Host / -Proto spoofing for authz or '
                                    'logging bypass',
                                    'mass assignment / auto-binding / over-posting (privilege '
                                    'fields, isAdmin)',
                                    'web cache poisoning via unkeyed inputs',
                                    'open redirect via trusted-looking parameters',
                                    'content-type / filename trust (upload MIME spoofing)',
                                    'referer-based access control bypass'],
        'systemic_fix': 'Treat all request-derived data, including metadata, as untrusted by '
                        'default and bind capabilities explicitly: allow-list expected Host values '
                        'and derive absolute URLs from server config, not from the request; only '
                        'trust forwarding headers from known proxies at a controlled hop; use '
                        'explicit input-to-field allow-lists (DTOs / strong-params / read-only '
                        "attributes) so no request can set a field the developer didn't opt in; "
                        'and re-derive security-relevant context (identity, tenant, origin) from '
                        'server-side state, never from a client-supplied claim.',
        'references': [   'https://portswigger.net/research/practical-http-host-header-attacks',
                          'https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html',
                          'https://cwe.mitre.org/data/definitions/915.html',
                          'https://portswigger.net/research/practical-web-cache-poisoning',
                          'https://cwe.mitre.org/data/definitions/807.html']},
    {   'id': 'ambient-authority-excess-privilege',
        'name': 'Ambient Authority & Excess Privilege (Least-Privilege Violation)',
        'summary': 'Components run with far more authority than any single operation needs, and '
                   'that authority is ambient — automatically available by virtue of '
                   'identity/context rather than explicitly granted per-task. When any part of an '
                   'over-privileged component is subverted, the attacker inherits its entire '
                   'authority. This is the amplifier that turns a small foothold (an injection, an '
                   'SSRF, a deserialization bug) into total compromise.',
        'why_it_recurs': 'Granting broad, standing privilege is operationally easier than scoping '
                         "narrow, task-specific capabilities: it avoids 'permission denied' "
                         'friction during development, and identity-based access control (this '
                         'service account can touch everything) is the default model in OSes and '
                         'clouds. Least privilege requires knowing exactly what each path needs, '
                         'which is tedious and brittle as code evolves, so privileges accrete and '
                         'are never revoked. The design keeps authority ambient and coarse, so '
                         "every other vulnerability's blast radius is maximal.",
        'derived_vuln_classes': [   'privilege escalation & lateral movement after initial '
                                    'foothold',
                                    'over-scoped API tokens / OAuth scopes / service accounts',
                                    'database accounts with full DDL/DML rights for read-only apps',
                                    'over-permissioned cloud IAM roles (wildcard '
                                    'actions/resources)',
                                    'container/process running as root',
                                    'SSRF/RCE impact amplification via ambient credentials',
                                    'excessive session/token lifetime & scope'],
        'systemic_fix': 'Enforce the Principle of Least Authority structurally: capability-based '
                        'access (a component can only reach objects it was explicitly handed, no '
                        'ambient reach), narrowly-scoped short-lived credentials, per-task IAM '
                        'roles with resource-level conditions, sandboxing/seccomp/least-privilege '
                        'containers, network egress restrictions, and privilege separation so a '
                        'compromise of one component yields minimal authority. Design so authority '
                        "must be granted, never assumed — making every other bug's blast radius "
                        'small.',
        'references': [   'https://www.cs.virginia.edu/~evans/cs551/saltzer/',
                          'http://www.erights.org/elib/capability/duals/myths.html',
                          'https://cwe.mitre.org/data/definitions/250.html',
                          'https://cwe.mitre.org/data/definitions/272.html',
                          'https://csrc.nist.gov/glossary/term/least_privilege']}]

VULN_TOOLS: list[dict] = [   {   'id': 'marshalsec',
        'name': 'marshalsec',
        'category': 'deserialization',
        'target': 'Java deser across JSON/YAML/XML (Jackson, Fastjson, SnakeYAML, XStream) and '
                  'JNDI injection',
        'summary': 'Research toolkit showing non-native-Java formats are equally dangerous with '
                   'polymorphic typing enabled, and supplies the malicious LDAP/RMI reference '
                   'servers used to demonstrate JNDI injection (the Log4Shell-class mechanism).',
        'usage_note': 'Use the bundled LDAP/RMI servers only in a lab to understand JNDI-injection '
                      'root cause and test that lookups of untrusted URLs are blocked. Reference '
                      'for why polymorphic typing (SnakeYAML, Fastjson autotype) must be disabled.',
        'url': 'https://github.com/mbechler/marshalsec'},
    {   'id': 'ysoserial',
        'name': 'ysoserial',
        'category': 'deserialization',
        'target': 'Java insecure deserialization (gadget-chain RCE)',
        'summary': 'Generates payload objects abusing gadget chains in common Java libraries '
                   '(Commons-Collections, Spring, etc.) to achieve code execution when an app '
                   'deserializes attacker-controlled data. The canonical Java deser research '
                   'artifact.',
        'usage_note': 'For authorized testing, confirm whether a Java endpoint deserializes '
                      'untrusted input and demonstrate impact. The gadget catalog justifies '
                      'defenses: ObjectInputFilter allowlists, avoiding native serialization for '
                      'untrusted data, dependency hygiene.',
        'url': 'https://github.com/frohoff/ysoserial'},
    {   'id': 'ysoserial-net',
        'name': 'ysoserial.net',
        'category': 'deserialization',
        'target': '.NET insecure deserialization (BinaryFormatter, Json.NET TypeNameHandling, '
                  'LosFormatter/ViewState, ...)',
        'summary': '.NET counterpart to ysoserial: produces gadget payloads for the many .NET '
                   'serializers whose type-resolution features enable RCE, including ViewState '
                   '(__VIEWSTATE) payloads given leaked machineKeys.',
        'usage_note': 'Use to validate .NET deserialization sinks and ViewState integrity (common '
                      'when validationKey/decryptionKey leak). Verify defenses: disable '
                      'BinaryFormatter, avoid TypeNameHandling.All, enforce ViewState '
                      'MAC/encryption, rotate machineKeys.',
        'url': 'https://github.com/pwntester/ysoserial.net'},
    {   'id': 'feroxbuster',
        'name': 'feroxbuster',
        'category': 'fuzzing',
        'target': 'Recursive content discovery (directories/files)',
        'summary': 'A fast Rust forced-browsing tool that recurses automatically, handles '
                   'state/resume, and applies smart filtering. Complements ffuf when deep '
                   'recursive discovery is needed.',
        'usage_note': 'Use to inventory exposed paths on an authorized target; recursion depth and '
                      "filters help avoid rabbit holes. Results support a defensive 'what is "
                      "publicly reachable' review.",
        'url': 'https://github.com/epi052/feroxbuster'},
    {   'id': 'ffuf',
        'name': 'ffuf',
        'category': 'fuzzing',
        'target': 'Content/endpoint discovery, virtual-host fuzzing, parameter/value fuzzing',
        'summary': 'A very fast Go web fuzzer for directory/file discovery, vhost enumeration and '
                   'generic FUZZ-keyword fuzzing with rich matcher/filter logic. A workhorse for '
                   'mapping unlinked attack surface.',
        'usage_note': 'Use with curated wordlists (SecLists) to find forgotten admin panels, '
                      'backups and staging endpoints that should be removed or access-controlled. '
                      'Auto-calibration and response filters teach how to separate signal from '
                      'soft-404 noise.',
        'url': 'https://github.com/ffuf/ffuf'},
    {   'id': 'kiterunner',
        'name': 'kiterunner',
        'category': 'fuzzing',
        'target': 'API/route discovery for modern REST/GraphQL apps and API gateways',
        'summary': "Assetnote's tool that discovers API routes using route-aware wordlists derived "
                   'from real API specs (Swagger/OpenAPI), including correct methods, headers and '
                   'content-types, far more effective than directory brute-forcing against APIs.',
        'usage_note': 'Use to find undocumented/shadow API endpoints traditional content discovery '
                      'misses. Great for verifying an API gateway only exposes intended routes; '
                      'unexpected hits indicate shadow/zombie APIs to retire.',
        'url': 'https://github.com/assetnote/kiterunner'},
    {   'id': 'smuggler-suite',
        'name': 'smuggler.py / http-request-smuggler',
        'category': 'fuzzing',
        'target': 'HTTP request smuggling / desync (CL.TE, TE.CL, TE.TE, CL.0, HTTP/2 and '
                  'client-side desync)',
        'summary': 'smuggler.py (defparam) probes classic CL/TE desync variants; '
                   "http-request-smuggler (PortSwigger, from Kettle's desync research) is the Burp "
                   'extension detecting and confirming smuggling including newer HTTP/2 and CL.0 '
                   'variants.',
        'usage_note': 'Use only in authorized tests with care (desync probes can affect other '
                      'users of shared front-ends). Findings drive defenses: reject ambiguous '
                      'CL+TE requests at the front-end, prefer HTTP/2 end-to-end, disable risky '
                      'connection reuse.',
        'url': 'https://github.com/PortSwigger/http-request-smuggler'},
    {   'id': 'turbo-intruder',
        'name': 'Turbo Intruder',
        'category': 'fuzzing',
        'target': 'Race conditions (single-packet attack), high-rate fuzzing, timing-sensitive '
                  'logic flaws',
        'summary': "PortSwigger's scriptable, extremely high-throughput request engine "
                   'implementing the HTTP/2 single-packet attack to remove network jitter, the '
                   'standard for demonstrating limit-overrun / TOCTOU races (e.g. redeeming a '
                   'coupon twice).',
        'usage_note': 'Use to prove race conditions for a report and verify the fix (atomic '
                      'operations, row locking, idempotency keys). Its Python request model also '
                      'makes it a precise custom fuzzer under authorization.',
        'url': 'https://github.com/PortSwigger/turbo-intruder'},
    {   'id': 'commix',
        'name': 'Commix',
        'category': 'injection',
        'target': 'OS command injection (results-based, blind, time-based, file-based)',
        'summary': 'Automates detection/exploitation of command injection where user input is '
                   'concatenated into a shell invocation, enumerating technique per parameter and '
                   'context.',
        'usage_note': 'Ideal for confirming a suspected command-injection sink and '
                      'regression-testing a fix (input allowlisting, avoiding shell interpreters). '
                      'Its separator/encoding options illustrate why blocklists fail and '
                      'argument-array execution is correct.',
        'url': 'https://github.com/commixproject/commix'},
    {   'id': 'nosqlmap',
        'name': 'NoSQLMap',
        'category': 'injection',
        'target': 'NoSQL injection (MongoDB and similar), Mongo/Node misconfig checks',
        'summary': 'Automates detection of NoSQL/operator injection ($ne, $gt, $where) against '
                   'MongoDB-backed apps and JSON/REST endpoints where attacker-controlled '
                   'structure reaches the query.',
        'usage_note': 'Use to show why JSON body params must be type-validated and query operators '
                      'stripped. Project is older/less maintained, so verify findings manually. '
                      'Root cause is unsanitized structured input reaching the driver; fix is '
                      'server-side schema validation.',
        'url': 'https://github.com/codingo/NoSQLMap'},
    {   'id': 'jwt-tool-cracker',
        'name': 'jwt_tool / jwt-cracker',
        'category': 'jwt',
        'target': 'JWT flaws: alg:none, RS256->HS256 key confusion, weak HMAC secrets, kid/jku/x5u '
                  'injection, claim tampering',
        'summary': 'jwt_tool is the all-in-one JWT auditor (tampering, signature-bypass playbooks, '
                   'known-attack automation, RFC checks); jwt-cracker brute-forces weak HMAC '
                   'signing secrets to demonstrate insufficient key entropy.',
        'usage_note': 'Use jwt_tool to enumerate missing JWT controls (pin allowed alg, verify '
                      'sig, validate iss/aud/exp) and jwt-cracker to prove a guessable HMAC '
                      'secret. All techniques stem from trusting attacker-supplied header fields; '
                      'verify the server ignores them.',
        'url': 'https://github.com/ticarpi/jwt_tool'},
    {   'id': 'oast',
        'name': 'interactsh / Burp Collaborator',
        'category': 'oast',
        'target': 'Out-of-band testing: blind SSRF, blind XXE, blind injection/RCE via DNS/HTTP '
                  'callbacks',
        'summary': 'OAST servers that mint unique DNS/HTTP(S)/SMTP callback domains and log any '
                   'interaction, revealing vulnerabilities that produce no in-band response. '
                   'interactsh is open-source/self-hostable; Collaborator is the Burp-integrated '
                   'equivalent.',
        'usage_note': 'Essential for confirming blind/asynchronous bugs during authorized testing '
                      'and for detection engineering: the same callback pattern is what defenders '
                      'alert on (unexpected egress DNS to random subdomains). Self-host interactsh '
                      'to keep test data in-scope.',
        'url': 'https://github.com/projectdiscovery/interactsh'},
    {   'id': 'param-discovery-suite',
        'name': 'Arjun / ParamSpider / x8',
        'category': 'param-discovery',
        'target': 'Hidden GET/POST/JSON parameters and historical parameter surface',
        'summary': 'Arjun brute-forces valid parameters via response-diffing; ParamSpider mines '
                   'archived (Wayback) URLs for previously-seen parameters; x8 is a fast Rust '
                   'hidden-parameter tool with strong body/JSON support. Together they map the '
                   'full input surface.',
        'usage_note': 'Run early in an authorized assessment to inventory inputs before testing '
                      'each for injection. The Wayback approach (ParamSpider) also surfaces '
                      'deprecated endpoints that should be decommissioned, a useful defensive '
                      'audit.',
        'url': 'https://github.com/s0md3v/Arjun'},
    {   'id': 'param-miner',
        'name': 'Param Miner',
        'category': 'param-discovery',
        'target': 'Hidden request parameters/headers/cookies; web cache poisoning / '
                  'cache-deception inputs',
        'summary': 'Burp extension that guesses unlinked parameters, headers and cookies by '
                   'observing response deltas, and is the standard tool for discovering unkeyed '
                   "inputs behind web cache poisoning (Kettle's research).",
        'usage_note': 'Use to enumerate attack surface a crawler misses and to test cache keying. '
                      'Findings feed defense: normalize/allowlist inputs and ensure cache keys '
                      'include every input that influences the response.',
        'url': 'https://github.com/PortSwigger/param-miner'},
    {   'id': 'burp-suite',
        'name': 'Burp Suite',
        'category': 'proxy',
        'target': 'General web application testing platform (proxy, scanner, Intruder, Repeater, '
                  'extensions)',
        'summary': 'The industry-standard intercepting proxy and testing platform. Community gives '
                   'manual tools (Repeater/Intruder/Decoder); Professional adds active scanner, '
                   'Collaborator, and the BApp ecosystem (Param Miner, Turbo Intruder, InQL, '
                   'http-request-smuggler run inside it).',
        'usage_note': 'The hub for most manual authorized testing and for precisely '
                      "reproducing/triaging findings. For defenders it's invaluable to observe "
                      'exactly what a request/response looks like when validating a fix. Scope '
                      'config keeps testing in-bounds.',
        'url': 'https://portswigger.net/burp'},
    {   'id': 'mitmproxy',
        'name': 'mitmproxy',
        'category': 'proxy',
        'target': 'Interactive TLS-capable HTTP(S) interception, scripting, traffic analysis',
        'summary': 'An open-source, scriptable intercepting proxy with CLI/TUI/web interfaces and '
                   'a Python addon API. Excellent for programmatic request/response rewriting, '
                   'mobile/app traffic inspection, and automated test harnesses.',
        'usage_note': 'Use to inspect and script traffic during authorized testing, reproduce API '
                      'behavior, and build repeatable transforms for regression-testing a fix. Its '
                      'Python addons make it a clean, auditable automation alternative to a GUI.',
        'url': 'https://github.com/mitmproxy/mitmproxy'},
    {   'id': 'graphql-suite',
        'name': 'GraphQLmap / clairvoyance / InQL',
        'category': 'recon',
        'target': 'GraphQL: schema/introspection recovery, field/injection testing, batching '
                  'abuse, authz/IDOR gaps',
        'summary': 'clairvoyance reconstructs a schema even when introspection is disabled (via '
                   'field-suggestion inference); GraphQLmap is an interactive console for '
                   'enumerating/exploiting endpoints; InQL is the Burp extension for GraphQL '
                   'scanning and request generation.',
        'usage_note': 'Use to audit that introspection is disabled in prod, per-field '
                      'authorization is enforced (GraphQL bypasses REST endpoint auth), and '
                      'depth/complexity limits exist against batching/DoS. clairvoyance shows why '
                      'disabling introspection alone is insufficient.',
        'url': 'https://github.com/nikitastupin/clairvoyance'},
    {   'id': 'reference-dbs',
        'name': 'PayloadsAllTheThings / HackTricks / PortSwigger Web Security Academy / SecLists',
        'category': 'reference-db',
        'target': 'Cross-cutting reference: payload patterns, methodology, root-cause writeups, '
                  'and wordlists for every class above',
        'summary': 'The canonical public knowledge bases: PayloadsAllTheThings (per-vuln '
                   'technique/defense cheatsheets), HackTricks (methodology encyclopedia), '
                   'PortSwigger Web Security Academy (authoritative labs/explanations from the '
                   'researchers behind many techniques), and SecLists (standard wordlists powering '
                   'ffuf/feroxbuster/kiterunner/Arjun).',
        'usage_note': 'Primary sourcing for a referenced, defensive catalog: use the Academy for '
                      'root-cause and remediation writeups, PayloadsAllTheThings/HackTricks for '
                      'technique context, and SecLists as the vetted wordlist source. Cite the '
                      'specific page when documenting a finding or fix.',
        'url': 'https://github.com/swisskyrepo/PayloadsAllTheThings'},
    {   'id': 'corsy',
        'name': 'Corsy',
        'category': 'scanner',
        'target': 'CORS misconfigurations (reflected origin, null origin, wildcard+credentials, '
                  'prefix/suffix trust)',
        'summary': 'Scans for permissive Access-Control-Allow-Origin logic that lets malicious '
                   'sites read authenticated responses, enumerating the common misconfiguration '
                   'patterns quickly.',
        'usage_note': 'Use to audit that ACAO reflects only an allowlist and never pairs '
                      'wildcard/reflected origins with Allow-Credentials. Each check maps directly '
                      'to a concrete server-side header-policy fix.',
        'url': 'https://github.com/s0md3v/Corsy'},
    {   'id': 'dalfox',
        'name': 'Dalfox',
        'category': 'scanner',
        'target': 'Cross-Site Scripting (reflected/stored/DOM), parameter analysis, CSP/eval sink '
                  'review',
        'summary': 'A fast Go XSS scanner doing parameter analysis, context-aware payload '
                   'selection and headless DOM verification to cut false positives. Strong at '
                   'proving exploitability rather than mere reflection.',
        'usage_note': 'Use to confirm reflected/DOM XSS on authorized targets and regression-test '
                      'output-encoding/CSP fixes. Its context detection illustrates why the '
                      'correct defense is context-aware output encoding plus a strong CSP, not '
                      'input blocklists.',
        'url': 'https://github.com/hahwul/dalfox'},
    {   'id': 'nuclei',
        'name': 'Nuclei',
        'category': 'scanner',
        'target': 'Known CVEs, misconfigurations, exposures, default creds, takeovers via '
                  'community YAML templates',
        'summary': "ProjectDiscovery's template-driven scanner: thousands of community-maintained, "
                   'human-readable YAML signatures across HTTP/DNS/TCP/SSL. The de-facto standard '
                   'for scalable, low-false-positive checks.',
        'usage_note': 'Ideal for defensive continuous scanning of your own assets and for '
                      'confirming a specific CVE is present/patched. Templates are auditable, so '
                      'you can read exactly what each check does and author detections for '
                      'internal issues.',
        'url': 'https://github.com/projectdiscovery/nuclei'},
    {   'id': 'ghauri',
        'name': 'Ghauri',
        'category': 'sqli',
        'target': 'SQL injection (boolean/time/error/UNION), incl. some WAF/CSRF-token flows',
        'summary': 'A faster, lighter SQLi detection/exploitation tool built to cut false '
                   'positives and handle cases sqlmap struggles with. Good cross-check for '
                   'confirming a suspected injection.',
        'usage_note': 'Use as a second opinion when triaging a candidate injection. Its evasion '
                      'features are the same class as sqlmap tamper scripts; studying them shows '
                      'why parameterized queries defeat the whole category.',
        'url': 'https://github.com/r0oth3x49/ghauri'},
    {   'id': 'sqlmap',
        'name': 'sqlmap',
        'category': 'sqli',
        'target': 'SQL injection (MySQL, PostgreSQL, MSSQL, Oracle, SQLite, etc.)',
        'summary': 'The reference open-source engine for detecting/exploiting SQL injection. '
                   'Automates boolean/error/time/UNION/stacked and out-of-band inference, DBMS '
                   'fingerprinting, data extraction, and file/OS access where the DB permits.',
        'usage_note': 'Defensively, confirm a parameter is NOT injectable and reproduce reported '
                      'findings for triage. --level/--risk control payload breadth; --tamper '
                      'scripts illustrate how encoding/comment/case tricks defeat naive signature '
                      'WAFs, informing rule hardening. Authorized targets only.',
        'url': 'https://github.com/sqlmapproject/sqlmap'},
    {   'id': 'gopherus',
        'name': 'Gopherus',
        'category': 'ssrf',
        'target': 'SSRF-to-RCE/data theft against internal services via gopher:// (Redis, '
                  'Memcached, MySQL, Postgres, FastCGI, SMTP, Zabbix)',
        'summary': 'Generates gopher:// payloads letting an SSRF primitive speak raw TCP to '
                   "internal backends, turning a 'fetch internal URL' bug into command execution "
                   'or data manipulation against unauthenticated internal services.',
        'usage_note': "Use in authorized testing to demonstrate real SSRF impact (why 'it only "
                      "fetches URLs' is not low severity). Documents why internal services need "
                      'auth and why URL schemes must be allowlisted (block gopher/file/dict) at '
                      'the sink.',
        'url': 'https://github.com/tarunkant/Gopherus'},
    {   'id': 'tplmap-sstimap',
        'name': 'tplmap / SSTImap',
        'category': 'ssti',
        'target': 'Server-Side Template Injection (Jinja2, Twig, Freemarker, Velocity, Mako, ERB, '
                  '...) and downstream RCE',
        'summary': 'tplmap pioneered automated SSTI detection across many engines; SSTImap is a '
                   'modern maintained successor with wider coverage. Both fingerprint the engine '
                   'from probe responses and map SSTI to code/command execution where the sandbox '
                   'allows.',
        'usage_note': 'Use to prove user input reaches a template compiler (the root cause) and to '
                      'verify remediation (render untrusted data as data, never template source). '
                      'The polyglot probes teach how per-engine sandbox escapes work.',
        'url': 'https://github.com/vladko312/SSTImap'},
    {   'id': 'nowafpls',
        'name': 'nowafpls',
        'category': 'waf',
        'target': 'WAF request-size/inspection-limit blind spots (conceptual evasion via padding)',
        'summary': 'Assetnote Burp extension demonstrating that many WAFs stop inspecting request '
                   'bodies past a size threshold; benign junk padding can push the real payload '
                   'beyond the inspection window, illustrating a WAF architectural limit.',
        'usage_note': 'Value is defensive: it proves WAFs are mitigation, not a fix, and reveals a '
                      "real config gap. Verify your WAF's max-inspected-body-size and ensure "
                      'origin apps are patched regardless. Not a substitute for fixing the '
                      'underlying vuln.',
        'url': 'https://github.com/assetnote/nowafpls'},
    {   'id': 'origin-discovery',
        'name': 'CloudFail / bypass-firewalls-by-DNS-history',
        'category': 'waf',
        'target': 'Uncovering the real origin IP behind a WAF/CDN so the proxy can be bypassed '
                  'entirely',
        'summary': 'Both exploit that a CDN/WAF only protects traffic routed through it: they mine '
                   'DNS history, crt.sh, misconfigured subdomains and historical records to find '
                   "the origin server's real IP, which may accept direct connections and skip the "
                   'WAF.',
        'usage_note': 'Defensive lesson: WAF protection is void if the origin IP is directly '
                      'reachable. Use to check your own exposure, then lock the origin firewall to '
                      "accept only the CDN's IP ranges (and rotate the origin IP if it leaked). A "
                      'recon/config-audit aid.',
        'url': 'https://github.com/vincentcox/bypass-firewalls-by-DNS-history'},
    {   'id': 'wafw00f',
        'name': 'wafw00f',
        'category': 'waf',
        'target': 'WAF/WAAP fingerprinting (identifies which WAF/CDN fronts a site)',
        'summary': 'Sends benign probes and matches response fingerprints to identify the specific '
                   'WAF product (Cloudflare, Akamai, AWS WAF, Imperva, F5, etc.). The standard '
                   'first step in understanding perimeter defenses.',
        'usage_note': 'For defenders, run against your own assets to confirm the WAF is engaged '
                      'and identifiable, and to see what an attacker learns externally. Knowing '
                      'the product informs which tuning/managed-rule sets to review.',
        'url': 'https://github.com/EnableSecurity/wafw00f'},
    {   'id': 'xxe-tools',
        'name': 'XXEinjector / oxml_xxe',
        'category': 'xxe',
        'target': 'XML External Entity injection: file disclosure, SSRF, OOB exfiltration, and XXE '
                  'in Office/OOXML/SVG uploads',
        'summary': 'XXEinjector automates classic and out-of-band XXE (incl. blind via hosted DTD) '
                   'for file read and SSRF; oxml_xxe injects XXE payloads into XML-based documents '
                   '(docx/xlsx/pptx, SVG) to test upload parsers.',
        'usage_note': 'Use to confirm an XML parser resolves external entities/DTDs (the root '
                      'cause) and to test easily-overlooked document-parsing paths. Verify the fix '
                      'by disabling DOCTYPE/external-entity/parameter-entity resolution in parser '
                      'config.',
        'url': 'https://github.com/enjoiz/XXEinjector'}]
