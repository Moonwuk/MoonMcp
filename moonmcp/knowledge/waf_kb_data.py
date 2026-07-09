"""WAF (Web Application Firewall) reference knowledge base — structured data.

Three kinds of entry: ``how-it-works`` (rule engines, models, cloud WAFs),
``fingerprint`` (identify the vendor from response headers/cookies/blocking
pages — each carries an ``indicator`` string) and ``bypass-technique``
(CONCEPTUAL, defensive: understanding evasion to detect & defend — normalization
and parser differentials, encoding layers, HTTP-parameter-pollution, origin-IP
discovery, etc.). Reference material, not a copy-paste attack kit.

Complements the active ``waf_detect`` / ``waf_efficacy`` tools. Compiled from
OWASP CRS/ModSecurity docs, PortSwigger research, wafw00f signatures and vendor docs.
"""

from __future__ import annotations

WAF_ENTRIES: list[dict] = [   {   'id': 'hiw-aws-waf',
        'name': 'AWS WAF architecture',
        'category': 'how-it-works',
        'summary': 'Cloud WAF attached to CloudFront/ALB/API Gateway/AppSync where a Web ACL '
                   'evaluates ordered rules and rule groups, each ALLOW/BLOCK/COUNT/CAPTCHA, using '
                   'a Web ACL Capacity Unit budget.',
        'detail': 'AWS WAF is configured as a Web ACL associated with a resource (CloudFront '
                  'distribution, Application Load Balancer, API Gateway, AppSync, Cognito, App '
                  'Runner). A Web ACL contains ordered rules and rule groups evaluated top-down; '
                  'each rule has a statement (match conditions like byte-match, SQLi, XSS, '
                  'size-constraint, geo, IP set, rate-based, label matching) and an action (Allow, '
                  'Block, Count, CAPTCHA, Challenge). AWS Managed Rule Groups (e.g. Core rule set '
                  'AWSManagedRulesCommonRuleSet, SQLi, Known Bad Inputs, IP reputation, Bot '
                  'Control, ATP) provide negative-model coverage; Marketplace vendors sell managed '
                  'groups. Capacity is governed by WCUs (Web ACL Capacity Units), capping rule '
                  'complexity. Body inspection historically had an 8 KB limit (now expandable to '
                  'larger sizes on some resources) — an important inspection-size consideration. '
                  'Logging goes to CloudWatch/S3/Kinesis Firehose.',
        'applies_to': ['AWS WAF', 'CloudFront', 'inspection size limits'],
        'indicator': '',
        'references': [   'https://docs.aws.amazon.com/waf/latest/developerguide/what-is-aws-waf.html',
                          'https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-list.html',
                          'https://docs.aws.amazon.com/waf/latest/developerguide/web-request-body-inspection.html']},
    {   'id': 'hiw-cloudflare-waf',
        'name': 'Cloudflare WAF architecture',
        'category': 'how-it-works',
        'summary': 'Reverse-proxy edge WAF combining Managed Rules (Cloudflare + OWASP CRS '
                   'rulesets), ML-based attack scoring, rate limiting, and bot management across '
                   "Cloudflare's global network.",
        'detail': 'Cloudflare operates as an inline reverse proxy at its edge PoPs. The WAF '
                  'layers: (1) Managed Rulesets — the Cloudflare Managed Ruleset and a Cloudflare '
                  'OWASP Core Ruleset implementation, each rule set to log/block/challenge; the '
                  'OWASP ruleset uses a score with an adjustable paranoia-level-like sensitivity '
                  'and threshold. (2) WAF Attack Score — a machine-learning model producing 1-99 '
                  'scores for SQLi/XSS/RCE that catches obfuscated variants regex misses. (3) '
                  'Custom Rules (firewall rules with wirefilter expressions), Rate Limiting Rules, '
                  'and Bot Management (ML + heuristics, emits bot scores). Actions include block, '
                  'managed challenge, JS challenge, and log. Because it is DNS/proxy fronted, its '
                  'protection is only effective if the origin IP is hidden (see origin-IP '
                  'discovery). Enterprise adds API Shield (schema validation = positive model) and '
                  'leaked-credential checks.',
        'applies_to': ['Cloudflare'],
        'indicator': '',
        'references': [   'https://developers.cloudflare.com/waf/',
                          'https://developers.cloudflare.com/waf/managed-rules/',
                          'https://developers.cloudflare.com/waf/detections/attack-score/']},
    {   'id': 'hiw-crs-paranoia-scoring',
        'name': 'OWASP CRS: paranoia levels and anomaly scoring',
        'category': 'how-it-works',
        'summary': 'The Core Rule Set groups negative-model rules into paranoia levels (PL1-PL4) '
                   'and uses collaborative anomaly scoring to decide blocking, trading detection '
                   'for false positives.',
        'detail': 'OWASP Core Rule Set (CRS) is the reference generic attack-detection ruleset '
                  '(SQLi, XSS, RCE, LFI/RFI, protocol violations). Two operating modes: '
                  'traditional (self-contained, each rule blocks) and the default anomaly-scoring '
                  'mode. In anomaly scoring, matching rules add to an inbound (and outbound) '
                  'anomaly score by severity (CRITICAL=5, ERROR=4, WARNING=3, NOTICE=2). At the '
                  'end of phase 2 a blocking-evaluation rule denies if the accumulated score meets '
                  'the inbound threshold (default 5). Paranoia Levels tune aggressiveness: PL1 '
                  '(default, few false positives), PL2, PL3, PL4 (very strict, expects heavy '
                  'tuning). Higher PL enables more/stricter rules that catch obfuscation but raise '
                  'false positives. Operators tune by raising thresholds, writing rule exclusions '
                  '(before/after CRS via SecRuleUpdateTargetById or exclusion rule ranges), and '
                  'sampling percentage. This scoring model is what lets a single '
                  'suspicious-but-benign signal pass while several combined signals block.',
        'applies_to': ['OWASP CRS', 'ModSecurity', 'Coraza', 'false positives'],
        'indicator': '',
        'references': [   'https://coreruleset.org/docs/concepts/anomaly_scoring/',
                          'https://coreruleset.org/docs/concepts/paranoia_levels/',
                          'https://coreruleset.org/docs/concepts/false_positives_tuning/']},
    {   'id': 'hiw-enterprise-waf-compare',
        'name': 'Enterprise/appliance WAFs: Akamai, Imperva, F5',
        'category': 'how-it-works',
        'summary': 'Akamai App & API Protector, Imperva WAF (Cloud/SecureSphere), and F5 BIG-IP '
                   'Advanced WAF combine negative-model signatures with positive-model policy '
                   'learning, adaptive/ML tuning, and bot + DDoS protection.',
        'detail': 'Akamai App & API Protector (successor to Kona Site Defender) runs on the Akamai '
                  'CDN edge: adaptive security engine with self-tuning risk scoring, Kona rule '
                  'groups, automated attack-group detection, API request-constraint enforcement '
                  '(positive model), plus client reputation and DDoS. Imperva (formerly Incapsula '
                  'cloud WAF and on-prem SecureSphere) uses signatures, reputation, ThreatRadar '
                  'feeds, and dynamic profiling that learns a positive application model, with '
                  'account-takeover and API protection. F5 BIG-IP Advanced WAF / ASM builds a '
                  'positive security policy through automatic policy building (learning legitimate '
                  'URLs, parameters, methods, and enforcing them after a learning window), layered '
                  'with attack signatures, DataGuard, brute-force and bot defense, L7 DoS, and a '
                  'distinctive Support-ID block page. Common theme: all three offer both a generic '
                  'negative-model backstop and a per-application positive model, and all sit '
                  'inline so origin exposure defeats them.',
        'applies_to': ['Akamai', 'Imperva', 'F5 BIG-IP', 'positive model'],
        'indicator': '',
        'references': [   'https://www.akamai.com/products/app-and-api-protector',
                          'https://www.imperva.com/products/web-application-firewall-waf/',
                          'https://www.f5.com/products/security/advanced-waf']},
    {   'id': 'hiw-modsecurity-engine',
        'name': 'ModSecurity rule engine',
        'category': 'how-it-works',
        'summary': 'Open-source rules-based WAF engine that inspects HTTP transactions in phases '
                   'and acts (pass/deny/log) based on operator-matched rules.',
        'detail': 'ModSecurity (now maintained as OWASP ModSecurity, formerly '
                  'Trustwave/SpiderLabs; libmodsecurity/v3 with connectors for nginx/Apache/IIS) '
                  'processes each request/response across five phases: request headers (1), '
                  'request body (2), response headers (3), response body (4), and logging (5). '
                  'Rules use the SecRule syntax: variables (ARGS, REQUEST_URI, REQUEST_HEADERS), '
                  'operators (@rx regex, @pm phrase match, @detectSQLi/@detectXSS libinjection '
                  'operators), transformations (t:lowercase, t:urlDecodeUni, t:removeComments), '
                  'and actions (deny, pass, block, pass, setvar). It is only an engine — detection '
                  'quality depends on the ruleset loaded on top (typically OWASP CRS). '
                  'libinjection provides tokenizer-based SQLi/XSS detection that is more robust '
                  'than pure regex. Note ModSecurity v2 is EOL; the engine is a rules interpreter, '
                  'not a policy by itself.',
        'applies_to': ['ModSecurity', 'OWASP CRS', 'negative-model WAF'],
        'indicator': '',
        'references': [   'https://github.com/owasp-modsecurity/ModSecurity',
                          'https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)',
                          'https://github.com/libinjection/libinjection']},
    {   'id': 'hiw-positive-vs-negative',
        'name': 'Positive vs negative security models',
        'category': 'how-it-works',
        'summary': 'Negative (blocklist) models block known-bad signatures; positive (allowlist) '
                   'models permit only known-good input per learned/declared schema — each with '
                   'distinct false-positive/coverage tradeoffs.',
        'detail': 'A negative security model (deny-list / signature or scoring based, e.g. CRS, '
                  'most cloud managed rules) enumerates malicious patterns; it is easy to deploy '
                  'generically but is inherently bypassable because it must anticipate every '
                  'attack encoding — anything not matched is allowed. A positive security model '
                  '(allow-list) defines what legitimate traffic looks like — permitted URLs, '
                  'parameters, methods, value types/lengths, character sets — and rejects '
                  'everything else; it is far harder to bypass but requires per-application '
                  'modeling. Appliance WAFs (F5 BIG-IP ASM, Imperva) build positive models via '
                  'automatic policy learning / traffic profiling, and schema-based API protection '
                  '(OpenAPI/GraphQL schema enforcement) is a modern positive model. Real '
                  'deployments blend both: a strict positive model for API endpoints plus a '
                  'negative-model backstop. Most WAF bypasses target the negative model; '
                  'positive-model gaps come from over-broad learned policies or unmodeled '
                  'endpoints.',
        'applies_to': ['all WAFs', 'API security', 'F5 ASM', 'Imperva'],
        'indicator': '',
        'references': [   'https://owasp.org/www-community/Web_Application_Firewall',
                          'https://owasp.org/www-pdf-archive/Best_Practices_Guide_WAF_v104.en.pdf']},
    {   'id': 'fp-akamai',
        'name': 'Fingerprint: Akamai',
        'category': 'fingerprint',
        'summary': 'Identified by the AkamaiGHost Server banner, Akamai bot-manager cookies '
                   "(_abck, ak_bmsc, bm_sz), X-Akamai-* headers, and 'Reference #' access-denied "
                   'pages.',
        'detail': 'Akamai edge servers announce Server: AkamaiGHost. Bot Manager sets the _abck '
                  'and ak_bmsc/bm_sz sensor cookies (very characteristic). Kona/App & API '
                  "Protector denials return an 'Access Denied' page containing a 'Reference "
                  "#18.xxxx.xxxxxx.xxxxxxxx' error reference used for support correlation. "
                  'X-Akamai-* and Akamai-GRN request headers/IDs also leak presence. The _abck '
                  'cookie in particular is a near-unique Akamai indicator.',
        'applies_to': ['Akamai', 'Kona Site Defender', 'App & API Protector'],
        'indicator': "Header 'Server: AkamaiGHost' or 'AkamaiNetStorage'; cookies '_abck', "
                     "'ak_bmsc', 'bm_sz', 'bm_mi', 'bm_sv'; headers 'X-Akamai-Transformed', "
                     "'X-Akamai-Request-ID', 'Akamai-GRN'; block body 'Access Denied' with "
                     "'Reference #<hex>.<hex>' and 'You don't have permission to access ... on "
                     "this server'.",
        'references': [   'https://github.com/EnableSecurity/wafw00f',
                          'https://techdocs.akamai.com/bot-manager/docs',
                          'https://developer.akamai.com/legacy/introduction/Prov_HTTP_Headers.html']},
    {   'id': 'fp-aws-waf',
        'name': 'Fingerprint: AWS WAF / CloudFront',
        'category': 'fingerprint',
        'summary': 'Harder to fingerprint directly; inferred from CloudFront fronting headers '
                   "(X-Amz-Cf-Id, Via ... cloudfront), x-amzn-RequestId, and generic 403 'The "
                   "request could not be satisfied' / 'Generated by cloudfront' block pages.",
        'detail': 'AWS WAF itself emits no branded header — detection relies on the fronting '
                  'service. Behind CloudFront a WAF block returns HTTP 403 with the CloudFront '
                  "error page 'The request could not be satisfied ... Generated by cloudfront "
                  "(CloudFront)' plus X-Amz-Cf-Id/X-Amz-Cf-Pop. Behind API Gateway a blocked "
                  'request returns 403 with {"message":"Forbidden"} and '
                  'x-amzn-RequestId/x-amzn-ErrorType. ALB-attached WAF returns a bare 403. The '
                  'distinguishing signal versus a plain CloudFront 403 is that WAF blocks specific '
                  'attack payloads while identical benign requests pass. wafw00f keys off the '
                  'CloudFront/Amazon headers and 403 body.',
        'applies_to': ['AWS WAF', 'CloudFront', 'API Gateway', 'ALB'],
        'indicator': "Headers 'X-Amz-Cf-Id', 'X-Amz-Cf-Pop', 'Via: ... CloudFront', "
                     "'X-Amzn-Trace-Id', 'x-amzn-RequestId', 'x-amzn-ErrorType'; block body 'The "
                     "request could not be satisfied' / 'Generated by cloudfront (CloudFront)' "
                     'with a \'403 ERROR\' Request ID; API Gateway \'{"message":"Forbidden"}\'.',
        'references': [   'https://github.com/EnableSecurity/wafw00f',
                          'https://docs.aws.amazon.com/waf/latest/developerguide/customizing-the-error-response.html']},
    {   'id': 'fp-cloudflare',
        'name': 'Fingerprint: Cloudflare',
        'category': 'fingerprint',
        'summary': 'Identified by the cloudflare Server header, CF-RAY response header, __cf_bm / '
                   "cf_clearance cookies, and the branded 'Attention Required! | Cloudflare' block "
                   'page with a Ray ID.',
        'detail': 'Every response through Cloudflare carries Server: cloudflare and a CF-RAY '
                  'header (edge trace ID with the datacenter code suffix). The __cf_bm '
                  'bot-management cookie and cf_clearance (post-challenge) cookie are strong '
                  "tells. WAF/security blocks render an interstitial titled 'Attention Required! | "
                  "Cloudflare' with a Ray ID and a numeric error (1020 firewall rule, 1015 "
                  'rate-limited, 1010 browser-integrity). Managed/JS challenges emit cf-mitigated: '
                  'challenge and Sec-Fetch/turnstile assets. wafw00f detects Cloudflare via these '
                  'headers/cookies.',
        'applies_to': ['Cloudflare'],
        'indicator': "Header 'Server: cloudflare' and 'CF-RAY: <hex>-<POP>'; cookies '__cf_bm', "
                     "'cf_clearance', '__cfduid' (legacy); block body 'Attention Required! | "
                     "Cloudflare', 'Ray ID:', 'Error 1020 Access Denied' / error codes 1010/1015; "
                     "challenge header 'cf-mitigated: challenge'.",
        'references': [   'https://github.com/EnableSecurity/wafw00f',
                          'https://developers.cloudflare.com/fundamentals/reference/http-headers/',
                          'https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-1xxx-errors/']},
    {   'id': 'fp-f5-bigip',
        'name': 'Fingerprint: F5 BIG-IP (ASM / Advanced WAF)',
        'category': 'fingerprint',
        'summary': 'Identified by BIGipServer* persistence cookies, TS* ASM cookies, X-WA-Info / '
                   "X-Cnection headers, and the 'The requested URL was rejected ... Your support "
                   "ID is:' block page.",
        'detail': 'F5 BIG-IP load-balancing sets BIGipServer<poolname> cookies (often containing '
                  'an encoded backend IP/port). The ASM/Advanced WAF module sets TS-prefixed '
                  "cookies and, on a policy violation, returns the unmistakable block page: 'The "
                  "requested URL was rejected. Please consult with your administrator.' followed "
                  "by 'Your support ID is: <digits>'. The X-Cnection: close header quirk and "
                  "X-WA-Info are additional tells. The 'support ID' page is the canonical F5 ASM "
                  'fingerprint.',
        'applies_to': ['F5 BIG-IP', 'ASM', 'Advanced WAF'],
        'indicator': "Cookies 'BIGipServer<pool>' (may be encoded), ASM cookies 'TS<hex>' and "
                     "'F5_ST'/'LastMRH_Session'/'MRHSession' (APM); headers 'X-WA-Info', "
                     "'X-Cnection: close'; ASM block body 'The requested URL was rejected. Please "
                     "consult with your administrator.' + 'Your support ID is: <number>'.",
        'references': [   'https://github.com/EnableSecurity/wafw00f',
                          'https://my.f5.com/manage/s/article/K6917']},
    {   'id': 'fp-imperva-incapsula',
        'name': 'Fingerprint: Imperva Incapsula',
        'category': 'fingerprint',
        'summary': 'Identified by visid_incap_ / incap_ses_ / nlbi_ cookies, the X-Iinfo and '
                   "X-CDN: Incapsula headers, and 'Request unsuccessful. Incapsula incident ID' "
                   'block pages.',
        'detail': "Imperva's cloud WAF (formerly Incapsula) sets the visid_incap_, incap_ses_, and "
                  'nlbi_ cookies keyed by site ID, and adds the X-Iinfo debug header plus X-CDN: '
                  "Incapsula. A blocked request returns an HTML page reading 'Request "
                  "unsuccessful. Incapsula incident ID: NNNN-NNNNNNNNNNNNN' — the incident ID is "
                  'the strongest single indicator. On-prem SecureSphere may instead show generic '
                  'blocks, but cloud-fronted sites reveal the cookies. wafw00f fingerprints '
                  'Imperva via these markers.',
        'applies_to': ['Imperva', 'Incapsula', 'SecureSphere'],
        'indicator': "Cookies 'visid_incap_<siteID>', 'incap_ses_<n>_<siteID>', 'nlbi_<siteID>'; "
                     "headers 'X-Iinfo', 'X-CDN: Incapsula'; block body 'Request unsuccessful. "
                     "Incapsula incident ID: <id>' or 'Powered by Incapsula'.",
        'references': [   'https://github.com/EnableSecurity/wafw00f',
                          'https://docs.imperva.com/bundle/cloud-application-security/page/more/imperva-cookies.htm']},
    {   'id': 'fp-modsecurity',
        'name': 'Fingerprint: ModSecurity / generic open-source WAF',
        'category': 'fingerprint',
        'summary': "Identified by default 403/406 responses, 'Mod_Security'/'NOYB' Server banners, "
                   "and Apache 'You don't have permission to access' / '406 Not Acceptable' error "
                   'pages.',
        'detail': 'ModSecurity has no mandatory branded page — behavior depends on configuration. '
                  'Older/default installs advertised Server: Mod_Security or the obfuscation token '
                  'NOYB, and used SecDefaultAction status:403 (or 406 Not Acceptable) yielding the '
                  "stock Apache 'You don't have permission to access' page. With OWASP CRS the "
                  'operator often customizes the block response, so detection leans on behavioral '
                  'testing (identical benign request passes, attack payload gets a consistent '
                  '403). Related open-source engines: NAXSI (X-Data-Origin: naxsi header) and '
                  'Coraza (CRS-compatible). Because responses are so tunable, ModSecurity is one '
                  'of the harder WAFs to fingerprint reliably.',
        'applies_to': ['ModSecurity', 'OWASP CRS', 'NAXSI', 'Coraza'],
        'indicator': "Header 'Server: Mod_Security' or 'NOYB' (deliberate obfuscation); default "
                     "deny returns HTTP 403 (or 406 'Not Acceptable') with Apache body 'You don't "
                     "have permission to access <url> on this server'; CRS may return a custom "
                     "403; NAXSI shows 'X-Data-Origin: naxsi'.",
        'references': [   'https://github.com/EnableSecurity/wafw00f',
                          'https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)']},
    {   'id': 'fp-sucuri',
        'name': 'Fingerprint: Sucuri CloudProxy',
        'category': 'fingerprint',
        'summary': 'Identified by the X-Sucuri-ID / X-Sucuri-Cache headers, Server: '
                   "Sucuri/Cloudproxy banner, and the 'Access Denied - Sucuri Website Firewall' "
                   'block page.',
        'detail': "Sucuri's cloud WAF (CloudProxy) adds X-Sucuri-ID (edge node) and X-Sucuri-Cache "
                  'headers to responses and identifies as Server: Sucuri/Cloudproxy. A blocked '
                  "request returns an HTML page titled 'Access Denied - Sucuri Website Firewall' "
                  "referencing 'Sucuri CloudProxy', a block reason, and the cloudproxy@sucuri.net "
                  'contact. These headers alone are a reliable fingerprint.',
        'applies_to': ['Sucuri'],
        'indicator': "Headers 'X-Sucuri-ID', 'X-Sucuri-Cache', 'Server: Sucuri/Cloudproxy'; block "
                     "body 'Access Denied - Sucuri Website Firewall' with 'Sucuri CloudProxy' and "
                     "a Block ID / 'Questions? cloudproxy@sucuri.net'.",
        'references': [   'https://github.com/EnableSecurity/wafw00f',
                          'https://docs.sucuri.net/website-firewall/']},
    {   'id': 'fp-wordfence',
        'name': 'Fingerprint: Wordfence (WordPress)',
        'category': 'fingerprint',
        'summary': "Application-layer WordPress WAF identified by 'Generated by Wordfence' block "
                   "pages and 'Your access to this site has been limited' 503 responses.",
        'detail': 'Wordfence is a plugin-based WAF running inside WordPress (PHP), so it sets no '
                  'proprietary edge headers; it is fingerprinted by its block/challenge HTML which '
                  "explicitly reads 'Generated by Wordfence' and 'Your access to this site has "
                  "been limited by the site owner (Response code: 503)'. Human-verification "
                  'challenges and the wordfence plugin path under /wp-content/plugins/wordfence/ '
                  'corroborate it. wafw00f matches on the body strings.',
        'applies_to': ['Wordfence', 'WordPress'],
        'indicator': "Block body 'Generated by Wordfence', 'Your access to this site has been "
                     "limited by the site owner', 'This response was generated by Wordfence'; "
                     'often HTTP 403/503; presence of /wp-content/plugins/wordfence/ assets.',
        'references': [   'https://github.com/EnableSecurity/wafw00f',
                          'https://www.wordfence.com/help/firewall/']},
    {   'id': 'bp-content-type-confusion',
        'name': 'Content-Type / JSON / multipart confusion',
        'category': 'bypass-technique',
        'summary': 'Mislabeling or exploiting the parsing of the request body (wrong Content-Type, '
                   'alternate JSON/XML encodings, multipart boundary tricks) so the WAF skips or '
                   'misparses the body the backend still reads.',
        'detail': 'WHY IT WORKS: A WAF decides how to parse a body from its Content-Type. If it '
                  'lacks a parser for the declared type, mishandles multipart/form-data boundaries '
                  '(duplicate/oversized/whitespace-padded boundaries, mismatched filename vs name, '
                  'nested parts), or the backend ignores/overrides the declared type (e.g. accepts '
                  "JSON body sent as text/plain, parses XML with entities the WAF doesn't expand), "
                  'the malicious field is never inspected. JSON-specific evasions include '
                  'unicode-escaped keys/values (Union), numeric/whitespace padding, and deeply '
                  'nested structures that exceed WAF parse depth. DEFENSE: parse every body '
                  'according to what the backend will actually accept, not just the declared '
                  'header; enforce a strict allowed Content-Type set (positive model); fully '
                  'expand JSON \\u escapes and XML entities before matching; cap and validate '
                  'multipart boundaries and part counts; treat unparseable bodies as suspicious '
                  '(fail closed).',
        'applies_to': ['API WAFs', 'ModSecurity', 'cloud WAFs', 'REST/GraphQL APIs'],
        'indicator': '',
        'references': [   'https://coreruleset.org/docs/rules/paranoia_levels/',
                          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/',
                          'https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)#requestbodyprocessor']},
    {   'id': 'bp-encoding-layers',
        'name': 'Layered/alternate encodings',
        'category': 'bypass-technique',
        'summary': 'Wrapping a payload in URL, double-URL, unicode/%u, overlong-UTF-8, '
                   'HTML-entity, or mixed encodings so a signature engine that under-decodes fails '
                   'to match while the backend fully decodes.',
        'detail': 'WHY IT WORKS: Signatures match on a canonical form (e.g. the literal string '
                  '"<script" or "UNION SELECT"). If the WAF decodes fewer layers than the '
                  "application — single URL-decode vs the app's double-decode, no %uXXXX handling, "
                  'no overlong UTF-8 (e.g. multi-byte encodings of ASCII), no HTML-entity or '
                  "base64/JSON-unicode (\\uXXXX) decoding — the pattern never appears in the WAF's "
                  'normalized view but is restored downstream. Negative models are especially '
                  'exposed because they must anticipate every encoding permutation. DEFENSE: '
                  'recursively decode all supported encodings to a canonical form before matching '
                  '(ModSecurity t:urlDecodeUni, t:htmlEntityDecode, t:jsDecode, applied and '
                  'repeated), reject overlong/invalid UTF-8 and %u sequences outright, enforce a '
                  'single expected charset, and use tokenizer-based detection (libinjection) '
                  'rather than raw-string regex.',
        'applies_to': ['negative-model WAFs', 'ModSecurity', 'signature engines'],
        'indicator': '',
        'references': [   'https://coreruleset.org/docs/concepts/false_positives_tuning/',
                          'https://owasp.org/www-community/attacks/Double_Encoding',
                          'https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)#transformation-functions']},
    {   'id': 'bp-http-parameter-pollution',
        'name': 'HTTP Parameter Pollution (HPP)',
        'category': 'bypass-technique',
        'summary': 'Sending the same parameter multiple times so the WAF and the backend '
                   'select/concatenate different occurrences, splitting a payload past signature '
                   'inspection.',
        'detail': 'WHY IT WORKS: Platforms disagree on duplicate parameters — some take the first '
                  'value, some the last, some concatenate (PHP/APACHE with []-arrays, ASP '
                  'concatenates with commas, JSP takes first). If a WAF inspects only the first '
                  'occurrence (or a concatenation) while the backend uses the last (or splits '
                  'differently), an attacker distributes a malicious value across several '
                  'same-named parameters so no single inspected value trips a rule, yet the '
                  'backend reassembles the attack. Related: separator confusion (&, ;, %26). '
                  'DEFENSE: normalize by inspecting ALL occurrences of a parameter (ModSecurity '
                  'ARGS matches every instance) and the concatenated form; reject requests with '
                  "unexpected duplicate keys under a positive model; align the WAF's "
                  'parameter-selection semantics with the specific backend framework.',
        'applies_to': ['negative-model WAFs', 'PHP', 'ASP.NET', 'JSP'],
        'indicator': '',
        'references': [   'https://owasp.org/www-community/attacks/HTTP_Parameter_Pollution',
                          'https://www.imperva.com/resources/resource-library/white-papers/hpp/',
                          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution']},
    {   'id': 'bp-inline-mutation',
        'name': 'Inline lexical mutation (case, comments, whitespace, null bytes)',
        'category': 'bypass-technique',
        'summary': 'Mutating payload tokens with mixed case, inline comments, alternate '
                   'whitespace, or embedded null bytes so brittle signatures fail to match while '
                   'the target language parser ignores the noise.',
        'detail': 'WHY IT WORKS: SQL, HTML/JS, and shell grammars tolerate lexical noise that a '
                  'naive regex does not anticipate: mixed case (SeLeCt), inline comments splitting '
                  'keywords (UN/**/ION, SEL/**/ECT), MySQL versioned comments (/*!50000UNION*/), '
                  'alternate whitespace/line separators (tab, %0b, %0c, %a0, comment-as-space), '
                  "backticks, and embedded null bytes (%00) that truncate the WAF's string view "
                  'but are stripped or tolerated downstream. Any signature keyed to an exact '
                  'literal or a single whitespace class is evadable. DEFENSE: apply normalizing '
                  'transforms before matching (t:lowercase, t:removeComments, t:removeWhitespace, '
                  't:replaceNulls / reject nulls), and prefer grammar/tokenizer-aware detection '
                  '(libinjection tokenizes SQL/XSS so comment/case/whitespace mutation collapses '
                  'to the same token stream) over raw regex; reject embedded null bytes in text '
                  'fields outright.',
        'applies_to': ['negative-model WAFs', 'signature engines', 'SQLi/XSS filters'],
        'indicator': '',
        'references': [   'https://github.com/libinjection/libinjection',
                          'https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)#transformation-functions',
                          'https://owasp.org/www-community/attacks/SQL_Injection']},
    {   'id': 'bp-origin-ip-discovery',
        'name': 'Origin-IP discovery (bypassing the WAF entirely)',
        'category': 'bypass-technique',
        'summary': "Locating the backend's real IP so traffic is sent directly to the origin, "
                   'skipping the cloud/reverse-proxy WAF completely — the most impactful bypass '
                   'class.',
        'detail': 'WHY IT WORKS: Cloud/CDN WAFs (Cloudflare, Akamai, Imperva, Sucuri, '
                  'AWS+CloudFront) only protect traffic that traverses them. If the origin '
                  "server's real IP is reachable and accepts requests with the right Host header, "
                  'an attacker connects directly and every WAF rule is irrelevant. Origins leak '
                  'through historical DNS records, subdomains not proxied (mail/dev/ftp), SPF/MX '
                  'and TXT records, SSL-certificate transparency logs matching the origin cert, '
                  'default vhost/IP responses, server-side request features (webhooks, PDF/image '
                  'fetchers) that reveal outbound IP, and misconfigured services on the same IP. '
                  'This is reconnaissance, not payload crafting — hence the strongest defense '
                  'target. DEFENSE: firewall the origin to accept traffic ONLY from the WAF '
                  "provider's published IP ranges (allowlist), use provider origin-authentication "
                  '(Cloudflare Authenticated Origin Pulls / AWS custom-header verification at '
                  'ALB), rotate the origin IP after fronting, avoid unproxied leaking DNS records '
                  'and shared hosting, and use a private origin (VPC / origin pull only). Verify '
                  'no path resolves to the origin outside the WAF.',
        'applies_to': [   'Cloudflare',
                          'Akamai',
                          'Imperva',
                          'Sucuri',
                          'AWS WAF',
                          'all cloud/CDN WAFs'],
        'indicator': '',
        'references': [   'https://developers.cloudflare.com/fundamentals/security/protect-your-origin-server/',
                          'https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/',
                          'https://github.com/EnableSecurity/wafw00f']},
    {   'id': 'bp-oversized-body',
        'name': 'Oversized bodies to skip inspection',
        'category': 'bypass-technique',
        'summary': "Placing the payload beyond the WAF's maximum inspected body size (or padding "
                   'to exceed it) so the malicious bytes are never scanned, while the backend '
                   'still processes the full body.',
        'detail': 'WHY IT WORKS: Every WAF caps how many body bytes it buffers/inspects for '
                  'performance (e.g. ModSecurity SecRequestBodyLimit / SecRequestBodyNoFilesLimit; '
                  'AWS WAF historically inspected only the first 8 KB of body; other engines have '
                  'similar limits). If the request body exceeds that limit, engines either skip '
                  'inspection or only scan the prefix. An attacker pads the request (large benign '
                  'preamble, junk fields, big file part) and positions the attack after the '
                  'inspection cutoff; the origin, which reads the entire body, executes it. '
                  'DEFENSE: configure the body limit deliberately with SecRequestBodyLimitAction '
                  'Reject (fail closed) rather than ProcessPartial; where the platform allows, '
                  'raise inspected-body size (AWS WAF association config / oversize-handling '
                  'action set to Match/Block); reject requests larger than the application '
                  'legitimately needs; and ensure that content past the limit cannot reach the '
                  'backend unfiltered.',
        'applies_to': ['ModSecurity', 'AWS WAF', 'cloud WAFs', 'inspection size limits'],
        'indicator': '',
        'references': [   'https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)#SecRequestBodyLimit',
                          'https://docs.aws.amazon.com/waf/latest/developerguide/web-request-body-inspection.html',
                          'https://coreruleset.org/docs/concepts/false_positives_tuning/']},
    {   'id': 'bp-parser-differential',
        'name': 'Normalization and parser differentials',
        'category': 'bypass-technique',
        'summary': 'WAF and origin parse the same request differently, so a payload the WAF sees '
                   'as benign is reassembled as malicious by the backend (or vice versa).',
        'detail': 'WHY IT WORKS: A WAF must reconstruct the request the way the backend will '
                  "interpret it. When the WAF's HTTP/URL/charset/JSON parser diverges from the "
                  "application framework's parser — different handling of duplicate keys, of ';' "
                  "vs '&' separators, of trailing bytes, of charset (e.g. treating body as ASCII "
                  'while backend decodes UTF-16/EBCDIC), of malformed percent-encoding — an '
                  "attacker crafts input that lands in the gap: the WAF's view is clean, the app's "
                  'view is the attack. This is the root cause behind many concrete bypasses (HPP, '
                  'content-type confusion, charset tricks). DEFENSE: normalize aggressively and '
                  'identically to the backend before inspection (canonical decode, single '
                  'charset), reject ambiguous/malformed requests instead of best-effort parsing, '
                  'prefer a positive/schema model, and keep WAF and app parser behavior in sync '
                  '(fail-closed on parse disagreement). This is defensive research into '
                  'interpretation gaps, not an exploit recipe.',
        'applies_to': ['all negative-model WAFs', 'ModSecurity', 'cloud WAFs'],
        'indicator': '',
        'references': [   'https://owasp.org/www-pdf-archive/OWASP_Testing_Guide_v4.pdf',
                          'https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn',
                          'https://www.usenix.org/conference/usenixsecurity21/presentation/pletinckx']},
    {   'id': 'bp-path-normalization',
        'name': 'Path normalization and traversal encoding',
        'category': 'bypass-technique',
        'summary': 'Using dot-segments, encoded slashes, mixed separators, and case/normalization '
                   "quirks so the WAF's view of the URL path differs from the resolved path the "
                   'origin/router uses.',
        'detail': 'WHY IT WORKS: WAF rules often match on the raw or lightly-normalized path, but '
                  'the origin server, application router, or reverse proxy resolves ./ and ../ '
                  'segments, decodes %2f/%2e, collapses duplicate slashes, and applies OS/case '
                  'normalization afterward. So /admin can be reached (or a rule protecting a path '
                  'evaded) via /./admin, /admin/..;/, /%2e/admin, //admin, /Admin, or '
                  "encoded-slash traversal — the WAF sees a path its rule doesn't cover while the "
                  'backend maps to the protected resource. This also underlies ACL/authorization '
                  'bypasses and traversal that path-based signatures miss. DEFENSE: fully '
                  'canonicalize the path before matching (decode, resolve dot-segments, collapse '
                  "slashes, normalize case per the backend's filesystem/router semantics) exactly "
                  'as the origin will; reject ambiguous encoded slashes/dot-segments where not '
                  'needed; apply access rules on the normalized path and enforce authorization at '
                  'the application, never solely at the WAF path pattern.',
        'applies_to': ['reverse-proxy WAFs', 'CDN WAFs', 'path-based ACLs', 'traversal filters'],
        'indicator': '',
        'references': [   'https://owasp.org/www-community/attacks/Path_Traversal',
                          'https://portswigger.net/web-security/access-control',
                          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Directory_Traversal_File_Include']},
    {   'id': 'bp-transfer-encoding-smuggling',
        'name': 'Chunked encoding / Transfer-Encoding and request smuggling',
        'category': 'bypass-technique',
        'summary': 'Abusing Transfer-Encoding: chunked, obfuscated TE headers, or TE/CL '
                   'disagreements so the WAF and origin frame request boundaries differently, '
                   'hiding a payload from inspection.',
        'detail': 'WHY IT WORKS: HTTP message framing can be specified by Content-Length or '
                  'Transfer-Encoding: chunked. If a fronting WAF/proxy and the origin resolve an '
                  'ambiguous or duplicated framing header differently (classic TE.CL / CL.TE / '
                  'TE.TE desync), part of the body the WAF never inspects becomes a new request or '
                  'hidden payload at the origin. Even without full smuggling, chunk-size '
                  'obfuscation, whitespace/newline tricks in Transfer-Encoding, or splitting the '
                  'payload across chunk boundaries can defeat body signatures that inspect the raw '
                  '(still-chunked) stream. DEFENSE: de-chunk and reassemble the full body before '
                  'inspection; reject requests with both Content-Length and Transfer-Encoding, '
                  'malformed chunk sizes, or non-standard TE values (fail closed); normalize '
                  'framing to a single canonical form; keep proxy and origin on identical, strict '
                  "HTTP parsers. Classic research: Watchfire (2005) and Kettle's HTTP Desync.",
        'applies_to': ['reverse-proxy WAFs', 'CDN WAFs', 'front-end/back-end pairs'],
        'indicator': '',
        'references': [   'https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn',
                          'https://portswigger.net/web-security/request-smuggling',
                          'https://www.cgisecurity.com/lib/HTTP-Request-Smuggling.pdf']},
    {   'id': 'bp-xff-ip-verb-tampering',
        'name': 'X-Forwarded-For / trusted-header spoofing and verb tampering',
        'category': 'bypass-technique',
        'summary': 'Spoofing client-IP/trust headers (X-Forwarded-For, X-Real-IP, '
                   'X-Originating-IP) or swapping the HTTP method to hit allowlists, rate-limit '
                   'exemptions, or rules scoped to specific verbs.',
        'detail': 'WHY IT WORKS: (a) IP/trust-header spoofing: WAF rules that allowlist internal '
                  "IPs, apply geo/reputation, or exempt 'trusted' sources from rate limiting often "
                  'trust client-controlled headers (X-Forwarded-For, X-Real-IP, X-Client-IP, '
                  'X-Originating-IP). If the WAF reads these without a trusted-proxy chain, an '
                  'attacker forges an allowlisted/internal IP to bypass blocks or rate limits. (b) '
                  'Verb tampering: rules scoped to specific methods (only inspecting POST bodies, '
                  'or an ACL that denies GET to /admin) can be sidestepped with HEAD, PUT, PATCH, '
                  'or arbitrary/uncommon methods the framework still routes to the same handler. '
                  'DEFENSE: derive the real client IP only from the actual TCP peer or a strictly '
                  'validated left-most-untrusted XFF using a configured trusted-proxy list; strip '
                  'inbound spoofable trust headers at the edge; apply WAF rules and authorization '
                  'across all methods (default-deny methods, positive model of allowed verbs per '
                  'endpoint) rather than per-verb allowlists.',
        'applies_to': ['all WAFs', 'rate limiting', 'IP allowlists', 'method-based rules'],
        'indicator': '',
        'references': [   'https://owasp.org/www-community/attacks/HTTP_Verb_Tampering',
                          'https://portswigger.net/web-security/access-control',
                          'https://developers.cloudflare.com/support/troubleshooting/restoring-visitor-ips/restoring-original-visitor-ips/']}]
