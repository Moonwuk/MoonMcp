# MoonMCP — Where the Core of All Problems Is: a Root-Cause Taxonomy

> Nearly every server-side vulnerability is a surface symptom of one of a small number
> of **fundamental root causes**. Learn the causes and the whole zoo of named bugs
> collapses into a handful of ideas — and each idea has a *systemic* fix that kills the
> entire class, not just one instance. This is the conceptual spine of MoonMCP's
> vulnerability knowledge base, exposed as the `rootcause_info` tool and the
> `rootcauses://all` resource; every entry in the vuln catalog links back to its cause.


**13 root causes.**


## Code/Data Confusion (In-Band Control)
*id:* `code-data-confusion`

Data supplied by an untrusted party is concatenated into a string that a downstream interpreter later parses, so attacker-controlled bytes cross the boundary from inert data into executable control tokens. This is the literal essence of every injection: there is no out-of-band channel separating the trusted control plane (the query structure, the command, the markup grammar) from the untrusted data plane (the values), so the interpreter cannot tell the developer's intent from the attacker's.

**Why it never dies —** The default and most ergonomic way to build a command for another interpreter is string concatenation/interpolation, which is exactly the operation that erases the code/data boundary. Every language ships string formatting before it ships safe parameterization, every new interpreter (GraphQL, NoSQL, LLM prompts, template engines) re-introduces an in-band control syntax, and the vulnerability is invisible in the common case because benign data never contains control tokens. The tool that is easiest to reach is the unsafe one.

**Spawns:** SQL injection, NoSQL injection, OS command injection, argument injection, Cross-Site Scripting (reflected/stored/DOM), server-side template injection (SSTI), LDAP injection, XPath injection, expression-language / OGNL injection, log injection / log forging, CRLF header injection, GraphQL injection, prompt injection (LLM)

**Systemic fix —** Establish a structural, out-of-band separation of code and data so untrusted input can never be reinterpreted as control: parameterized queries / prepared statements (values shipped over a separate channel than the query AST), context-aware auto-escaping template engines that encode by output grammar, safe APIs that take arg arrays instead of shell strings (execve not system), allow-list-driven typed parsers, and contextual output encoding at every sink. Never build a program by string-concatenating untrusted input; hand the interpreter a pre-parsed structure with data bound as opaque literals.

**In this catalog:** Argument / Parameter Injection, Connection-String / DSN Injection, Email Header Injection, HTTP Response Splitting / Range Abuse, LDAP Injection, NoSQL Injection, ORM Injection / ORM Leak, OS Command Injection, SQL Injection (classic, blind, boolean/time-based, second-order), SSI / ESI Injection, Server-Side Template Injection (SSTI), XPath / XQuery Injection

**References:** [link](https://owasp.org/Top10/A03_2021-Injection/) · [link](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html) · [link](https://portswigger.net/web-security/sql-injection) · [link](https://portswigger.net/web-security/server-side-template-injection) · [link](https://cwe.mitre.org/data/definitions/74.html)


## Confused Deputy / Trust-Boundary Violation
*id:* `confused-deputy-trust-boundary`

A privileged component (the deputy) performs an action using its own authority but under the direction of a less-privileged party, without carrying the requester's authority with the request. The deputy's ambient privilege is thereby borrowed by an attacker who supplies the object of the action but not the right to it. Norm Hardy's 1988 formulation: the deputy is confused about whose authority it is exercising because designation (which object) is separated from authorization (may this caller touch it).

**Why it never dies —** Server-side architectures are built out of privileged intermediaries (browsers with your cookies, the app server with its DB creds, an SSRF-reachable metadata endpoint that trusts the network) whose authority is ambient and positional rather than tied to the specific request. As long as authority is carried by identity/position (a session cookie the browser attaches automatically, a source IP an internal service trusts) instead of by an unforgeable per-request capability, any component that can steer the deputy inherits its power. The web's cookie/same-origin model institutionalizes exactly this ambient authority.

**Spawns:** Cross-Site Request Forgery (CSRF), Server-Side Request Forgery (SSRF), clickjacking / UI redressing, cloud metadata (IMDS) credential theft, OAuth redirect_uri / token substitution abuse, cross-service ambient-trust abuse, SSO / SAML relay

**Systemic fix —** Bundle designation with authorization: use unforgeable, request-scoped capabilities instead of ambient authority. Anti-CSRF tokens / SameSite cookies + Origin/Fetch-Metadata validation so a request must prove intent, not just identity; per-request signed tokens (IMDSv2 session tokens) instead of trusting network position; the deputy must act with the caller's authority, not its own. Adopt capability-security principles (POLA) so a component can only reach what it was explicitly handed.

**In this catalog:** Host Header Injection, JWT / JWS Attacks, Malicious File Upload leading to RCE, OAuth / OIDC & SAML Federation Flaws, Open Redirect (and Redirect-to-SSRF / auth-token leak chains), Path Traversal / Local File Inclusion / Remote File Inclusion, Second-Order (Stored) Injection, Zip Slip / Archive Extraction Path Traversal

**References:** [link](http://cap-lore.com/CapTheory/ConfusedDeputy.html) · [link](https://owasp.org/www-community/attacks/csrf) · [link](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/) · [link](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-Site) · [link](https://cwe.mitre.org/data/definitions/441.html)


## Parser Differential / Impedance Mismatch
*id:* `parser-differential`

Two or more components in a chain parse the same bytes according to different (or differently-configured) grammars, so a message that means one thing to component A means something else to component B. Security decisions made by the first parser are voided by the second parser's divergent interpretation. This is the LangSec insight: input is a language, ad-hoc parsers accept a larger/looser language than the spec, and any two hand-rolled parsers of a complex format will disagree on edge cases.

**Why it never dies —** Real protocols are underspecified, permissive ('be liberal in what you accept'), and re-implemented independently by every proxy, cache, WAF, framework, and library in the path. Postel's robustness principle actively manufactures differentials, complex formats (HTTP, XML, MIME, Unicode, multipart) are effectively Turing-tarpits, and no two independent implementations agree on all malformed inputs. The differential is emergent from the system, so no single vendor sees or owns the bug.

**Spawns:** HTTP request smuggling / desync (CL.TE, TE.CL, TE.TE, CL.0, H2.CL), XML External Entity (XXE) & billion-laughs, Content-Type / charset confusion & MIME sniffing, Unicode normalization & homoglyph / overlong-encoding bypasses, double-decoding & canonicalization bypasses (path traversal via ..%252f), cookie/header parsing discrepancies, JSON interoperability (duplicate keys, integer precision), SSRF URL-parser confusion (host vs authority disagreement)

**Systemic fix —** Collapse the differential: use a single, spec-strict, generated (not hand-rolled) parser and reject rather than repair ambiguous input (fail-closed on conflicting length/encoding headers, disable HTTP/1.1 chunked+CL coexistence, disable XML external entities and DTDs by default). Normalize/canonicalize to one representation before any security decision, then re-validate. LangSec: define the input language formally, parse fully before processing, and make every hop use identical parsing semantics (end-to-end HTTP/2, front-end normalization).

**In this catalog:** CL.0 / Client-Side Desync Request Smuggling, HTTP Request Smuggling / Desync, HTTP/2 Downgrade Smuggling (H2.CL / H2.TE), SAML Signature Wrapping (XSW), Web Cache Deception

**References:** [link](http://langsec.org/) · [link](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn) · [link](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing) · [link](https://portswigger.net/research/http2) · [link](https://cwe.mitre.org/data/definitions/444.html)


## Missing or Broken Authorization
*id:* `broken-authorization`

The system authenticates who you are but fails to consistently enforce what you may do to a specific object or function. Authorization is a per-request, per-object property, but it is enforced (if at all) in scattered, imperative checks that are easy to omit; the absence of a check is the vulnerability, and absence is invisible in normal use because legitimate users never request objects they don't own.

**Why it never dies —** Authorization is a cross-cutting concern implemented as ad-hoc if-statements bolted onto business logic, so it fails open by omission: adding a new endpoint, object type, or field silently ships without the corresponding check. There is no compiler error for a missing authz check, object identifiers are exposed and enumerable, and 'looks fine in the UI' hides the fact that the API trusts client-supplied object IDs. It is the top web risk precisely because correctness requires enforcement at every single access path.

**Spawns:** Insecure Direct Object Reference (IDOR), Broken Object-Level Authorization (BOLA), Broken Function-Level Authorization (BFLA), vertical privilege escalation (accessing admin functions), horizontal privilege escalation (accessing peer objects), Broken Object Property Level Authorization / excessive data exposure, forced browsing to unlinked functions, multi-tenant isolation bypass

**Systemic fix —** Make authorization a mandatory, centralized, deny-by-default gate that every request must pass, tied to the specific object and action: a policy engine / middleware (ABAC/ReBAC, e.g. an OPA/Cedar/Zanzibar-style layer) the data layer cannot be reached without, object references scoped to the session (query WHERE owner = current_user, or per-user unguessable handles), and framework-level enforcement so a new route is unreachable until a policy is declared. Fail closed; test authorization as a first-class matrix (role x object x action).

**In this catalog:** Authentication Bypass, Broken Access Control / IDOR / BOLA, Business Logic Flaws / Mass Abuse, Cross-Site WebSocket Hijacking (CSWSH), GraphQL Batching, Alias Abuse & Introspection

**References:** [link](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/) · [link](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) · [link](https://cwe.mitre.org/data/definitions/639.html) · [link](https://cwe.mitre.org/data/definitions/862.html) · [link](https://research.google/pubs/zanzibar-googles-consistent-global-authorization-system/)


## Insecure Deserialization / Type Confusion
*id:* `insecure-deserialization`

The application reconstructs rich, typed, in-memory objects (with behavior, not just data) from an untrusted serialized byte stream. Because the serializer is a general object-graph builder that can instantiate arbitrary types and trigger their lifecycle callbacks (constructors, __wakeup, readObject, finalizers), the attacker supplies a payload that, upon deserialization, chains existing 'gadget' methods in the classpath into arbitrary code execution or logic subversion.

**Why it never dies —** Native serialization formats (Java, .NET, PHP, Python pickle, Ruby Marshal) were designed for convenience and trust, conflating data transport with object instantiation and executing type-defined callbacks during decoding. Developers reach for them because they round-trip objects for free, gadget chains live in ubiquitous libraries (so the app author never wrote the vulnerable code), and 'just deserialize the request' looks innocuous. Type confusion recurs whenever a decoder trusts a caller-supplied type tag.

**Spawns:** Java/.NET/PHP object-injection RCE (ysoserial-style gadget chains), Python pickle / PyYAML / Ruby Marshal RCE, property-oriented programming (POP) chains, type confusion via polymorphic JSON type hints (e.g. Jackson polymorphic deserialization), prototype pollution (JS object-graph corruption), PHP phar:// deserialization

**Systemic fix —** Never deserialize untrusted data into live objects. Use data-only interchange formats with no code/type binding (JSON/Protobuf/CBOR) parsed into plain records, then validate against an explicit schema before constructing domain objects. If native serialization is unavoidable: enforce a strict allow-list of deserializable classes (JEP 290 / ObjectInputFilter), disable polymorphic type handling, sign+MAC the blob so only server-produced state round-trips, and run decoders with least privilege. Separate data decoding from behavior instantiation.

**In this catalog:** Insecure Deserialization (Java/PHP/.NET/Python/Ruby/Node)

**References:** [link](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data) · [link](https://github.com/frohoff/ysoserial) · [link](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/) · [link](https://cwe.mitre.org/data/definitions/502.html) · [link](https://portswigger.net/web-security/deserialization)


## State Desynchronization & Race Conditions
*id:* `state-desync-race`

Security decisions assume the system moves through a linear, atomic sequence of states, but the check and the use of a resource are separated in time (TOCTOU) or the same logical state is mutated concurrently. An attacker exploits the sub-state 'window' between validation and action, or drives two components' state machines out of sync, so an invariant that held at check time is false at use time.

**Why it never dies —** Distributed and concurrent systems have no free atomicity: every check-then-act is two operations across a network, a database, and multiple threads, and the developer's mental model is a single-threaded state machine that does not exist at runtime. Frameworks hide concurrency, connection pooling and async multiply the parallelism, and races are non-deterministic so they pass tests and review. Modern techniques (single-packet attack) shrink the window to microseconds, making races broadly practical rather than theoretical.

**Spawns:** TOCTOU file/permission races, limit-overrun / double-spend (redeeming a coupon or withdrawal N times), auth/session state desync & multi-step flow bypass, HTTP request smuggling as a state-desync between hops, idempotency-key and payment races, signup / MFA-enrollment race conditions, cache poisoning via response desync

**Systemic fix —** Make check-and-act atomic and serialized around the invariant: database transactions with proper isolation (SELECT ... FOR UPDATE, unique constraints, atomic compare-and-swap), idempotency keys, optimistic/pessimistic locking, single-owner state machines with explicit valid transitions, and rate/limit enforcement inside the same atomic unit as the decrement. Enforce invariants in the datastore (constraints) rather than by application-level ordering; assume every window can be hit concurrently.

**In this catalog:** HTTP/2 Rapid Reset, Race Conditions / TOCTOU (limit-overrun, double-spend), Single-Packet Race Conditions / TOCTOU, Web Cache Poisoning

**References:** [link](https://portswigger.net/research/smashing-the-state-machine) · [link](https://cwe.mitre.org/data/definitions/367.html) · [link](https://cwe.mitre.org/data/definitions/362.html) · [link](https://owasp.org/www-community/vulnerabilities/Race_Conditions) · [link](https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack)


## Insecure Defaults & Misconfiguration
*id:* `insecure-defaults-misconfiguration`

The vulnerability is not in code the developer wrote but in the configuration space of the components they assembled: a default password, an open admin panel, a permissive CORS or S3 bucket policy, verbose error pages, an enabled debug endpoint, an unauthenticated management port. The insecure state is reachable because 'works out of the box' was prioritized over 'safe out of the box'.

**Why it never dies —** Software is optimized for a frictionless first-run, so vendors ship permissive defaults (enabled features, wildcard access, sample accounts) to minimize support tickets; security is opt-in and the configuration surface grows combinatorially with every added component, framework, and cloud primitive. Nobody reads every config knob, defaults change silently across versions, and the person deploying is rarely the one who understands the security implications of each toggle. The safe path requires positive effort; the unsafe path is the path of least resistance.

**Spawns:** default/blank credentials & sample accounts, exposed admin/actuator/debug endpoints, overly permissive CORS (Access-Control-Allow-Origin: * with credentials), public cloud storage buckets & IAM over-permission, directory listing & verbose stack traces, missing security headers (HSTS, CSP, cookie flags), unpatched/EOL components left enabled, TLS misconfiguration & weak cipher suites

**Systemic fix —** Secure-by-default and secure-by-design: ship products locked down (deny-by-default, no default creds, features off until enabled), and make deployed configuration declarative, version-controlled, and continuously verified. Infrastructure-as-code with policy-as-code gates (CSPM, config scanners, CIS benchmarks in CI), hardened golden images, automatic drift detection, and minimal attack surface (remove, don't just disable). Treat configuration as code subject to the same review and testing as source.

**In this catalog:** CORS Misconfiguration, XML External Entity (XXE) Injection

**References:** [link](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) · [link](https://cwe.mitre.org/data/definitions/1188.html) · [link](https://cwe.mitre.org/data/definitions/16.html) · [link](https://www.cisecurity.org/cis-benchmarks) · [link](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)


## Memory Safety (Native Code)
*id:* `memory-safety`

In languages without automatic bounds/lifetime enforcement, program-controlled operations on memory (indexing, pointer arithmetic, allocation lifetime) can read or write outside the intended object, letting attacker-controlled data corrupt adjacent memory, control-flow structures, or type invariants. The abstraction 'a buffer of size N' is not enforced by the machine, so length is just a convention the attacker violates.

**Why it never dies —** C/C++ deliberately trade safety for control and remain the substrate of OSes, runtimes, parsers, and browsers, so decades of new code keep entering the unsafe substrate. Manual memory management makes every allocation a potential lifetime bug, humans cannot track aliasing and bounds across large codebases, and the same properties that make these languages fast (no runtime checks) make them unsafe. Microsoft and Google independently found ~70% of their critical CVEs are memory-safety issues, and legacy code cannot be rewritten wholesale.

**Spawns:** stack/heap buffer overflow, use-after-free & double-free, out-of-bounds read (e.g. Heartbleed), integer overflow leading to undersized allocation, type confusion (native), uninitialized-memory disclosure, format-string vulnerabilities, off-by-one / boundary errors

**Systemic fix —** Eliminate the class by construction with memory-safe languages (Rust, Go, managed runtimes) for new code and rewrites of critical attack surface; where native code must remain, deploy defense-in-depth mitigations that raise exploitation cost (ASLR, DEP/NX, stack canaries, CFI, hardware memory tagging/MTE, sandboxing) and aggressive detection (ASan/fuzzing/formal verification). The strategic fix is a substrate migration to languages that enforce bounds and lifetimes at compile time, not per-bug patching.

**References:** [link](https://www.memorysafety.org/docs/memory-safety/) · [link](https://github.com/microsoft/MSRC-Security-Research/blob/master/presentations/2019_02_BlueHatIL/2019_01%20-%20BlueHatIL%20-%20Trends%2C%20challenge%2C%20and%20shifts%20in%20software%20vulnerability%20mitigation.pdf) · [link](https://www.cisa.gov/resources-tools/resources/case-memory-safe-roadmaps) · [link](https://cwe.mitre.org/data/definitions/119.html) · [link](https://cwe.mitre.org/data/definitions/416.html)


## Cryptographic Misuse
*id:* `cryptographic-misuse`

The cryptographic primitives are sound but are composed, parameterized, or trusted incorrectly: the attacker exploits how crypto is used, not the math. This spans trusting attacker-controlled algorithm/parameter fields, leaking a decryption/verification oracle, reusing nonces/IVs, predictable randomness, and using fast hashes for passwords. Crypto fails at the joints between primitives and the application.

**Why it never dies —** Cryptography has a brutal usability gap: correct construction requires understanding of oracles, malleability, nonce discipline, and constant-time comparison that general developers lack, while libraries historically expose dangerous low-level knobs (raw ECB, caller-selected JWT alg, unauthenticated encryption) with footgun defaults. The failure modes are silent (the ciphertext still decrypts, the token still validates) so misuse passes functional tests, and each new format (JWT, JWE, SAML) re-litigates the same algorithm-agility and oracle mistakes.

**Spawns:** JWT alg=none & RS256->HS256 key-confusion, padding-oracle attacks (CBC, PKCS#7; POODLE-class), predictable/weak randomness (guessable tokens, IVs, session IDs), nonce/IV reuse (CTR, GCM catastrophic), unauthenticated encryption / ciphertext malleability, fast-hash / unsalted password storage, timing side channels in comparison/verification, hardcoded keys & static IVs

**Systemic fix —** Use misuse-resistant, high-level APIs that make the wrong thing hard: authenticated encryption only (AEAD, libsodium/NaCl 'boxes'), no caller-selectable algorithms (pin the alg server-side, reject alg from the token), CSPRNGs for all security tokens, memory-hard password hashes (argon2/scrypt/bcrypt), and constant-time comparisons. Remove algorithm agility where possible, key by role not by attacker input, and prefer opinionated libraries over primitive toolkits so the secure path is the only path.

**References:** [link](https://portswigger.net/web-security/jwt) · [link](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/) · [link](https://en.wikipedia.org/wiki/Padding_oracle_attack) · [link](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) · [link](https://cwe.mitre.org/data/definitions/347.html)


## Network-Position Abuse / Implicit Network Trust
*id:* `network-position-abuse`

Security is granted based on where a request appears to originate (internal network, localhost, a specific source IP, a resolved hostname) rather than on a verified, authenticated credential. Because network position is forgeable or re-bindable, an attacker who can make a request emanate from a trusted vantage point, or change what a name resolves to after a check, inherits the trust the network placement confers.

**Why it never dies —** The classic perimeter model equates 'inside the firewall' with 'trusted', so internal services, admin panels, cloud metadata endpoints, and databases skip authentication entirely, assuming the network is the boundary. Naming is late-bound (DNS is checked once but used again later), server-side request initiators run inside that trusted zone, and flat internal networks mean one foothold grants broad reach. The assumption 'this came from inside, so it's safe' is baked into decades of network architecture.

**Spawns:** SSRF pivoting to internal services & cloud metadata (IMDS), DNS rebinding (TOCTOU on name resolution), trust of source IP / X-Forwarded-For for authz, unauthenticated internal/east-west services & lateral movement, localhost / 127.0.0.1 trust bypass, VPN/perimeter over-trust

**Systemic fix —** Adopt zero-trust: authenticate and authorize every request on its own cryptographic merits regardless of network origin, so 'inside' confers nothing. Mutually-authenticated TLS (mTLS) and signed service identities for east-west traffic, per-request tokens for metadata services (IMDSv2), egress filtering + allow-listed outbound destinations for SSRF containment, DNS-rebinding defenses (validate resolved IP at connect time, pin, reject private ranges), and micro-segmentation. Trust the credential, never the location.

**In this catalog:** Gopher/Dict SSRF to Internal Service RCE, SSRF via PDF/SVG/Image/Webhook Renderers, Server-Side Request Forgery (SSRF), including blind/OOB

**References:** [link](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/) · [link](https://crypto.stanford.edu/dns/dns-rebinding.pdf) · [link](https://en.wikipedia.org/wiki/DNS_rebinding) · [link](https://csrc.nist.gov/pubs/sp/800/207/final) · [link](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)


## Supply Chain / Transitive Trust
*id:* `supply-chain-transitive-trust`

The application transitively trusts code, artifacts, and build infrastructure it did not author and cannot fully audit: third-party dependencies, their dependencies, package registries, CI/CD pipelines, and update channels. A compromise anywhere in this transitive-trust graph executes with the full privilege of the consuming application, and the consumer never wrote or reviewed the malicious line.

**Why it never dies —** Modern software is assembled, not written: a typical app pulls in thousands of transitive packages, each an implicit trust decision, and the economics reward reuse over auditing. Package managers resolve names to code automatically (enabling substitution and typosquatting), build systems run untrusted code with high privilege, and the trust is transitive and unbounded, so one weak maintainer or one poisoned registry entry propagates everywhere. You cannot review what you don't know you depend on.

**Spawns:** dependency confusion / namespace substitution, typosquatting & malicious packages, compromised maintainer / account takeover (protestware, backdoors), build-pipeline / CI compromise (SolarWinds-class), poisoned base images & artifacts, malicious/vulnerable transitive dependencies (Log4Shell-class blast radius), compromised update channels / code-signing key theft

**Systemic fix —** Establish verifiable provenance and least-privilege for the whole software lifecycle: pin and lockfile every dependency, generate and consume SBOMs, verify signatures/attestations (Sigstore, SLSA provenance levels), prefer private-registry namespace ownership to defeat confusion attacks, run builds hermetically with minimal permissions and ephemeral credentials, and continuously scan (SCA) for known-vuln and anomalous packages. Shift from trusting names to trusting cryptographically attested artifacts and reproducible builds.

**In this catalog:** Dependency Confusion, Software Supply-Chain / Dependency Attacks (incl. dependency confusion)

**References:** [link](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610) · [link](https://slsa.dev/) · [link](https://www.cisa.gov/news-events/alerts/2021/12/11/apache-log4j-vulnerability-guidance) · [link](https://www.sigstore.dev/) · [link](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)


## Implicit Trust of Client-Controlled Input & Metadata
*id:* `implicit-trust-client-metadata`

The server treats request metadata and structure that are actually attacker-controlled as if they were authoritative context: the Host header, X-Forwarded-* headers, referer, filenames, content-type, and the very set of fields in a request body. Because these look like framework/infrastructure-provided context rather than 'user input', developers forget they are fully forgeable and use them to make security or routing decisions, or to bind data straight into internal objects.

**Why it never dies —** Everything in an HTTP request is client-controlled, but frameworks present metadata (headers, absolute URLs, parsed params) as ambient environment, blurring the line between trusted server context and untrusted client claims. Convenience features actively invert the safe default: ORMs auto-bind every submitted field to model attributes (mass assignment), password-reset code trusts the Host header to build links, reverse proxies inject spoofable forwarding headers. The framework's ergonomics make trusting client metadata the default.

**Spawns:** Host-header attacks (password-reset poisoning, cache poisoning, routing-based SSRF), X-Forwarded-For / -Host / -Proto spoofing for authz or logging bypass, mass assignment / auto-binding / over-posting (privilege fields, isAdmin), web cache poisoning via unkeyed inputs, open redirect via trusted-looking parameters, content-type / filename trust (upload MIME spoofing), referer-based access control bypass

**Systemic fix —** Treat all request-derived data, including metadata, as untrusted by default and bind capabilities explicitly: allow-list expected Host values and derive absolute URLs from server config, not from the request; only trust forwarding headers from known proxies at a controlled hop; use explicit input-to-field allow-lists (DTOs / strong-params / read-only attributes) so no request can set a field the developer didn't opt in; and re-derive security-relevant context (identity, tenant, origin) from server-side state, never from a client-supplied claim.

**In this catalog:** Mass Assignment / Auto-binding (Object Property Injection), Server-Side Prototype Pollution to RCE

**References:** [link](https://portswigger.net/research/practical-http-host-header-attacks) · [link](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html) · [link](https://cwe.mitre.org/data/definitions/915.html) · [link](https://portswigger.net/research/practical-web-cache-poisoning) · [link](https://cwe.mitre.org/data/definitions/807.html)


## Ambient Authority & Excess Privilege (Least-Privilege Violation)
*id:* `ambient-authority-excess-privilege`

Components run with far more authority than any single operation needs, and that authority is ambient — automatically available by virtue of identity/context rather than explicitly granted per-task. When any part of an over-privileged component is subverted, the attacker inherits its entire authority. This is the amplifier that turns a small foothold (an injection, an SSRF, a deserialization bug) into total compromise.

**Why it never dies —** Granting broad, standing privilege is operationally easier than scoping narrow, task-specific capabilities: it avoids 'permission denied' friction during development, and identity-based access control (this service account can touch everything) is the default model in OSes and clouds. Least privilege requires knowing exactly what each path needs, which is tedious and brittle as code evolves, so privileges accrete and are never revoked. The design keeps authority ambient and coarse, so every other vulnerability's blast radius is maximal.

**Spawns:** privilege escalation & lateral movement after initial foothold, over-scoped API tokens / OAuth scopes / service accounts, database accounts with full DDL/DML rights for read-only apps, over-permissioned cloud IAM roles (wildcard actions/resources), container/process running as root, SSRF/RCE impact amplification via ambient credentials, excessive session/token lifetime & scope

**Systemic fix —** Enforce the Principle of Least Authority structurally: capability-based access (a component can only reach objects it was explicitly handed, no ambient reach), narrowly-scoped short-lived credentials, per-task IAM roles with resource-level conditions, sandboxing/seccomp/least-privilege containers, network egress restrictions, and privilege separation so a compromise of one component yields minimal authority. Design so authority must be granted, never assumed — making every other bug's blast radius small.

**References:** [link](https://www.cs.virginia.edu/~evans/cs551/saltzer/) · [link](http://www.erights.org/elib/capability/duals/myths.html) · [link](https://cwe.mitre.org/data/definitions/250.html) · [link](https://cwe.mitre.org/data/definitions/272.html) · [link](https://csrc.nist.gov/glossary/term/least_privilege)

