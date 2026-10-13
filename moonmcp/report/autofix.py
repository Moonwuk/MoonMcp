"""Auto-fix & Remediation generator for MoonMCP.

Generates concrete, vulnerability-class-specific remediation text and (when
source code is available) suggested code patches.  Uses the OWASP Cheat
Sheets (120 sheets in the knowledge base) as the authoritative reference for
defensive guidance, supplemented by PayloadsAllTheThings for exploit context.

Two public methods on ``RemediationGenerator``:

- ``generate_remediation(finding)`` — returns a structured remediation text
  with concrete steps tailored to the vulnerability type (SQLi → parameterized
  queries, XSS → CSP + output escaping, SSRF → URL allowlist, IDOR →
  authorization checks, etc.).

- ``generate_patch(finding, code_context)`` — returns a unified-diff-style
  code patch when the caller supplies the vulnerable source snippet.  The
  patch is heuristic (pattern-matched by vuln class + language) and serves as
  a *suggested fix* for pentest-client reports, not an auto-merge PR.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# OWASP Cheat Sheet knowledge base — lazy-loaded, path resolved at call time
# ---------------------------------------------------------------------------

_KB_ROOT = Path(os.environ.get(
    "HERMES_PIPELINE_KB",
    str(Path(__file__).resolve().parents[4] / "knowledge_base"),
))
_CHEATSHEET_DIR = _KB_ROOT / "owasp_cheatsheets"

# Mapping: vuln-type aliases → relevant OWASP cheat sheet filenames
_CHEAT_SHEET_MAP: dict[str, list[str]] = {
    "sqli":         ["SQL_Injection_Prevention_Cheat_Sheet.md",
                    "Query_Parameterization_Cheat_Sheet.md",
                    "Injection_Prevention_Cheat_Sheet.md"],
    "nosqli":       ["NoSQL_Security_Cheat_Sheet.md",
                    "Injection_Prevention_Cheat_Sheet.md"],
    "xss":          ["Cross_Site_Scripting_Prevention_Cheat_Sheet.md",
                    "DOM_based_XSS_Prevention_Cheat_Sheet.md",
                    "XSS_Filter_Evasion_Cheat_Sheet.md",
                    "Content_Security_Policy_Cheat_Sheet.md"],
    "ssrf":         ["Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md"],
    "idor":         ["Authorization_Cheat_Sheet.md",
                    "Access_Control_Cheat_Sheet.md",
                    "Authorization_Testing_Automation_Cheat_Sheet.md"],
    "authz":        ["Authorization_Cheat_Sheet.md",
                    "Access_Control_Cheat_Sheet.md"],
    "auth":         ["Authentication_Cheat_Sheet.md"],
    "csrf":         ["Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md"],
    "xxe":          ["XML_External_Entity_Prevention_Cheat_Sheet.md"],
    "ssti":         ["Injection_Prevention_Cheat_Sheet.md"],
    "cmdi":         ["OS_Command_Injection_Defense_Cheat_Sheet.md",
                    "Injection_Prevention_Cheat_Sheet.md"],
    "lfi":          ["File_Upload_Cheat_Sheet.md"],
    "path-traversal": ["File_Upload_Cheat_Sheet.md"],
    "deserialization": ["Deserialization_Cheat_Sheet.md"],
    "open-redirect": ["Unvalidated_Redirects_and_Forwards_Cheat_Sheet.md"],
    "upload":       ["File_Upload_Cheat_Sheet.md"],
    "jwt":          ["JSON_Web_Token_for_Java_Cheat_Sheet.md"],
    "oauth":        ["OAuth2_Cheat_Sheet.md"],
    "crlf":         ["Injection_Prevention_Cheat_Sheet.md"],
    "race":         ["Race_Conditions_Cheat_Sheet.md"],
    "business-logic": ["Business_Logic_Security_Cheat_Sheet.md"],
    "clickjacking": ["Clickjacking_Defense_Cheat_Sheet.md"],
    "cors":         ["Cross_Origin_Resource_Sharing_Cheat_Sheet.md",
                    "Content_Security_Policy_Cheat_Sheet.md"],
    "info-disclosure": ["Information_Exposure_Cheat_Sheet.md"],
}

# Fallback for unknown vuln types
_DEFAULT_SHEETS = ["Injection_Prevention_Cheat_Sheet.md"]


def _load_cheat_sheet(filename: str, *, max_chars: int = 6000) -> str:
    """Load and truncate an OWASP cheat sheet to a manageable size."""

    path = _CHEATSHEET_DIR / filename
    if not path.exists():
        return ""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    # Strip markdown headers beyond level 3 and collapse whitespace-ish blocks
    # to keep the reference focused.
    return text[:max_chars]


def _extract_remediation_section(md_text: str) -> str:
    """Extract the most relevant 'Prevention'/'Defense'/'Mitigation' section."""

    if not md_text:
        return ""
    # Look for headers that typically contain remediation guidance
    pattern = re.compile(
        r"^(#{1,3})\s+(?:Prevention|Defense|Mitigation|How to (?:Prevent|Protect|Mitigate)|"
        r"Remediation|Recommendations?|Secure (?:Coding|Implementation)|"
        r"Defense (?:Implementation|Options)|Solution)\b.*$",
        re.IGNORECASE | re.MULTILINE,
    )
    matches = list(pattern.finditer(md_text))
    if not matches:
        return ""
    # Take the first matching section up to the next same-level header
    start = matches[0].start()
    level = len(matches[0].group(1))
    rest = md_text[start:]
    next_header = re.compile(rf"^#{{1,{level}}}\s", re.MULTILINE)
    next_match = next_header.search(rest, matches[0].end())
    if next_match:
        return rest[:next_match.start()].strip()
    return rest.strip()


# ---------------------------------------------------------------------------
# Vulnerability-type → remediation text templates
# ---------------------------------------------------------------------------

_REMEDIATION_TEMPLATES: dict[str, str] = {
    "sqli": """\
## SQL Injection — Remediation

### Primary Defence: Parameterized Queries (Prepared Statements)

**Use prepared statements with parameterized queries for ALL database access.
Never concatenate user input into SQL strings.**

- **Python (sqlite3 / psycopg2 / SQLAlchemy):**
  ```python
  # VULNERABLE
  cursor.execute(f"SELECT * FROM users WHERE id = {user_input}")
  # SECURE — parameterized
  cursor.execute("SELECT * FROM users WHERE id = ?", (user_input,))
  ```
- **Java (JDBC / Hibernate / JPA):**
  ```java
  // VULNERABLE
  stmt.executeQuery("SELECT * FROM users WHERE id = " + userInput);
  // SECURE — prepared statement
  PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
  ps.setInt(1, userId);
  ```
- **Node.js (pg / mysql2):**
  ```javascript
  // VULNERABLE
  db.query(`SELECT * FROM users WHERE id = ${userInput}`);
  // SECURE — parameterized
  db.query('SELECT * FROM users WHERE id = $1', [userInput]);
  ```
- **PHP (PDO):**
  ```php
  // VULNERABLE
  $pdo->query("SELECT * FROM users WHERE id = " . $_GET['id']);
  // SECURE — prepared statement
  $stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');
  $stmt->execute([':id' => $_GET['id']]);
  ```

### Additional Measures
1. **Input validation / allowlisting** — validate data type, length, format
   before it reaches the query. Use it as defence-in-depth, NOT as the primary
   control.
2. **Stored procedures** with parameterized inputs are also safe.
3. **ORMs** (SQLAlchemy, Hibernate, Prisma) parameterize by default — ensure
   you never bypass the ORM with raw string interpolation.
4. **Least-privilege DB accounts** — the application DB user should not be
   `sa`/`root`; restrict to the tables/operations it needs.
5. **WAF** (e.g. ModSecurity with OWASP CRS) as a compensating control — does
   NOT fix the root cause.
""",

    "xss": """\
## Cross-Site Scripting (XSS) — Remediation

### Primary Defence: Context-Aware Output Encoding

**Encode ALL untrusted data according to the context where it is inserted
(HTML body, attribute, JavaScript, URL, CSS). Never insert untrusted data
without encoding.**

#### 1. HTML Body Context
- Use HTML entity encoding (`<`, `>`, `&`, `"`, `'`):
  ```python
  # Python (html.escape / Jinja2 autoescape)
  import html
  safe = html.escape(user_input)
  # Jinja2: autoescape is ON by default — do not use |safe filter
  ```

#### 2. HTML Attribute Context
- Encode with HTML entities, ensuring quotes around attributes:
  ```html
  <input value="<%= encodeForHTMLAttribute(userInput) %>">
  ```

#### 3. JavaScript Context
- Use JavaScript string encoding (backslash-x followed by two hex digits for all non-alphanumeric):
  ```javascript
  // Do NOT put user data in <script> blocks — use data attributes + textContent
  <div data-user="<%= encodeForHTMLAttribute(userInput) %>"></div>
  ```

#### 4. URL Context
- Use `encodeURIComponent()` (JS) or equivalent for URL parameters.

### Defence-in-Depth

1. **Content Security Policy (CSP):**
   ```
   Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'
   ```
   - CSP prevents inline script execution — the strongest XSS mitigation.
   - Use nonces or hashes for legitimate inline scripts.
   - **No `unsafe-inline` or `unsafe-eval`** in production.

2. **Framework auto-escaping** — React, Angular, Vue, Django/Jinja2, Twig all
   auto-escape by default. Do NOT bypass with `dangerouslySetInnerHTML`,
   `bypassSecurityTrustHtml`, `|safe`, or `{!! !!}`.

3. **HttpOnly cookies** — prevents XSS from stealing session tokens:
   ```
   Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict
   ```

4. **Input validation** — allowlisting is preferred but encoding is the
   primary defence.
""",

    "ssrf": """\
## Server-Side Request Forgery (SSRF) — Remediation

### Primary Defence: URL Allowlist + Network Segmentation

**Never fetch URLs from user input without strict validation. Use an
allowlist of permitted destinations.**

1. **Allowlist permitted destinations:**
   ```python
   ALLOWED_HOSTS = {"api.internal-service.local", "cdn.example.com"}
   def fetch_url(url):
       parsed = urllib.parse.urlparse(url)
       if parsed.hostname not in ALLOWED_HOSTS:
           raise ValueError("Host not allowed")
       # Resolve and check against blocked ranges (below)
       ...
   ```

2. **Block internal / metadata IP ranges** — resolve the hostname and reject
   if it resolves to:
   - `127.0.0.0/8` (loopback)
   - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (private)
   - `169.254.169.254` (AWS/GCP/Azure metadata)
   - `::1`, `fc00::/7` (IPv6 loopback / ULA)
   - `0.0.0.0/8` (unspecified)

3. **Do not redirect** — disable following redirects when fetching user-
   supplied URLs (an attacker can redirect from an allowed host to an
   internal IP).

4. **Enforce scheme allowlist** — only allow `http://` and `https://`;
   block `gopher://`, `file://`, `dict://`, `ftp://`.

5. **Network-level controls:**
   - Egress firewall rules restricting outbound connections from the
     application server.
   - IAM roles with least privilege (even if metadata endpoint is reached,
     credentials should be scoped).
   - IMDSv2 on AWS (requires a session token — mitigates SSRF to metadata).

6. **Do not return raw response bodies** — parse and return only the needed
   data fields, stripping headers and internal info.
""",

    "idor": """\
## Broken Object-Level Authorization (IDOR / BOLA) — Remediation

### Primary Defence: Object-Level Authorization Checks

**Every access to an object MUST verify that the requesting user is
authorized to access THAT specific object. Authentication is NOT
authorization.**

1. **Check ownership / authorization on every object access:**
   ```python
   # VULNERABLE — user can change the ID to access others' data
   @app.get("/api/orders/{order_id}")
   async def get_order(order_id: int):
       return await db.get_order(order_id)

   # SECURE — verify the requesting user owns this order
   @app.get("/api/orders/{order_id}")
   async def get_order(order_id: int, user = Depends(current_user)):
       order = await db.get_order(order_id)
       if order is None or order.user_id != user.id:
           raise HTTPException(404)  # 404, NOT 403 — do not leak existence
       return order
   ```

2. **Use unguessable identifiers** (UUIDv4) as resource IDs instead of
   sequential integers — reduces enumeration surface (but NOT a replacement
   for authorization checks).

3. **Centralize authorization logic** — do not scatter `if user.id ==`
   checks across controllers. Use a policy/permission service:
   ```python
   def can_access(user, resource, action="read"):
       if user.role == "admin":
           return True
       return resource.user_id == user.id
   ```

4. **Deny by default** — if the authorization check is missing or ambiguous,
   return 404/403. Never expose object existence to unauthorized users.

5. **Test authorization** — automated tests that swap user identities and
   verify each cannot access the other's objects. See OWASP Authorization
   Testing Automation Cheat Sheet.

6. **For multi-tenant apps** — enforce tenant isolation at the query level
   (e.g. a global `WHERE tenant_id = ?` filter) so the tenant boundary
   cannot be accidentally bypassed.
""",

    "nosqli": """\
## NoSQL Injection — Remediation

### Primary Defence: Input Sanitization + Strict Typing

**Validate input types and sanitize operators. Never pass user input
directly as a query filter object.**

1. **Type-check input:**
   ```javascript
   // VULNERABLE — user sends {"username": {"$ne": null}}
   db.users.findOne({ username: req.body.username });

   // SECURE — enforce string type
   if (typeof req.body.username !== 'string') throw new Error('Invalid input');
   db.users.findOne({ username: req.body.username });
   ```

2. **Strip `$` operators from user input:**
   ```javascript
   function sanitize(obj) {
       if (obj === null || typeof obj !== 'object') return obj;
       for (const key of Object.keys(obj)) {
           if (key.startsWith('$')) delete obj[key];
           else sanitize(obj[key]);
       }
       return obj;
   }
   ```

3. **Use schema validation** (e.g. Mongoose strict schemas, Joi, Zod) to
   reject non-string values where strings are expected.

4. **Disable `$where`** if not needed — it allows arbitrary JavaScript
   execution server-side.
""",

    "cmdi": """\
## OS Command Injection — Remediation

### Primary Defence: Avoid Shell Calls, Use Safe APIs

**Never pass user input to a shell command. Use language-native APIs that
do NOT invoke a shell.**

1. **Use safe APIs instead of shell:**
   ```python
   # VULNERABLE
   os.system(f"ping {user_input}")
   os.system(f"nslookup {user_input}")

   # SECURE — subprocess with list args (no shell)
   subprocess.run(["ping", "-c", "1", user_input], check=True)
   # SECURE — use a library instead of shelling out
   import socket
   socket.gethostbyname(user_input)
   ```

2. **If a shell is unavoidable** (last resort):
   - Allowlist input with a strict regex (e.g. `^[a-zA-Z0-9._-]+$`).
   - Use `subprocess.run(["cmd", "arg"], shell=False)` — never
     `shell=True` with user input.
   - Never use `eval()`, `exec()`, or `os.system()` with user input.

3. **Language-specific safe APIs:**
   - Python: `subprocess.run(["cmd", "arg"])` with list args
   - Java: `ProcessBuilder` with separate arguments (not `Runtime.exec(String)`)
   - Node.js: `child_process.execFile` (not `exec`), or `spawn` with list args
""",

    "xxe": """\
## XML External Entity (XXE) — Remediation

### Primary Defence: Disable External Entity Resolution

**Disable DTD processing and external entity resolution in your XML parser.**

- **Python (defusedxml / lxml):**
  ```python
  # Use defusedxml — it disables entity resolution by default
  from defusedxml import ElementTree as ET
  tree = ET.parse(user_xml_file)
  # If using lxml explicitly:
  parser = lxml.etree.XMLParser(resolve_entities=False, no_network=True)
  ```

- **Java (JAXP / SAX):**
  ```java
  DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
  dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
  dbf.setXIncludeAware(false);
  dbf.setExpandEntityReferences(false);
  ```

- **.NET:**
  ```csharp
  XmlReaderSettings settings = new XmlReaderSettings();
  settings.DtdProcessing = DtdProcessing.Prohibit;
  settings.XmlResolver = null;
  ```

- **If JSON can replace XML** — prefer JSON for data exchange to eliminate
  the entire class of XXE vulnerabilities.
""",

    "csrf": """\
## Cross-Site Request Forgery (CSRF) — Remediation

### Primary Defence: Synchronizer Token Pattern / SameSite Cookies

1. **Anti-CSRF tokens:**
   - Generate a cryptographically random token per session/form.
   - Include it as a hidden field in every state-changing form.
   - Validate it server-side on every POST/PUT/DELETE.
   - Frameworks: Django (`CsrfViewMiddleware`), Flask-WTF, Spring Security
     (`CsrfTokenRepository`), Express (`csurf`).

2. **SameSite cookies:**
   ```
   Set-Cookie: session=abc123; SameSite=Strict; Secure; HttpOnly
   ```
   - `SameSite=Strict` — cookie is never sent on cross-site requests (most
     secure; can break legitimate cross-site navigation).
   - `SameSite=Lax` — cookie sent on top-level GET navigations only (good
     default for most apps).

3. **Verify origin/referer** — check the `Origin` (or `Referer`) header on
   state-changing requests; reject if it does not match the expected origin.

4. **Do NOT use custom headers for CSRF protection alone** — combine with
   tokens.
""",

    "open-redirect": """\
## Open Redirect — Remediation

### Primary Defence: Redirect Only to Allowlisted Destinations

**Never redirect to a user-supplied URL without validation. Use an
allowlist or a relative-path-only redirect.**

```python
# VULNERABLE
return redirect(request.args.get("next"))

# SECURE — allowlist or relative path
ALLOWED_REDIRECTS = {"/dashboard", "/profile", "/login"}

def safe_redirect(next_url):
    parsed = urllib.parse.urlparse(next_url)
    # Only allow relative paths (no scheme, no netloc)
    if parsed.scheme or parsed.netloc:
        return "/"
    if parsed.path in ALLOWED_REDIRECTS:
        return parsed.path
    return "/"
```

- If user-chosen redirects are a product requirement, show an interstitial
  page with a warning for external redirects.
""",

    "ssti": """\
## Server-Side Template Injection (SSTI) — Remediation

### Primary Defence: Use Logic-Less Templates / Sandboxing

1. **Use logic-less templates** (e.g. Mustache) where possible — they
   cannot execute code.

2. **Do not render user input as a template expression:**
   ```python
   # VULNERABLE — user input rendered as a template
   template = f"Hello {user_input}"
   render_string(template)  # Jinja2 evaluates {{ }}

   # SECURE — user input is data, not template source
   template = Template("Hello {{ name }}")
   template.render(name=user_input)
   ```

3. **Sandbox the template engine** if user-authored templates are a product
   requirement:
   - Jinja2: `SandboxedEnvironment`
   - Freemarker: configure `TemplateClassUnloader` and disable
     `?api` / `?new`
   - Twig: `Sandbox` extension
""",

    "lfi": """\
## Path Traversal / LFI — Remediation

### Primary Defence: Canonicalize + Allowlist

1. **Canonicalize and validate file paths:**
   ```python
   import os
   BASE_DIR = "/var/www/uploads"

   def safe_path(filename):
       full = os.path.normpath(os.path.join(BASE_DIR, filename))
       # Ensure the resolved path is inside BASE_DIR
       if not full.startswith(BASE_DIR + os.sep) and full != BASE_DIR:
           raise ValueError("Path traversal detected")
       return full
   ```

2. **Allowlist filenames** — only accept alphanumeric + `.` + `-` + `_`.
   Reject any path separators (`/`, `\\`), `..`, or null bytes.

3. **Use a mapping** instead of user-supplied paths (e.g. map a numeric ID
   to a server-side file path).
""",

    "deserialization": """\
## Insecure Deserialization — Remediation

### Primary Defence: Do Not Deserialize Untrusted Data

1. **Never deserialize untrusted data** — use JSON (or another safe data
   format) for cross-system data exchange.

2. **If deserialization is unavoidable:**
   - **Java**: Use a `ObjectInputFilter` (JEP 290) to allowlist classes:
     ```java
     ObjectInputStream ois = new ObjectInputStream(in);
     ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter(
         "com.example.*;java.lang.*;!*"
     ));
     ```
   - **Python**: Avoid `pickle` for untrusted data; use `json` or
     `ast.literal_eval` for literals.
   - **.NET**: Use `DataContractSerializer` or `JavaScriptSerializer` with
     type constraints, not `BinaryFormatter`.

3. **Integrity checks** — sign serialized payloads with HMAC and verify
   before deserializing (defence-in-depth, not a standalone fix).
""",

    "jwt": """\
## JWT Vulnerability — Remediation

1. **Pin the algorithm** — explicitly specify the expected algorithm
   (`HS256`, `RS256`) and reject `alg: none`:
   ```python
   # PyJWT
   payload = jwt.decode(token, key, algorithms=["HS256"])
   # Do NOT pass algorithms=None
   ```

2. **Do not use the public key as an HMAC secret** — ensure RS/ES and HS
   algorithms use different keys to prevent algorithm confusion.

3. **Validate `exp`, `nbf`, `iss`, `aud`** claims on every request.

4. **Store JWTs in HttpOnly cookies**, not in localStorage (XSS can steal
   them).
""",

    "cors": """\
## CORS Misconfiguration — Remediation

1. **Never reflect `Origin` with `Access-Control-Allow-Credentials: true`** —
   this allows any origin to make authenticated cross-site requests.

2. **Allowlist specific origins:**
   ```
   Access-Control-Allow-Origin: https://trusted.example.com
   Access-Control-Allow-Credentials: true
   ```
   - Maintain a server-side allowlist of trusted origins.
   - Do NOT use `*` when credentials are involved.

3. **Restrict headers and methods:**
   ```
   Access-Control-Allow-Headers: Authorization, Content-Type
   Access-Control-Allow-Methods: GET, POST
   ```
""",

    "clickjacking": """\
## Clickjacking — Remediation

1. **Set `X-Frame-Options` header:**
   ```
   X-Frame-Options: DENY
   # or SAMEORIGIN if you need to frame your own pages
   ```

2. **Use CSP `frame-ancestors` directive** (modern replacement):
   ```
   Content-Security-Policy: frame-ancestors 'self';
   ```

3. **Frame-busting JavaScript** is unreliable — use headers as the primary
   defence.
""",

    "race": """\
## Race Condition — Remediation

1. **Use database-level locking:**
   - Pessimistic: `SELECT ... FOR UPDATE` (row lock during transaction).
   - Optimistic: version column + `WHERE version = ?` on UPDATE.

2. **Use atomic operations:**
   ```sql
   -- VULNERABLE: SELECT then UPDATE
   SELECT balance FROM accounts WHERE id = 1;
   UPDATE accounts SET balance = balance - 100 WHERE id = 1;

   -- SECURE: atomic conditional update
   UPDATE accounts SET balance = balance - 100
   WHERE id = 1 AND balance >= 100;
   ```

3. **Idempotency keys** — assign a unique key per operation so duplicate
   requests are no-ops.
""",

    "info-disclosure": """\
## Information Disclosure — Remediation

1. **Remove verbose error pages in production** — return generic error
   messages; log stack traces server-side only.

2. **Disable debug endpoints** (e.g. Spring Actuator `/env`, Django debug
   toolbar, Laravel Telescope) in production.

3. **Remove version-exposing headers:**
   ```
   Server: nginx  (not: nginx/1.18.0)
   X-Powered-By: (remove entirely)
   ```

4. **Do not return more data than needed** — use DTOs / field selection to
   limit response payloads to what the client requires.
""",

    "business-logic": """\
## Business Logic Vulnerability — Remediation

1. **Validate business rules server-side** — never trust client-side
   validation for price, quantity, discount, or workflow state.

2. **Enforce workflow state machine** — validate that each step is in the
   correct state before allowing the next (e.g. payment required before
   order confirmation).

3. **Rate-limit sensitive operations** — coupon redemption, password
   reset, OTP verification.

4. **Use database constraints** — CHECK constraints for negative values,
   unique constraints for single-use resources.
""",

    "auth": """\
## Authentication Vulnerability — Remediation

1. **Enforce strong passwords** — minimum 12 characters, breached-password
   check (e.g. k-anonymity / HaveIBeenPwned API).

2. **Rate-limit / lockout** — exponential backoff after N failed attempts;
   use a per-account, not per-IP, key.

3. **Use secure session management:**
   - Cryptographically random session IDs (≥128 bits).
   - `HttpOnly; Secure; SameSite=Strict` cookie flags.
   - Regenerate session ID after login.
   - Short session lifetime with refresh-token rotation.

4. **Multi-factor authentication** for sensitive accounts.
""",

    "authz": """\
## Broken Access Control / Authorization — Remediation

1. **Enforce role-based access control (RBAC)** on every endpoint —
   verify the user's role/permissions server-side, not in the UI.

2. **Deny by default** — access is granted only when a positive
   authorization check passes.

3. **Centralize authorization logic** — do not rely on hiding UI elements
   or obscurity.

4. **See the IDOR remediation for object-level authorization.**
""",

    "upload": """\
## File Upload Vulnerability — Remediation

1. **Validate file type by content (magic bytes)**, not by extension or
   Content-Type header.

2. **Store uploads outside the web root** — serve via a controlled endpoint
   that checks permissions.

3. **Rename files** — do not use the user-supplied filename.

4. **Restrict file size** and scan for malware.

5. **If serving user content inline**, set `Content-Disposition: attachment`
   and `X-Content-Type-Options: nosniff`.
""",

    "crlf": """\
## CRLF Injection — Remediation

1. **Strip CR/LF from user input** before inserting into headers:
   ```python
   safe = user_input.replace("\r", "").replace("\n", "")
   ```

2. **Use framework APIs for setting headers** instead of manual string
   construction — frameworks (Django, Flask, Express) validate header
   values.

3. **URL-encode** redirect parameters.
""",

    "oauth": """\
## OAuth Misconfiguration — Remediation

1. **Validate `redirect_uri` exactly** — allowlist specific, fully-qualified
   redirect URIs. Do not allow wildcards or prefix matching.

2. **Use `state` parameter** to prevent CSRF on the authorization flow.

3. **Use PKCE** for public clients (mobile apps, SPAs).

4. **Validate `iss` claim** in ID tokens.

5. **Do not pass access tokens in URL parameters** — use Authorization
   header.
""",
}


# ---------------------------------------------------------------------------
# Vulnerability-type normalisation
# ---------------------------------------------------------------------------

# Map finding.type values to template keys
_TYPE_ALIASES: dict[str, str] = {
    "sqli": "sqli", "sql-injection": "sqli", "sql_injection": "sqli",
    "nosqli": "nosqli", "nosql-injection": "nosqli", "nosql_injection": "nosqli",
    "xss": "xss", "cross-site-scripting": "xss", "cross_site_scripting": "xss",
    "stored-xss": "xss", "reflected-xss": "xss", "dom-xss": "xss",
    "ssrf": "ssrf", "server-side-request-forgery": "ssrf",
    "idor": "idor", "bola": "idor", "broken-access-control": "authz",
    "authz": "authz", "authorization": "authz", "broken-authorization": "authz",
    "auth": "auth", "authentication": "auth", "auth-bypass": "auth",
    "csrf": "csrf", "cross-site-request-forgery": "csrf",
    "xxe": "xxe", "xml-external-entity": "xxe",
    "ssti": "ssti", "template-injection": "ssti",
    "cmdi": "cmdi", "command-injection": "cmdi", "rce": "cmdi",
    "os-command-injection": "cmdi",
    "lfi": "lfi", "path-traversal": "lfi", "path_traversal": "lfi",
    "directory-traversal": "lfi",
    "deserialization": "deserialization", "insecure-deserialization": "deserialization",
    "open-redirect": "open-redirect", "open_redirect": "open-redirect",
    "redirect": "open-redirect",
    "jwt": "jwt", "jwt-confusion": "jwt", "jwt-alg-confusion": "jwt",
    "cors": "cors", "cors-misconfiguration": "cors",
    "clickjacking": "clickjacking",
    "race": "race", "race-condition": "race", "race_condition": "race",
    "info-disclosure": "info-disclosure", "information-disclosure": "info-disclosure",
    "info_disclosure": "info-disclosure",
    "business-logic": "business-logic", "business_logic": "business-logic",
    "logic": "business-logic",
    "upload": "upload", "file-upload": "upload",
    "crlf": "crlf", "crlf-injection": "crlf", "response-splitting": "crlf",
    "oauth": "oauth", "oauth-misconfiguration": "oauth",
}


def _normalize_vuln_type(finding: dict[str, Any]) -> str:
    """Extract and normalize the vulnerability type from a finding dict."""

    # Try finding["type"], then finding["title"], then finding["detail"]
    raw = str(finding.get("type") or "").strip().lower()
    if not raw:
        # Try to infer from the title
        title = str(finding.get("title") or "").strip().lower()
        for alias, key in _TYPE_ALIASES.items():
            if alias in title:
                return key
    return _TYPE_ALIASES.get(raw, raw)


# ---------------------------------------------------------------------------
# CWE → vuln-type mapping (fallback when type is ambiguous)
# ---------------------------------------------------------------------------

_CWE_TO_TYPE: dict[str, str] = {
    "cwe-89": "sqli",
    "cwe-79": "xss",
    "cwe-918": "ssrf",
    "cwe-639": "idor",
    "cwe-611": "xxe",
    "cwe-94": "ssti",
    "cwe-77": "cmdi",
    "cwe-78": "cmdi",
    "cwe-22": "lfi",
    "cwe-352": "csrf",
    "cwe-601": "open-redirect",
    "cwe-502": "deserialization",
    "cwe-284": "authz",
    "cwe-287": "auth",
    "cwe-285": "authz",
    "cwe-306": "authz",
    "cwe-862": "authz",
    "cwe-200": "info-disclosure",
    "cwe-209": "info-disclosure",
    "cwe-522": "auth",
    "cwe-362": "auth",
    "cwe-434": "upload",
    "cwe-93": "crlf",
    "cwe-444": "crlf",
    "cwe-367": "race",
    "cwe-840": "business-logic",
    "cwe-841": "business-logic",
    "cwe-269": "business-logic",
    "cwe-1023": "business-logic",
    "cwe-347": "jwt",
    "cwe-346": "cors",
    "cwe-451": "clickjacking",
}


def _cwe_from_finding(finding: dict[str, Any]) -> str:
    """Extract a normalized CWE-NNN from the finding, or ''."""

    cwe = finding.get("cwe") or finding.get("CWE") or ""
    if isinstance(cwe, list) and cwe:
        cwe = cwe[0]
    cwe = str(cwe).strip()
    nums = re.findall(r"\d+", cwe)
    return f"cwe-{nums[0]}" if nums else ""


# ---------------------------------------------------------------------------
# Language detection from code context
# ---------------------------------------------------------------------------

def _detect_language(code_context: str) -> str:
    """Heuristic language detection from a code snippet."""

    if not code_context:
        return ""
    code = code_context.strip()
    # Python
    if re.search(r"\bdef\s+\w+\s*\(|\bimport\s+\w+|\bfrom\s+\w+\s+import\b", code):
        return "python"
    # Java
    if re.search(r"\bpublic\s+(class|static|void)\b|\bSystem\.out\b|\.java\b", code):
        return "java"
    # JavaScript / Node
    if re.search(r"\bconst\s+\w+\s*=|\brequire\s*\(|=>\s*{|module\.exports\b", code):
        return "javascript"
    # PHP
    if re.search(r"<\?php|\$\w+\s*=|->|::", code):
        return "php"
    # C#
    if re.search(r"\busing\s+System|namespace\s+\w+|public\s+(class|void)\b.*\{", code):
        return "csharp"
    # Go
    if re.search(r"\bpackage\s+main\b|\bfunc\s+\w+\s*\(|\bimport\s+\(", code):
        return "go"
    return ""


# ---------------------------------------------------------------------------
# Patch generation (heuristic, by vuln type + language)
# ---------------------------------------------------------------------------

_PATCH_RULES: dict[str, dict[str, dict[str, str]]] = {
    "sqli": {
        "python": {
            # cursor.execute(f"... {var} ...") → cursor.execute("... ?", (var,))
            "pattern": r'(\w+)\.execute\s*\(\s*(f["\'])(.*?\{(\w+)\}.*?)["\']\s*\)',
            "replacement": r'\1.execute("... ?...", (\4,))',
            "comment": "# Use parameterized queries — never concatenate user input into SQL",
        },
        "java": {
            "pattern": r'(\w+)\.executeQuery\s*\(\s*"([^"]*?)"\s*\+\s*(\w+)',
            "replacement": r'PreparedStatement ps = conn.prepareStatement("$2?");\nps.set{Type}(1, $3);\nResultSet rs = ps.executeQuery();',
            "comment": "// Use PreparedStatement with parameterized queries",
        },
        "javascript": {
            "pattern": r'(\w+)\.query\s*\(\s*(`[^`]*?\$\{(\w+)\}[^`]*?`)\s*\)',
            "replacement": r'$1.query("... $1 ...", [$2])',
            "comment": "// Use parameterized queries — never template-literal-interpolate user input",
        },
        "php": {
            "pattern": r'(\$\w+)->query\s*\(\s*"([^"]*?)"\s*\.\s*(\$\w+)',
            "replacement": r'$stmt = $1->prepare("$2:id");\n$stmt->execute([":id" => $3]);',
            "comment": "// Use PDO prepared statements with parameterized queries",
        },
    },
    "xss": {
        "python": {
            "pattern": r'\|\s*safe\b',
            "replacement": r'| escape',
            "comment": "# Remove |safe — let Jinja2 auto-escape untrusted data",
        },
        "javascript": {
            "pattern": r'dangerouslySetInnerHTML\s*=\s*\{\{\s*(\w+)\s*\}\}',
            "replacement": r'{/* Use textContent or a sanitization library (DOMPurify) */}\n{/* dangerouslySetInnerHTML removed */}',
            "comment": "// Do not use dangerouslySetInnerHTML with untrusted data",
        },
    },
    "ssrf": {
        "python": {
            "pattern": r'requests\.get\s*\(\s*(\w+)\s*\)',
            "replacement": r'# Validate URL against allowlist before fetching\n_url = _validate_ssrf_url(\1)\nrequests\.get(_url)',
            "comment": "# Validate URL against an allowlist — block internal/metadata IPs",
        },
    },
    "idor": {
        "python": {
            "pattern": r'return\s+await\s+\w+\.get_otp\b',
            "replacement": r'# Verify object-level authorization\n_obj = await db.get_object(obj_id)\nif _obj is None or _obj.user_id != current_user.id:\n    raise HTTPException(404)\nreturn _obj',
            "comment": "# Check that the requesting user owns or is authorized for this object",
        },
    },
    "cmdi": {
        "python": {
            "pattern": r'os\.system\s*\(\s*(f["\'][^"\']*\{(\w+)\}[^"\']*["\'])\s*\)',
            "replacement": r'import subprocess\nsubprocess.run(["cmd", "arg", \2], check=True, shell=False)',
            "comment": "# Use subprocess with list args (shell=False) — never os.system with user input",
        },
    },
}


def _generate_code_patch(
    vuln_type: str,
    language: str,
    code_context: str,
    finding: dict[str, Any],
) -> str:
    """Generate a heuristic code patch for the given vuln type + language."""

    rules = _PATCH_RULES.get(vuln_type, {}).get(language)
    if not rules:
        # Try a generic patch comment
        return _generic_patch_comment(vuln_type, language, finding)

    pattern = rules["pattern"]
    replacement = rules["replacement"]
    comment = rules.get("comment", "")

    if not re.search(pattern, code_context):
        # Pattern not found — return a generic suggestion
        return _generic_patch_comment(vuln_type, language, finding)

    # Build a unified-diff-style output
    patched = re.sub(pattern, replacement, code_context)

    lines_old = code_context.splitlines(keepends=True)
    lines_new = patched.splitlines(keepends=True)

    diff_lines: list[str] = [
        f"--- {finding.get('target', 'unknown')} (original)",
        f"+++ {finding.get('target', 'unknown')} (patched)",
    ]

    if comment:
        diff_lines.append("@@ suggested fix @@")
        diff_lines.append(f"+ {comment}")

    # Simple line-by-line diff
    import difflib
    diff = difflib.unified_diff(
        lines_old, lines_new,
        fromfile=f"{finding.get('target', 'original')}",
        tofile=f"{finding.get('target', 'patched')}",
        lineterm="",
    )
    diff_lines.extend(diff)
    return "\n".join(diff_lines)


def _generic_patch_comment(
    vuln_type: str,
    language: str,
    finding: dict[str, Any],
) -> str:
    """Generate a generic patch comment when no specific rule matches."""

    remediation = _REMEDIATION_TEMPLATES.get(vuln_type, "")
    if not remediation:
        return f"// No specific patch rule for vuln type '{vuln_type}'. See the remediation text for guidance."

    # Extract the first code block from the remediation template
    code_blocks = re.findall(r"```(?:\w+)?\n(.*?)```", remediation, re.DOTALL)
    if code_blocks:
        return (
            f"// Suggested fix for {vuln_type} ({language or 'unknown language'}):\n"
            f"// See the remediation guidance below — the specific pattern in your\n"
            f"// code needs to be adapted manually.\n"
            f"//\n"
            f"// Example secure pattern:\n"
            + "\n".join(f"// {line}" for line in code_blocks[0].strip().splitlines())
        )
    return f"// See the remediation text for {vuln_type} guidance."


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class RemediationGenerator:
    """Generate remediation text and suggested code patches for findings.

    Uses the OWASP Cheat Sheets knowledge base (120 sheets) as the
    authoritative reference for defensive guidance, supplemented by
    built-in vulnerability-class-specific remediation templates.

    Usage::

        gen = RemediationGenerator()
        text = gen.generate_remediation(finding)    # → markdown remediation text
        patch = gen.generate_patch(finding, code)  # → unified diff (if applicable)
    """

    def __init__(self, cheatsheet_dir: str | None = None) -> None:
        """Optionally override the OWASP cheat sheet directory path."""

        self._cs_dir = Path(cheatsheet_dir) if cheatsheet_dir else _CHEATSHEET_DIR

    def _vuln_type(self, finding: dict[str, Any]) -> str:
        """Determine the normalized vuln type, with CWE fallback."""

        vtype = _normalize_vuln_type(finding)
        if vtype in _REMEDIATION_TEMPLATES:
            return vtype
        # Try CWE fallback
        cwe = _cwe_from_finding(finding)
        if cwe and cwe in _CWE_TO_TYPE:
            return _CWE_TO_TYPE[cwe]
        return vtype

    def _cheat_sheet_refs(self, vuln_type: str) -> list[dict[str, str]]:
        """Load relevant OWASP cheat sheet references for a vuln type."""

        filenames = _CHEAT_SHEET_MAP.get(vuln_type, _DEFAULT_SHEETS)
        refs: list[dict[str, str]] = []
        for fname in filenames:
            path = self._cs_dir / fname
            if not path.exists():
                # Try a fuzzy match (case-insensitive)
                if self._cs_dir.exists():
                    for p in self._cs_dir.iterdir():
                        if p.name.lower() == fname.lower():
                            path = p
                            break
            if not path.exists():
                continue
            md = _load_cheat_sheet(path.name)
            if not md:
                continue
            section = _extract_remediation_section(md)
            refs.append({
                "file": path.name,
                "url": f"https://cheatsheetseries.owasp.org/cheatsheets/{path.name.replace('.md', '.html')}",
                "remediation_excerpt": section[:2000] if section else md[:2000],
            })
        return refs

    def generate_remediation(self, finding: dict[str, Any]) -> str:
        """Generate concrete, vulnerability-type-specific remediation text.

        Args:
            finding: A finding dict with at least ``type`` (or ``title``
                containing a recognizable vuln name) and optionally ``cwe``,
                ``target``, ``severity``, ``detail``.

        Returns:
            A markdown-formatted remediation text with concrete, actionable
            steps (code examples, configuration changes, etc.).
        """

        vuln_type = self._vuln_type(finding)
        template = _REMEDIATION_TEMPLATES.get(vuln_type)

        if not template:
            # Fallback: generic guidance + try to infer from CWE
            cwe = _cwe_from_finding(finding)
            if cwe and cwe in _CWE_TO_TYPE:
                vuln_type = _CWE_TO_TYPE[cwe]
                template = _REMEDIATION_TEMPLATES.get(vuln_type)

        if not template:
            return self._generic_remediation(finding, vuln_type)

        # Build the full remediation: template + OWASP cheat sheet references
        lines: list[str] = [template]

        # Append OWASP cheat sheet references
        refs = self._cheat_sheet_refs(vuln_type)
        if refs:
            lines.append("### OWASP Cheat Sheet References\n")
            for ref in refs:
                lines.append(f"- **[{ref['file']}]({ref['url']})**")
                if ref.get("remediation_excerpt"):
                    # Include a short excerpt
                    excerpt = ref["remediation_excerpt"][:500].strip()
                    lines.append(f"  > {excerpt[:200]}...")
            lines.append("")

        # Append finding-specific context
        target = finding.get("target", "")
        if target:
            lines.append(f"### Affected Target\n`{target}`")
        detail = finding.get("detail", "")
        if detail:
            lines.append(f"### Finding Detail\n{detail}")

        return "\n".join(lines)

    def _generic_remediation(self, finding: dict[str, Any], vuln_type: str) -> str:
        """Fallback remediation for unrecognized vuln types."""

        cwe = _cwe_from_finding(finding)
        lines = [
            f"## Remediation ({vuln_type or 'unknown vulnerability'})\n",
            "### General Security Principles\n",
            "1. **Validate all input** — use allowlisting, not blocklisting.",
            "2. **Encode all output** — context-aware encoding for the output context.",
            "3. **Enforce authorization** on every access — authentication is not authorization.",
            "4. **Least privilege** — restrict permissions to the minimum needed.",
            "5. **Defence in depth** — multiple independent controls so no single point of failure.\n",
        ]
        if cwe:
            lines.append(f"### Relevant CWE: {cwe.upper()}\n")
            lines.append(f"See https://cwe.mitre.org/data/definitions/{cwe.replace('cwe-', '')}.html\n")

        # Try OWASP cheat sheet references anyway
        refs = self._cheat_sheet_refs(vuln_type)
        if refs:
            lines.append("### OWASP Cheat Sheet References\n")
            for ref in refs:
                lines.append(f"- **[{ref['file']}]({ref['url']})**\n")

        return "\n".join(lines)

    def generate_patch(
        self,
        finding: dict[str, Any],
        code_context: str,
    ) -> str:
        """Generate a suggested code patch (unified diff) for the finding.

        Uses heuristic pattern-matching by vuln type + detected language.
        The patch is a *suggestion* — it should be reviewed by a developer
        before merging. Not all vuln types have patch rules; in that case
        a comment with the recommended secure pattern is returned.

        Args:
            finding: A finding dict with at least ``type`` and optionally
                ``cwe``, ``target``, ``language``.
            code_context: The vulnerable source code snippet (as a string).

        Returns:
            A unified-diff-style string with the suggested fix, or a comment
            block with the recommended secure pattern.
        """

        vuln_type = self._vuln_type(finding)

        # Use explicit language hint from finding, or detect from code
        language = str(finding.get("language") or "").strip().lower()
        if not language:
            language = _detect_language(code_context)

        patch = _generate_code_patch(vuln_type, language, code_context, finding)

        # Prepend a header
        header = (
            f"# Suggested patch for {vuln_type} ({language or 'unknown language'})\n"
            f"# Target: {finding.get('target', 'unknown')}\n"
            f"# Severity: {finding.get('severity', 'unknown')}\n"
            f"# NOTE: This is a heuristic suggestion — review before merging.\n"
        )
        return header + "\n" + patch