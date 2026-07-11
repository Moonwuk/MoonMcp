"""The nuclei bridge — use nuclei for what it is best at, and *steer to what it cannot do*.

nuclei is a stateless, per-template request→matcher engine. On a real bug-bounty
target it is table stakes: everyone mass-scans with it, so the bugs it *can* find are
already reported and duped. The leverage is therefore twofold:

1. **Delegate** the commodity detection nuclei owns (version→CVE, static exposures,
   takeovers, tech fingerprints, DAST fuzzing of reflected params) instead of
   re-implementing it in Python — nuclei's community template library will always win.
2. **Steer to MoonMCP's native edge** — the *stateful / differential / timing /
   business-logic* probes nuclei structurally can't express in a template. Those fire
   on targets already scanned to death by nuclei, so their marginal hit-rate is higher.

This module is the single source of truth for that split (``coverage_report``), the
intent→template-tag selector (``intent_to_tags`` / ``build_args``), and the nuclei
JSONL normaliser (``normalize_finding``). It is pure/offline; the server tools drive it.
"""

from __future__ import annotations

# ── The coverage map (the honest nuclei-vs-us verdict, made executable) ─────────

# MoonMCP capabilities nuclei covers as well or better — prefer nuclei, don't invest
# native effort here. native_tool -> where nuclei covers it.
NUCLEI_DELEGATE: dict[str, str] = {
    "cve_lookup": "nuclei cves/ — thousands of community version→CVE templates",
    "cve_search": "nuclei cves/ + tags",
    "vcs_exposure": "nuclei http/exposures/ (.git/.svn/.env/.hg)",
    "debug_exposure": "nuclei http/exposures/ + misconfiguration/ (ignition/actuator/profiler/adminer…)",
    "extract_secrets": "nuclei exposures/tokens/ (also trufflehog/gitleaks)",
    "takeover_check": "nuclei http/takeovers/ (large fingerprint set; also subzy/subjack)",
    "fingerprint": "nuclei http/technologies/ (also wappalyzer/whatweb)",
    "favicon_hash": "nuclei favicon/ + shodan/fofa",
    "waf_detect": "wafw00f + nuclei technologies/waf",
    "well_known": "nuclei misconfiguration/",
    "content_discovery": "ffuf/feroxbuster + nuclei fuzzing/",
    "port_scan": "naabu/nmap",
    "open_redirect": "nuclei -dast fuzzing (reflected-param redirect)",
    "crlf_probe": "nuclei -dast fuzzing (crlf) — but our differential twin-set is a useful cross-check",
    "ssti_probe": "nuclei -dast fuzzing (ssti, OAST-backed)",
    "sqli_probe": "nuclei -dast fuzzing (sqli) — deep SQLi still needs sqlmap",
    # Reclassified from native-edge by the cited coverage audit (docs/NUCLEI_COVERAGE.md):
    # nuclei owns these, so they carry no hit-rate advantage — keep only as coverage.
    "ssrf_metadata_probe": "cloud-metadata SSRF is response-signature matching + interactsh — "
                           "nuclei's wheelhouse, with large existing template coverage",
    "edge_map": "CDN/edge vendor detection from headers — matcher territory; nuclei has it built in",
}

# MoonMCP capabilities nuclei STRUCTURALLY cannot (or only clumsily) express — these
# are the higher-hit-rate probes to keep and sharpen. native_tool -> why nuclei can't.
NATIVE_EDGE: dict[str, str] = {
    "access_control_check": "compares TWO authenticated identities against the same object "
                            "(IDOR/BOLA) — nuclei is single-template, no cross-identity diff",
    "authz_probe": "multi-step BOLA chain: read the owner's response, extract the object ids it "
                   "exposes, then access them as another identity — cross-request + cross-identity "
                   "state a stateless template engine cannot carry",
    "logic_probe": "business-logic param tampering + mass-assignment; depends on app intent, "
                   "not a static signature",
    "workflow_probe": "multi-step flow step-skipping (force-browse to a later/terminal step "
                      "without completing prerequisites) — needs the ordered flow + sequence state",
    "oauth_redirect_probe": "OAuth redirect_uri allow-list bypass: discover the authorization "
                            "endpoint → replay attacker redirect_uri twins → flag a 3xx to the canary "
                            "(one-click ATO). A discovery→differential chain, not a template match",
    "jwt_jku_probe": "re-issue the target's OWN token with jku/x5u→OAST, replay, correlate the "
                     "callback — cross-request key-injection/SSRF nuclei can't derive from the token",
    "orm_leak_probe": "ORM leak / relational-filter injection (Django __startswith, Prisma "
                      "[field][startsWith], Ransack) — a filter differential over an injected ORM "
                      "lookup, with NO raw SQL, so neither nuclei's -dast sqli fuzzing nor sqli_probe "
                      "fires; the empty-prefix vs no-match reproducible diff is native-edge",
    "ssrf_protocol_probe": "SSRF→internal-datastore reach: per-scheme OAST canaries (gopher/dict/ftp) "
                           "to prove non-HTTP scheme deref, plus a loopback DB-port reachability "
                           "differential vs a closed-port control — a two-request differential + OAST "
                           "correlation across MoonMCP's own callback server, not a template match",
    "fastjson_oast_probe": "Fastjson/Jackson autoType deserialization via a benign @type OAST "
                           "canary (java.net.Inet4Address/URL) correlated to MoonMCP's own callback "
                           "server — the request→callback correlation across MoonMCP's OAST is "
                           "state nuclei's stateless matcher can't carry; deep gadget/JNDI → Strix",
    "firebase_exposure": "Firebase RTDB open-rules — harvest the app's OWN databaseURL from its "
                         "JS firebaseConfig, then a shallow unauth read of the derived backend; a "
                         "config-discovery→backend-differential chain across two hosts, not a template match",
    "supabase_exposure": "Supabase RLS-off — harvest the project URL + public anon key from the app "
                         "JS, enumerate tables from the PostgREST schema, then a per-table limit=1 read "
                         "with that key; key-discovery→schema→per-table differential, nuclei can't derive it",
    "second_order_sqli_probe": "stored SQLi where the sink is a DIFFERENT endpoint from the "
                               "injection — seed a tagged payload at a write endpoint, then drive "
                               "the read endpoints and correlate the SQL error/differential by the "
                               "tag; the write→read state is exactly what a stateless per-template "
                               "engine cannot carry (nor can sqlmap against the write endpoint alone)",
    "db_exposure": "unauthenticated datastore sweep speaking each store's minimal read-only "
                   "handshake (Redis PING/INFO, memcached version, MongoDB listDatabases wire "
                   "query, ES/CouchDB/InfluxDB/YARN/TiDB HTTP) — nuclei's normalizing HTTP client "
                   "cannot speak the raw Redis/memcached/Mongo binary protocols, and its port "
                   "templates send no protocol handshake to differentiate unauth from protected",
    "nosqli_probe": "MongoDB operator-injection ($ne/$gt/$nin/$where) — sends an OBJECT where a "
                    "string is expected and diffs the auth/record outcome vs a plain-scalar "
                    "baseline; a stateless per-template matcher can only fuzz a scalar value, "
                    "never swap the value's TYPE for an operator document",
    "graphql_nosqli": "GraphQL resolver → Mongo/Mongoose operator-injection — sends an operator "
                      "OBJECT ($ne/$gt/$in/$nin) as a GraphQL VARIABLE value where a scalar is "
                      "expected and diffs the resolver's data/auth/record outcome vs a string "
                      "baseline (plus a Mongoose CastError leak); nuclei's -dast fuzzes scalar "
                      "values in a fixed request and cannot swap a variable's TYPE for an operator "
                      "document across a two-state GraphQL differential",
    "cspp_probe": "client-side prototype pollution — loads __proto__/constructor URL paths in a "
                  "real headless browser and reads Object.prototype[marker] back from the page's JS "
                  "realm; a stateless HTTP matcher cannot execute the SPA's JS, so it can neither "
                  "trigger the client-side merge nor observe the polluted prototype",
    "parser_diff_probe": "HTTP parser-differential / WAF-bypass multiplier — pairs a canonical "
                         "request against quirk-twins (UTF-7/overlong-UTF-8 decode, duplicate JSON "
                         "keys, JSON comments/trailing commas, duplicate multipart fields) carrying "
                         "one unique canary, and correlates which transform the app APPLIED / which "
                         "non-standard form it ACCEPTED vs a rejected invalid control; a stateless "
                         "per-template engine sends one fixed request and has no notion of 'same "
                         "logical input, two encodings, compare the decode/precedence'",
    "value_probe": "money-aware value manipulation (negative/overflow/precision/>100% discount, "
                   "currency swap, single-use coupon reuse) — semantics of value, not a signature",
    "race_probe": "single-packet race via HTTP/1.1 last-byte synchronization (all N requests "
                  "complete within ~1ms, neutralizing jitter) — nuclei's race directive is gate-based "
                  "and historically broken, and cannot do single-packet timing on its normalizing client",
    "desync_probe": "CL.TE / obfuscated-TE framing indicators on RAW sockets",
    "desync_modern_probe": "0.CL/TE.0/Expect/chunk-ext via response-timeout deltas on raw sockets — "
                           "nuclei's HTTP client normalises framing, so it cannot send these",
    "path_bypass_probe": "401/403→2xx path-normalization flip; needs a confirmed-protected baseline "
                         "then a per-twin differential",
    "cache_deception_probe": "authed-vs-anon body + cache-HIT differential; needs a session and a "
                             "two-state comparison",
    "response_leak_probe": "drives the OTP/reset/verify flow and detects the out-of-band secret "
                           "returned in-band — flow-stateful",
    "reset_poison_probe": "Host/X-Forwarded-Host reset poisoning; reflected-host differential across "
                          "the reset flow",
    "confirm_finding": "differential confirmation engine (baseline vs payload similarity)",
    "surface_diff": "cross-run attack-surface diff over time — stateful across snapshots",
    "origin_discovery": "behavioural: infer origin behind a CDN from response variance",
    "backend_probe": "behavioural: infer backend fleet from response variance — patch drift, "
                     "content drift (ETag/Last-Modified), clock skew, and header-name ordering "
                     "across a request series; nuclei matches one response, never compares samples",
    "tls_behavior": "bogus-SNI vs real cert diff + mining the DEFAULT cert's SANs for the origin/"
                    "sibling hostnames — a two-handshake comparison nuclei's ssl protocol doesn't do",
    "http_behavior": "behavioural HTTP variance analysis",
    "vhost_probe": "Host-header routing inference",
    "ratelimit_probe": "rate-limit behaviour inference over a request series",
    "oauth_probe": "OIDC metadata policy logic (implicit grant / weak-PKCE / none+HS256 / "
                   "issuer↔jwks mix) — partially templatable but reasoned better natively",
    "config_audit": "classifies a leaked signing secret → framework → forge-to-RCE primitive "
                    "(nuclei can detect the leak, not classify the chain)",
    "business_logic_hunt": "an LLM methodology prompt, not a scanner",
}


def coverage_report() -> dict:
    """The delegate-to-nuclei vs native-edge split — the executable form of the
    'what's in nuclei / what's only in us' answer."""

    return {
        "premise": ("nuclei is a stateless per-template matcher; because everyone mass-scans with "
                    "it, nuclei-detectable bugs are largely already reported. MoonMCP's leverage is "
                    "to DELEGATE the commodity detection to nuclei and spend its effort on the "
                    "stateful/differential/timing/logic probes nuclei structurally cannot express — "
                    "those have a higher marginal hit-rate on already-scanned targets."),
        "delegate_to_nuclei": [{"tool": k, "covered_by": v} for k, v in NUCLEI_DELEGATE.items()],
        "native_edge": [{"tool": k, "why_nuclei_cannot": v} for k, v in NATIVE_EDGE.items()],
        "architecture_edge": [
            "single scope-gating choke-point (allow/deny + resolve-then-check SSRF guard + "
            "intrusive gate + audit) for an AUTONOMOUS agent — nuclei has no scope model",
            "shared cross-agent memory hub (SQLite + FTS + provenance)",
            "offline knowledge bases (injection/technique/privesc/root-cause/WAF)",
            "orchestration of the Strix autonomous pentest agent under human confirmation",
            "the lead→PoC pipeline (promote_lead): classify an edge lead → route it to "
            "confirm_finding / side-effect re-observation / a Strix PoC brief, and track it in "
            "findings + shared memory — the bridge that turns review-leads into proven bugs",
        ],
        "recommendation": ("Run nuclei (via vuln_scan) for the commodity pass, then ALWAYS run the "
                           "native-edge probes — that is where bugs survive the nuclei crowd."),
    }


def also_run_native() -> list[str]:
    """The native-edge probes an agent should run *in addition to* a nuclei scan."""

    return list(NATIVE_EDGE)


# ── Template-tag selection (intent → nuclei flags) ──────────────────────────────

# Plain intent → nuclei -tags value(s). Keeps agents from guessing template paths.
_INTENT_TAGS: dict[str, str] = {
    "cve": "cve", "cves": "cve",
    "exposure": "exposure", "exposures": "exposure", "disclosure": "exposure",
    "misconfig": "misconfig", "misconfiguration": "misconfig",
    "takeover": "takeover", "takeovers": "takeover",
    "default-login": "default-login", "default-logins": "default-login", "login": "default-login",
    "panel": "panel", "panels": "panel",
    "tech": "tech", "fingerprint": "tech", "technology": "tech",
    "lfi": "lfi", "rce": "rce", "sqli": "sqli", "xss": "xss", "ssrf": "ssrf",
    "redirect": "redirect", "traversal": "lfi", "injection": "injection",
    "auth-bypass": "auth-bypass", "misconfigured": "misconfig",
}


def intent_to_tags(intent: str) -> list[str]:
    """Map a comma/space-separated plain intent string to nuclei tag values."""

    out: list[str] = []
    for token in str(intent or "").replace(",", " ").split():
        tag = _INTENT_TAGS.get(token.strip().lower())
        if tag and tag not in out:
            out.append(tag)
    return out


def build_args(url: str, *, tags: str | None = None, templates: str | None = None,
               severity: str | None = None, dast: bool = False) -> list[str]:
    """Assemble the nuclei argv (JSONL, silent, update-check off)."""

    args = ["-u", url, "-jsonl", "-silent", "-duc"]
    tag_values = intent_to_tags(tags) if tags else []
    if tag_values:
        args += ["-tags", ",".join(tag_values)]
    if templates:
        args += ["-t", templates]
    if severity:
        args += ["-severity", severity]
    if dast:
        args += ["-dast"]
    return args


# ── Finding normalisation (nuclei JSONL row → MoonMCP shape) ────────────────────

def normalize_finding(row: dict) -> dict:
    """Flatten one nuclei JSONL result into a stable, compact finding shape."""

    info = row.get("info") or {}
    return {
        "template_id": row.get("template-id") or row.get("templateID") or "",
        "name": info.get("name") or row.get("template-id") or "nuclei finding",
        "severity": str(info.get("severity") or "info").lower(),
        "type": row.get("type") or "http",
        "matched_at": row.get("matched-at") or row.get("matched_at") or row.get("host") or "",
        "tags": info.get("tags") or [],
        "description": (info.get("description") or "").strip()[:400],
        "reference": info.get("reference") or [],
    }
