"""Secret scanner: findings must be redacted in EVERY returned field, incl. context.

The context window used to span the full match verbatim, leaking the secret in
cleartext into the LLM context / audit log / reports / memory hub — exactly the
sinks the redaction step exists to protect.
"""

import time

from moonmcp.recon.secrets import scan_text


def test_context_does_not_leak_prefix_anchored_secret():
    secret = "ghp_" + "A" * 36                       # a GitHub PAT (grp=0 pattern)
    text = f'const token = "{secret}"; // deploy key'
    hits = [h for h in scan_text(text) if h.type == "GitHub PAT"]
    assert hits, "expected the PAT to be detected"
    h = hits[0]
    assert secret not in h.context                   # never the full secret
    assert secret not in h.redacted
    # surrounding context is still informative
    assert "token" in h.context or "deploy key" in h.context


def test_context_does_not_leak_generic_assignment_value():
    secret = "s3cr3tVALUE_abcdef123456"              # high-entropy, non-placeholder
    text = f'api_key = "{secret}"'
    hits = [h for h in scan_text(text) if h.type == "Generic Secret Assignment"]
    assert hits, "expected the assignment secret to be detected"
    h = hits[0]
    assert secret not in h.context
    assert "api_key" in h.context                     # the key name context is preserved


def test_context_does_not_leak_basic_auth_password():
    text = "url = https://admin:SuperSecretPw99@internal.example.com/api"
    hits = [h for h in scan_text(text) if h.type == "Basic Auth in URL"]
    assert hits
    assert "SuperSecretPw99" not in hits[0].context


def test_scan_text_no_redos_on_pathological_body():
    # a long run of letters with no "://" made the old Basic-Auth pattern backtrack
    # quadratically; the bounded pattern must scan it in well under a second.
    payload = "a" * 400_000
    start = time.perf_counter()
    scan_text(payload)
    assert time.perf_counter() - start < 1.5
