"""Cloud storage bucket enumeration (S3 / GCS / Azure Blob).

Permutate likely bucket names from a keyword (company / product / domain) and
probe the public cloud endpoints to see which exist and whether they are
anonymously listable — a classic source of data exposure.  Talks to the cloud
providers, not the target, so it is passive w.r.t. the engagement scope.
"""

from __future__ import annotations

import asyncio
import re

PROVIDERS = {
    "s3": "https://{name}.s3.amazonaws.com/",
    "gcs": "https://storage.googleapis.com/{name}/",
    "azure": "https://{name}.blob.core.windows.net/{name}?restype=container&comp=list",
}

_SUFFIXES = [
    "", "-dev", "-development", "-prod", "-production", "-staging", "-stage",
    "-test", "-qa", "-uat", "-backup", "-backups", "-bak", "-assets", "-static",
    "-media", "-images", "-img", "-uploads", "-upload", "-files", "-data",
    "-db", "-logs", "-log", "-public", "-private", "-internal", "-cdn", "-www",
    "-web", "-app", "-api", "-config", "-secret", "-secrets", "-archive", "-s3",
    "-dump", "-dumps", "-sql", "-database", "-databases",
]

# Object keys inside a listable bucket that are a DB dump / backup (a one-search data
# breach): a dump extension, or a dump/backup keyword in the key. <Key> is S3/GCS,
# <Name> is Azure Blob.
_KEY_TAG_RE = re.compile(r"<(?:Key|Name)>([^<]+)</(?:Key|Name)>", re.I)
# Precise DB-dump signals only. The bare word alternatives (backup/dumps?/snapshot) were
# removed: they escalated benign keys (`__snapshots__/Button.test.js.snap`, a photo under
# `backup/`) to a CRITICAL "data breach". A real dump carries a dump extension or a
# dump-tool name — and those keys still match.
_BACKUP_KEY_RE = re.compile(
    r"(?i)(?:\.(?:sql|bak|dump|bson)(?:\.(?:gz|tar|tgz|zip|bz2|xz))?$|"
    r"mongodump|mysqldump|pg_?dump|db[-_]?export)")


def extract_dump_keys(listing_body: str) -> list[str]:
    """From a public bucket's XML listing, the object keys that look like a DB
    dump / backup (a directly-downloadable data breach)."""

    out: list[str] = []
    for key in _KEY_TAG_RE.findall(listing_body or ""):
        if _BACKUP_KEY_RE.search(key) and key not in out:
            out.append(key)
    return out
_PREFIXES = ["", "dev-", "prod-", "staging-", "test-", "backup-", "assets-", "cdn-", "s3-"]


def _base_keywords(keyword: str) -> list[str]:
    k = keyword.strip().lower()
    out: list[str] = []

    def add(x: str) -> None:
        if x and x not in out:
            out.append(x)

    # order matters — the registrable label is the highest-value base, so it (and
    # its permutations) come first before the per-base limit truncates the list.
    if "." in k:
        add(k.split(".")[0])       # example.com → example
        add(k.replace(".", "-"))   # example-com
        add(k.replace(".", ""))    # examplecom
        add(k)                     # example.com (dotted; valid but discouraged)
    else:
        add(k)
    return out


def _valid(name: str) -> bool:
    # DNS-style bucket naming: 3-63 chars, lowercase alnum plus - and ., no empty
    # labels (consecutive dots) which S3/GCS/DNS reject.
    return bool(3 <= len(name) <= 63 and ".." not in name
                and re.fullmatch(r"[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]", name))


def generate_bucket_names(keyword: str, limit: int = 120) -> list[str]:
    """Permutate candidate bucket names from *keyword* (pure)."""

    names: dict[str, None] = {}
    for base in _base_keywords(keyword):
        for pre in _PREFIXES:
            for suf in _SUFFIXES:
                cand = f"{pre}{base}{suf}"
                if _valid(cand) and cand not in names:
                    names[cand] = None
                    if len(names) >= limit:
                        return list(names)
    return list(names)


def classify_status(status: int | None) -> str | None:
    """Interpret a bucket-probe HTTP status into an access level (or None=absent)."""

    if status is None:
        return None
    if status == 200:
        return "public-listable"
    if status in (401, 403):
        return "exists-private"
    if status in (301, 302, 307, 308):
        return "exists-redirect"
    return None  # 404 / NoSuchBucket / anything else → treat as absent


async def check_buckets(http_client, names: list[str], *,
                        templates: dict[str, str] | None = None) -> list[dict]:
    """Probe *names* across the provider endpoints; return the ones that exist."""

    tmpl = templates or PROVIDERS

    async def _one(name: str, provider: str, url: str) -> dict | None:
        r = await http_client.fetch(url, method="GET", follow_redirects=False)
        access = classify_status(r.status)
        if access is None:
            return None
        entry: dict = {"name": name, "provider": provider, "url": url,
                       "status": r.status, "access": access}
        # A listable bucket that also holds a DB dump/backup key is a direct data breach.
        if access == "public-listable" and getattr(r, "body", None):
            dumps = extract_dump_keys(r.text(limit=300_000))
            if dumps:
                entry["dump_keys"] = dumps[:20]
                entry["severity"] = "critical"
                entry["detail"] = (f"public bucket lists {len(dumps)} DB dump/backup object(s) "
                                   f"(e.g. {dumps[0]}) — directly downloadable data breach")
        return entry

    jobs = []
    for name in names:
        for provider, t in tmpl.items():
            jobs.append(_one(name, provider, t.format(name=name)))
    results = await asyncio.gather(*jobs)
    found = [r for r in results if r]
    order = {"public-listable": 0, "exists-redirect": 1, "exists-private": 2}
    found.sort(key=lambda f: order.get(f["access"], 9))
    return found
