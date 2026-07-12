"""Git-history forensics over an exposed ``.git`` (dumb-HTTP, read-only).

`vcs_exposure` confirms a ``.git`` is exposed; this goes deeper — it reconstructs
**history** from what the server already serves and mines it for secrets, the
classic stable-Critical bug-bounty win. Everything here is read-only HTTP GETs of
files the target itself publishes; nothing is written, and exploitation is left to
git-dumper / Strix.

What it recovers without a full clone:

* **`.git/config`** — remote URLs (often ``https://user:token@host`` → credentials).
* **`.git/logs/HEAD`** (reflog) — every commit SHA + author name/email + message.
* **`.git/index`** — the tracked file list (``.env`` / ``id_rsa`` / ``*.sql`` /
  ``credentials`` reveal *what* secrets exist), parsed from the binary DIRC format.
* **Loose objects** — a bounded walk of ``objects/<xx>/<38hex>`` (zlib-inflate →
  parse commit → tree → blob), running the secret scanner over each blob and
  commit message.
* **Packed history** — detected (``objects/info/packs`` / ``objects/pack/*.pack``)
  and *reported*: delta-compressed packs need git-dumper/Strix, so we flag rather
  than pretend to have covered them (no silent truncation).

Pure parsers (trivially testable) live here; scope-gating + the secret scan live in
the ``git_forensics`` server tool.

Sources: https://git-scm.com/docs/gitformat-index · https://github.com/arthaud/git-dumper
"""

from __future__ import annotations

import re
import struct
import zlib
from dataclasses import dataclass, field
from urllib.parse import urljoin

from ..net.http import HttpClient

_SHA_RE = re.compile(r"\b[0-9a-f]{40}\b")
# Cap loose-object inflation — a small compressed object can zlib-bomb to gigabytes,
# so bound the decompressed size (the header + enough payload to parse and scan).
_MAX_OBJECT = 5 * 1024 * 1024
_REF_RE = re.compile(r"^[\w][\w./-]*$")  # a sane ref path (no scheme, no traversal)
# Tracked filenames that, by themselves, signal exposed secrets/material.
_SENSITIVE_NAME_RE = re.compile(
    r"(?i)(?:^|/)(?:\.env|\.envrc|\.env\.[\w.]+|id_rsa|id_dsa|id_ecdsa|id_ed25519|"
    r".*\.pem|.*\.key|.*\.pfx|.*\.p12|.*\.ppk|.*\.keystore|.*\.jks|"
    r"secrets?\.[\w.]+|credentials?(?:\.[\w.]+)?|\.netrc|\.pgpass|\.htpasswd|"
    r"database\.ya?ml|secrets\.ya?ml|.*\.sql|.*\.sqlite3?|.*\.bak|.*\.dump|"
    r"terraform\.tfstate|.*\.tfvars|serviceaccount.*\.json|.*\.p8|wp-config\.php|"
    r"config/master\.key|.*\.ovpn)(?:$|[?#])")


@dataclass
class GitObject:
    sha: str
    otype: str            # commit / tree / blob / tag
    size: int
    payload: bytes


@dataclass
class Commit:
    sha: str
    tree: str | None
    parents: list[str] = field(default_factory=list)
    author: str = ""
    email: str = ""
    message: str = ""


def object_path(sha: str) -> str:
    """``<sha>`` → the loose-object path ``objects/ab/cdef...`` (pure)."""

    sha = sha.strip().lower()
    return f".git/objects/{sha[:2]}/{sha[2:]}"


def parse_object(raw: bytes) -> GitObject | None:
    """Inflate + split a loose git object ``"<type> <size>\\0<payload>"`` (pure).
    ``raw`` is the raw (zlib-compressed) bytes as served. Returns None on garbage."""

    try:
        dobj = zlib.decompressobj()
        data = dobj.decompress(raw, _MAX_OBJECT)  # bounded — decompression-bomb guard
    except zlib.error:
        return None
    nul = data.find(b"\x00")
    if nul < 0:
        return None
    header = data[:nul].decode("latin-1", errors="replace")
    parts = header.split(" ", 1)
    if len(parts) != 2 or parts[0] not in ("commit", "tree", "blob", "tag"):
        return None
    otype = parts[0]
    try:
        size = int(parts[1])
    except ValueError:
        size = len(data) - nul - 1
    return GitObject(sha="", otype=otype, size=size, payload=data[nul + 1:])


def parse_commit(payload: bytes) -> Commit:
    """Parse a commit object payload → tree, parents, author, email, message (pure)."""

    text = payload.decode("utf-8", errors="replace")
    head, _, message = text.partition("\n\n")
    c = Commit(sha="", tree=None, message=message.strip())
    for line in head.splitlines():
        if line.startswith("tree "):
            c.tree = line[5:].strip()
        elif line.startswith("parent "):
            c.parents.append(line[7:].strip())
        elif line.startswith("author "):
            c.author = line[7:].strip()
            m = re.search(r"<([^>]+)>", line)
            if m:
                c.email = m.group(1)
    return c


def parse_tree(payload: bytes) -> list[tuple[str, str, str]]:
    """Parse a tree object → ``[(mode, name, sha_hex)]`` (pure). Tree entries are
    ``<mode> <name>\\0<20 raw sha bytes>`` back-to-back."""

    out: list[tuple[str, str, str]] = []
    i, n = 0, len(payload)
    while i < n:
        sp = payload.find(b" ", i)
        nul = payload.find(b"\x00", sp)
        if sp < 0 or nul < 0 or nul + 20 > n:
            break
        mode = payload[i:sp].decode("latin-1", errors="replace")
        name = payload[sp + 1:nul].decode("utf-8", errors="replace")
        sha = payload[nul + 1:nul + 21].hex()
        out.append((mode, name, sha))
        i = nul + 21
    return out


def parse_index(raw: bytes, *, max_entries: int = 5000) -> list[str]:
    """Parse a ``.git/index`` (DIRC v2/v3) → the tracked file paths (pure). v4 uses
    path-prefix compression and is skipped (returns ``[]``)."""

    if len(raw) < 12 or raw[:4] != b"DIRC":
        return []
    version, count = struct.unpack("!II", raw[4:12])
    if version not in (2, 3):
        return []  # v4 path-compression not handled — caller notes it
    paths: list[str] = []
    off = 12
    for _ in range(min(count, max_entries)):
        if off + 62 > len(raw):
            break
        flags = struct.unpack("!H", raw[off + 60:off + 62])[0]
        name_len = flags & 0x0FFF
        extended = bool(flags & 0x4000)  # v3 extended flag → 2 more bytes
        name_start = off + 62 + (2 if extended else 0)
        if name_len == 0x0FFF:  # name longer than 0xFFF: read to the NUL
            nul = raw.find(b"\x00", name_start)
            if nul < 0:
                break
            name = raw[name_start:nul]
        else:
            name = raw[name_start:name_start + name_len]
        paths.append(name.decode("utf-8", errors="replace"))
        consumed = (name_start - off) + len(name)
        padded = (consumed + 8) & ~7  # ≥1 NUL, entry length a multiple of 8
        off += padded
    return paths


def sensitive_files(paths: list[str]) -> list[str]:
    """The subset of *paths* whose name signals secret material (pure)."""

    return [p for p in paths if _SENSITIVE_NAME_RE.search(p)]


def shas_from_text(text: str, limit: int = 500) -> list[str]:
    """Every 40-hex SHA in *text* (reflog, packed-refs, a ref file), de-duped,
    order-preserving (pure)."""

    seen: set[str] = set()
    out: list[str] = []
    for m in _SHA_RE.finditer(text or ""):
        s = m.group(0)
        if s not in seen and s != "0" * 40:
            seen.add(s)
            out.append(s)
            if len(out) >= limit:
                break
    return out


def creds_in_remote(config_text: str) -> list[str]:
    """Remote URLs embedding credentials (``scheme://user:pass@host``) (pure)."""

    out: list[str] = []
    for m in re.finditer(r"url\s*=\s*(\S+)", config_text or ""):
        url = m.group(1)
        if re.match(r"\w+://[^/@\s]+:[^/@\s]+@", url):
            out.append(url)
    return out


# ── async orchestration (bounded, read-only) ────────────────────────────────

# The plain metadata files worth pulling directly (each may hold secrets/SHAs).
_META_FILES = (
    ".git/HEAD", ".git/config", ".git/logs/HEAD", ".git/packed-refs",
    ".git/index", ".git/COMMIT_EDITMSG", ".git/description", ".git/FETCH_HEAD",
    ".git/ORIG_HEAD", ".git/info/refs",
)


@dataclass
class GitForensicsResult:
    base_url: str
    git_exposed: bool = False
    fetched: list[str] = field(default_factory=list)
    tracked_files: list[str] = field(default_factory=list)
    sensitive_files: list[str] = field(default_factory=list)
    commits: list[dict] = field(default_factory=list)
    secrets: list[dict] = field(default_factory=list)
    packed_history: bool = False
    objects_walked: int = 0
    review: list[str] = field(default_factory=list)
    error: str | None = None


async def git_forensics(client: HttpClient, base_url: str, *, scope_check=None,
                        max_objects: int = 60, timeout: float = 10.0):
    """Reconstruct history from an exposed ``.git`` and mine it for secrets. Bounded
    to *max_objects* loose objects. All GETs are scope-checked by the caller's
    ``scope_check``. Returns a ``GitForensicsResult`` + the raw secret hits so the
    server tool can redact/record them."""

    from .secrets import scan_text

    res = GitForensicsResult(base_url=base_url)
    raw_hits: list = []

    async def _get(path: str):
        r = await client.fetch(urljoin(base_url, path), follow_redirects=False,
                               timeout=timeout, scope_check=scope_check)
        return r

    # 1) metadata sweep
    meta: dict[str, bytes] = {}
    for path in _META_FILES:
        r = await _get(path)
        if r.status == 200 and r.body:
            body = r.body
            head = body.lstrip()[:200].lower()
            if head.startswith(b"<!doctype html") or b"<html" in head:
                continue  # soft-404
            meta[path] = body
            res.fetched.append(path)

    head_txt = meta.get(".git/HEAD", b"").decode("latin-1", errors="replace")
    if ".git/HEAD" not in meta or not head_txt.startswith("ref:") and not _SHA_RE.search(head_txt):
        res.review.append("No confirmable .git/HEAD — .git not exposed here (or blocked).")
        return res, raw_hits
    res.git_exposed = True

    # 2) config → remote creds
    config_txt = meta.get(".git/config", b"").decode("utf-8", errors="replace")
    for url in creds_in_remote(config_txt):
        res.secrets.append({"type": "Git remote credentials", "source": ".git/config",
                            "detail": re.sub(r"://[^@]+@", "://***:***@", url)})
    raw_hits += scan_text(config_txt, source=".git/config")

    # 3) index → tracked + sensitive file list
    idx = meta.get(".git/index")
    if idx:
        res.tracked_files = parse_index(idx)
        res.sensitive_files = sensitive_files(res.tracked_files)
        if not res.tracked_files and idx[:4] == b"DIRC":
            res.review.append("Git index is v4 (path-compressed) — file list skipped.")

    # 4) collect starting SHAs from reflog + packed-refs + HEAD ref
    reflog = meta.get(".git/logs/HEAD", b"").decode("utf-8", errors="replace")
    packed = meta.get(".git/packed-refs", b"").decode("utf-8", errors="replace")
    info_refs = meta.get(".git/info/refs", b"").decode("utf-8", errors="replace")
    raw_hits += scan_text(reflog, source=".git/logs/HEAD")
    queue: list[str] = shas_from_text(reflog + "\n" + packed + "\n" + info_refs)
    if head_txt.startswith("ref:"):
        ref = head_txt[4:].strip()
        if _REF_RE.match(ref) and ".." not in ref:  # never fetch a traversal/scheme ref
            rr = await _get(f".git/{ref}")
            if rr.status == 200 and rr.body:
                queue = shas_from_text(rr.text()) + queue
    elif _SHA_RE.search(head_txt):
        queue = shas_from_text(head_txt) + queue

    # 5) bounded loose-object walk: commit → tree → blob, scanning blobs for secrets
    seen: set[str] = set()
    pending = list(dict.fromkeys(queue))
    while pending and res.objects_walked < max_objects:
        sha = pending.pop(0)
        if sha in seen:
            continue
        seen.add(sha)
        r = await _get(object_path(sha))
        if r.status != 200 or not r.body:
            continue
        obj = parse_object(r.body)
        if obj is None:
            continue
        res.objects_walked += 1
        if obj.otype == "commit":
            c = parse_commit(obj.payload)
            res.commits.append({"sha": sha[:12], "author": c.author.split("<")[0].strip(),
                                "email": c.email, "message": c.message.splitlines()[0][:120]
                                if c.message else ""})
            raw_hits += scan_text(c.message, source=f"commit {sha[:12]}")
            if c.tree and c.tree not in seen:
                pending.append(c.tree)
            pending.extend(p for p in c.parents if p not in seen)
        elif obj.otype == "tree":
            for _mode, _name, csha in parse_tree(obj.payload):
                if csha not in seen:
                    pending.append(csha)
        elif obj.otype == "blob":
            raw_hits += scan_text(obj.payload.decode("utf-8", errors="replace"),
                                  source=f"blob {sha[:12]}")

    # 6) packed history detection (we don't parse packs — flag for delegation)
    packs = await _get(".git/objects/info/packs")
    if packs.status == 200 and b"pack-" in (packs.body or b""):
        res.packed_history = True
    if res.packed_history or (info_refs and not res.objects_walked):
        res.review.append(
            "Packed history present (objects/info/packs). Loose-object walk can't read "
            "delta-compressed packs — run git-dumper / delegate to Strix for the full "
            "history if the loose walk didn't surface enough.")

    if res.sensitive_files:
        res.review.append(
            f"Tracked sensitive files present: {', '.join(res.sensitive_files[:8])}. "
            "Fetch their blobs from history for likely credentials.")
    if res.secrets or raw_hits:
        res.review.append(
            f"{len(res.secrets) + len(raw_hits)} secret indicator(s) across git history — "
            "CONFIRM each is live (not rotated) before reporting; redacted here.")
    return res, raw_hits
