"""Git-history forensics (git_forensics) — pure git-object parsers + the walk."""

import hashlib
import struct
import zlib

import pytest

from moonmcp import server as srv
from moonmcp.recon import gitdump as gd


# ── helpers to synthesise a tiny exposed .git ───────────────────────────────
def _obj(otype: str, payload: bytes) -> tuple[str, bytes]:
    body = f"{otype} {len(payload)}".encode() + b"\x00" + payload
    return hashlib.sha1(body).hexdigest(), zlib.compress(body)  # noqa: S324


def _tree_entry(mode: str, name: str, sha_hex: str) -> bytes:
    return f"{mode} {name}".encode() + b"\x00" + bytes.fromhex(sha_hex)


def _index_v2(names_shas: list[tuple[str, str]]) -> bytes:
    out = b"DIRC" + struct.pack("!II", 2, len(names_shas))
    for name, sha_hex in names_shas:
        nb = name.encode()
        entry = b"\x00" * 40 + bytes.fromhex(sha_hex) + struct.pack("!H", len(nb)) + nb
        pad = ((len(entry) + 8) & ~7) - len(entry)
        out += entry + b"\x00" * pad
    return out + b"\x00" * 20  # trailing checksum (ignored by the parser)


# ── pure parsers ────────────────────────────────────────────────────────────
def test_parse_object_and_commit_tree_blob():
    blob_sha, blob_raw = _obj("blob", b"AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
    obj = gd.parse_object(blob_raw)
    assert obj.otype == "blob" and b"AKIA" in obj.payload

    tree_payload = _tree_entry("100644", ".env", blob_sha)
    tree_sha, tree_raw = _obj("tree", tree_payload)
    tobj = gd.parse_object(tree_raw)
    entries = gd.parse_tree(tobj.payload)
    assert entries == [("100644", ".env", blob_sha)]

    commit_payload = (f"tree {tree_sha}\n"
                      "author Jane Dev <jane@corp.example> 1700000000 +0000\n"
                      "committer Jane Dev <jane@corp.example> 1700000000 +0000\n\n"
                      "add prod secrets\n").encode()
    _csha, craw = _obj("commit", commit_payload)
    c = gd.parse_commit(gd.parse_object(craw).payload)
    assert c.tree == tree_sha and c.email == "jane@corp.example"
    assert "add prod secrets" in c.message


def test_parse_object_rejects_garbage():
    assert gd.parse_object(b"not zlib") is None
    assert gd.parse_object(zlib.compress(b"no-nul-header")) is None


def test_parse_object_caps_decompression_bomb():
    # A tiny compressed blob that would inflate to 20 MiB must be bounded to the cap,
    # not allocated whole (zlib-bomb guard).
    huge = b"blob 20971520\x00" + b"\x00" * (20 * 1024 * 1024)
    obj = gd.parse_object(zlib.compress(huge))
    assert obj is not None and obj.otype == "blob"
    assert len(obj.payload) <= gd._MAX_OBJECT


def test_parse_index_and_sensitive():
    _s, _r = _obj("blob", b"x")
    sha = hashlib.sha1(b"blob 1\x00x").hexdigest()  # noqa: S324
    idx = _index_v2([(".env", sha), ("src/app.py", sha), ("id_rsa", sha)])
    paths = gd.parse_index(idx)
    assert set(paths) == {".env", "src/app.py", "id_rsa"}
    assert set(gd.sensitive_files(paths)) == {".env", "id_rsa"}


def test_parse_index_v4_skipped():
    assert gd.parse_index(b"DIRC" + struct.pack("!II", 4, 1) + b"junk") == []


def test_shas_creds_object_path():
    assert gd.object_path("ab" + "c" * 38) == ".git/objects/ab/" + "c" * 38
    txt = "0000000000000000000000000000000000000000 " + "a" * 40 + " Jane"
    assert gd.shas_from_text(txt) == ["a" * 40]  # zero-sha dropped
    assert gd.creds_in_remote("url = https://user:tok@github.com/x.git") == \
        ["https://user:tok@github.com/x.git"]
    assert gd.creds_in_remote("url = https://github.com/x.git") == []


# ── orchestrator walk (fake client, deterministic) ──────────────────────────
class _Resp:
    def __init__(self, status, body=b""):
        self.status = status
        self.body = body

    def text(self, limit=None):
        return self.body.decode("utf-8", errors="replace")


class _FakeClient:
    def __init__(self, files: dict[str, bytes]):
        self.files = files

    async def fetch(self, url, **kw):
        from urllib.parse import urlsplit
        path = urlsplit(url).path.lstrip("/")
        body = self.files.get(path)
        return _Resp(200, body) if body is not None else _Resp(404, b"")


def _fake_repo() -> dict[str, bytes]:
    blob_sha, blob_raw = _obj("blob", b"password = ghp_" + b"A" * 36 + b"\n")
    tree_sha, tree_raw = _obj("tree", _tree_entry("100644", ".env", blob_sha))
    commit_payload = (f"tree {tree_sha}\n"
                      "author Bob <bob@corp.example> 1700000000 +0000\n\n"
                      "initial commit ghp_" + "B" * 36 + "\n").encode()
    commit_sha, commit_raw = _obj("commit", commit_payload)
    files = {
        ".git/HEAD": b"ref: refs/heads/main\n",
        ".git/refs/heads/main": (commit_sha + "\n").encode(),
        ".git/config": b"[core]\n[remote \"origin\"]\n\turl = https://u:tok@github.com/a/b.git\n",
        ".git/logs/HEAD": (f"{'0'*40} {commit_sha} Bob <bob@corp.example> 1700000000 +0000\tcommit\n").encode(),
        ".git/index": _index_v2([(".env", blob_sha)]),
        gd.object_path(commit_sha): commit_raw,
        gd.object_path(tree_sha): tree_raw,
        gd.object_path(blob_sha): blob_raw,
    }
    return files


@pytest.mark.asyncio
async def test_git_forensics_walk_finds_history_and_secrets():
    client = _FakeClient(_fake_repo())
    res, hits = await gd.git_forensics(client, "http://t.example/", max_objects=50)
    assert res.git_exposed is True
    # tracked file list + sensitive flagging from the index
    assert ".env" in res.tracked_files and ".env" in res.sensitive_files
    # remote credentials pulled from .git/config
    assert any(s.get("type") == "Git remote credentials" for s in res.secrets)
    # the loose-object walk reached the commit and the blob
    assert res.objects_walked >= 3
    assert any(c["email"] == "bob@corp.example" for c in res.commits)
    # GitHub PATs in the blob and the commit message were scanned out (redacted)
    assert any(h.type == "GitHub PAT" for h in hits)


@pytest.mark.asyncio
async def test_git_forensics_not_exposed():
    res, hits = await gd.git_forensics(_FakeClient({}), "http://t.example/")
    assert res.git_exposed is False and res.review


@pytest.mark.asyncio
async def test_git_forensics_registered(fresh_context):
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "git_forensics" in tools
