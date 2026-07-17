"""Apache Shiro-550 default-key oracle (safe key recovery)."""

import base64

import pytest

from moonmcp.web import shiro, stacks


# -- a faithful "fake Shiro": decrypt rememberMe with the configured key; a clean
#    SimplePrincipalCollection deserialize (valid padding + Java magic) → keep, else delete.
def _decrypts_clean(cookie_value: str, key_b64: str) -> bool:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7
    try:
        raw = base64.b64decode(cookie_value)
        iv, ct = raw[:16], raw[16:]
        dec = Cipher(algorithms.AES(base64.b64decode(key_b64)), modes.CBC(iv)).decryptor()
        pt = dec.update(ct) + dec.finalize()
        plain = PKCS7(128).unpadder()
        out = plain.update(pt) + plain.finalize()
        return out[:4] == b"\xac\xed\x00\x05"     # valid Java serialization → Shiro proceeds
    except Exception:
        return False


def test_default_keys_all_valid_16_byte_aes():
    for k in shiro.DEFAULT_KEYS:
        assert len(base64.b64decode(k)) == 16, k
    assert shiro.CHECK_BLOB[:4] == b"\xac\xed\x00\x05"           # benign SimplePrincipalCollection


@pytest.mark.asyncio
async def test_recover_key_finds_the_in_use_default():
    real = shiro.DEFAULT_KEYS[7]

    async def deletes(cookie):
        return not _decrypts_clean(cookie, real)          # only the real key decrypts clean
    assert await shiro.recover_key(deletes) == real


@pytest.mark.asyncio
async def test_recover_key_none_for_custom_key():
    custom = base64.b64encode(b"custom-key-16byt").decode()   # not a shipped default

    async def deletes(cookie):
        return not _decrypts_clean(cookie, custom)
    assert await shiro.recover_key(deletes) is None


@pytest.mark.asyncio
async def test_recover_key_none_when_tell_unreliable():
    async def never_deletes(cookie):
        return False                                        # endpoint never emits the tell
    # the garbage-key negative control fails to delete → we refuse to claim a match
    assert await shiro.recover_key(never_deletes) is None


# -- end-to-end through _probe_shiro ----------------------------------------
class _R:
    def __init__(self, status=200, set_cookies=None):
        self.status = status
        self._sc = set_cookies or []

    def get_all(self, name):
        return list(self._sc) if name.lower() == "set-cookie" else []


class _ShiroClient:
    """rememberMe=1 (undecryptable) → deleteMe; a cookie that decrypts clean under
    *real_key* → kept; everything else → deleteMe."""

    def __init__(self, real_key):
        self.real_key = real_key

    async def fetch(self, url, *, headers=None, **kw):
        cookie = (headers or {}).get("Cookie", "").split("rememberMe=", 1)[-1]
        deletes = not _decrypts_clean(cookie, self.real_key)
        return _R(200, ["rememberMe=deleteMe; Path=/; HttpOnly"] if deletes
                  else ["rememberMe=keep; Path=/"])


@pytest.mark.asyncio
async def test_probe_shiro_recovers_default_key():
    real = shiro.DEFAULT_KEYS[3]
    finding = await stacks._probe_shiro(_ShiroClient(real), "https://x.test", None)
    assert finding["verdict"] == "confirmed" and finding["severity"] == "high"
    assert finding["recovered_key"] == real


@pytest.mark.asyncio
async def test_probe_shiro_custom_key_is_fingerprint_only():
    custom = base64.b64encode(b"custom-key-16byt").decode()
    finding = await stacks._probe_shiro(_ShiroClient(custom), "https://x.test", None)
    assert finding["verdict"] == "fingerprint" and "recovered_key" not in finding


@pytest.mark.asyncio
async def test_probe_shiro_not_shiro_returns_none():
    class _NotShiro:
        async def fetch(self, url, **kw):
            return _R(200, [])                              # never sets rememberMe=deleteMe
    assert await stacks._probe_shiro(_NotShiro(), "https://x.test", None) is None
