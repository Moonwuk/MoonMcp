"""Out-of-band application security testing (OAST) — callback management.

Blind vulnerabilities (blind SSRF, XXE, blind RCE/SQLi, blind XSS) only reveal
themselves through an *out-of-band interaction*: the target reaches out to a
server you control.  This module mints unique callback canaries to embed in
probes and correlates the hits.

It is server-agnostic: point it at your own interaction domain (an
interactsh self-host, a Burp Collaborator instance, or any HTTP callback
collector) via :meth:`OastStore.configure` or the ``MOONMCP_OAST_DOMAIN`` /
``MOONMCP_OAST_POLL_URL`` env vars.  Without a server it still mints and tracks
canaries (useful on its own); polling then just reports the tracked set.
"""

from __future__ import annotations

import os
import secrets
import urllib.parse
from dataclasses import dataclass, field


def _token() -> str:
    """A short, DNS-label-safe correlation token."""

    return secrets.token_hex(8)  # 16 hex chars — valid hostname label


@dataclass
class Callback:
    token: str
    label: str
    canary_host: str | None
    http_url: str
    https_url: str
    dns: str | None


@dataclass
class OastStore:
    """Session-scoped OAST configuration + minted callbacks."""

    interaction_domain: str = ""
    poll_url: str = ""
    # When the built-in self-host catcher is running, canaries are path-based
    # (``http://<host:port>/<token>``) since a bare IP:port has no sub-domains.
    self_host_base: str = ""
    _callbacks: list[Callback] = field(default_factory=list)

    @classmethod
    def from_env(cls) -> OastStore:
        return cls(
            interaction_domain=os.environ.get("MOONMCP_OAST_DOMAIN", "").strip().lstrip("."),
            poll_url=os.environ.get("MOONMCP_OAST_POLL_URL", "").strip(),
        )

    def configure(self, interaction_domain: str | None = None, poll_url: str | None = None) -> None:
        if interaction_domain is not None:
            self.interaction_domain = interaction_domain.strip().lstrip(".")
        if poll_url is not None:
            self.poll_url = poll_url.strip()

    @property
    def configured(self) -> bool:
        return bool(self.interaction_domain or self.poll_url or self.self_host_base)

    def generate(self, label: str = "") -> Callback:
        tok = _token()
        if self.self_host_base:
            base = self.self_host_base
            cb = Callback(token=tok, label=label, canary_host=base,
                          http_url=f"http://{base}/{tok}", https_url=f"https://{base}/{tok}",
                          dns=None)
        elif self.interaction_domain:
            host = f"{tok}.{self.interaction_domain}"
            cb = Callback(token=tok, label=label, canary_host=host,
                          http_url=f"http://{host}/", https_url=f"https://{host}/", dns=host)
        else:
            # No domain configured — still hand back a correlation token + a
            # placeholder the operator can rewrite once a server is set.
            cb = Callback(token=tok, label=label, canary_host=None,
                          http_url=f"http://OAST-UNCONFIGURED/{tok}",
                          https_url=f"https://OAST-UNCONFIGURED/{tok}", dns=None)
        self._callbacks.append(cb)
        return cb

    def get(self, token: str) -> Callback | None:
        t = token.strip().lower()
        for cb in self._callbacks:
            if cb.token == t:
                return cb
        return None

    def list(self) -> list[Callback]:
        return list(self._callbacks)

    def poll_target(self, token: str | None) -> str | None:
        """The URL to GET when polling for interactions, or None if unconfigured."""

        if not self.poll_url:
            return None
        if "{token}" in self.poll_url:
            return self.poll_url.replace("{token}", urllib.parse.quote(token or ""))
        if token:
            sep = "&" if "?" in self.poll_url else "?"
            return f"{self.poll_url}{sep}token={urllib.parse.quote(token)}"
        return self.poll_url


def parse_interactions(body: str) -> list[dict]:
    """Best-effort parse of a poll response body into a list of interaction dicts.

    Accepts a JSON list, a ``{"interactions"|"data": [...]}`` envelope, or a
    JSON object; falls back to an empty list on anything unparseable.
    """

    import json

    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return []
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    if isinstance(data, dict):
        for key in ("interactions", "data", "results", "hits"):
            v = data.get(key)
            if isinstance(v, list):
                return [d for d in v if isinstance(d, dict)]
        # A dict with no list of interactions is only a real hit if it LOOKS like a
        # single interaction record — otherwise an empty/error poll envelope
        # (e.g. interactsh's {"data": null, "aes_key": ...}) would be miscounted as
        # one interaction and falsely "confirm" a blind vuln.
        interaction_fields = {"protocol", "remote-address", "remoteaddress", "unique-id",
                              "uniqueid", "full-id", "fullid", "raw-request", "rawrequest",
                              "q-type", "qtype"}
        if {k.lower() for k in data} & interaction_fields:
            return [data]
        return []
    return []
