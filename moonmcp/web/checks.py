"""Explicit subcheck coverage for composite probes; never infer clean negatives."""

from __future__ import annotations

from ..scope import ScopeError


class ProbeChecks:
    def __init__(self) -> None:
        self.items: list[dict] = []
        self.stopped = False

    async def fetch(self, client, url: str, *, check: str, identity: str = "",
                    **kwargs):
        if self.stopped:
            self.missing(check, "prior_check_stopped", identity=identity)
            return None
        item = {"check": check, "identity": identity, "url": url,
                "status": None, "state": "completed", "error": None}
        self.items.append(item)
        try:
            response = await client.fetch(url, **kwargs)
        except Exception as exc:
            # Cancellation is a BaseException and must reach managed recovery.
            code = getattr(exc, "code", "request_failed")
            state = "blocked" if isinstance(exc, ScopeError) or hasattr(exc, "code") else "failed"
            if isinstance(exc, ScopeError):
                code = "out_of_scope"
            if state != "blocked" and kwargs.get("method", "GET").upper() not in {"GET", "HEAD"}:
                state = "unknown"
            item.update(state=state, error=code)
            self.stopped = True
            return None
        item["status"] = response.status
        if getattr(response, "blocked_reason", None) or getattr(response, "redirect_blocked", None):
            item.update(state="blocked", error="request_blocked")
            self.stopped = True
        elif getattr(response, "error", None) or response.status is None:
            state = "failed" if kwargs.get("method", "GET").upper() in {"GET", "HEAD"} else "unknown"
            item.update(state=state, error="transport_error")
            self.stopped = state == "unknown"
        elif response.status == 429 or response.status >= 500:
            state = "failed" if kwargs.get("method", "GET").upper() in {"GET", "HEAD"} else "unknown"
            item.update(state=state, error="rate_limited" if response.status == 429 else "upstream_error")
            # A rate limit applies to the remaining probe too, including safe
            # reads. Do not keep sending sibling or later workflow requests.
            self.stopped = response.status == 429 or state == "unknown"
        elif getattr(response, "truncated", False):
            item.update(state="partial", error="truncated_response")
        return response if item["state"] == "completed" else None

    def missing(self, check: str, reason: str, *, identity: str = "") -> None:
        self.items.append({"check": check, "identity": identity, "status": None,
                           "state": "skipped", "error": reason})

    def finish(self, payload: dict, *, negative: str) -> dict:
        complete = bool(self.items) and all(item["state"] == "completed" for item in self.items)
        completed = sum(item["state"] == "completed" for item in self.items)
        states = {item["state"] for item in self.items}
        state = ("completed" if complete else "unknown" if "unknown" in states else
                 "partial" if completed else "blocked" if "blocked" in states else "failed")
        payload.update(result_version=2, ok=complete, state=state,
                       checks=self.items,
                       coverage={"version": 1, "complete": complete,
                                 "completed": completed, "total": len(self.items)},
                       verdict="review" if payload.get("findings") else negative if complete else "inconclusive")
        if not complete:
            payload.update(error="incomplete_checks", retryable=False,
                           detail="Some required checks lack usable evidence; inspect checks and coverage.",
                           recovery="Review incomplete checks and possible effects before scheduling further work.")
        return payload
