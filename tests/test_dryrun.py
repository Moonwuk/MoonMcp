"""dry_run previews for intrusive probes — see-before-you-fire."""

import pytest

from moonmcp import dryrun
from moonmcp import server as srv


# -- pure --------------------------------------------------------------------
def test_preview_envelope():
    p = dryrun.preview(probe="x_probe", target="http://t/", param="q", method="GET",
                       payloads=["a", "b", "c"])
    assert p["dry_run"] is True
    assert p["probe"] == "x_probe"
    assert p["payload_count"] == 3
    assert p["payloads"] == ["a", "b", "c"]
    assert "nothing was sent" in p["note"]


def test_preview_truncates_large_battery():
    p = dryrun.preview(probe="x", target="t", payloads=[str(i) for i in range(200)])
    assert p["payload_count"] == 200
    assert len(p["payloads"]) == 60
    assert p["_truncated"] == 140


# -- e2e: each wired probe previews without sending --------------------------
_PROBES = [
    ("lfi_probe", srv.lfi_probe, "q"),
    ("ssti_probe", srv.ssti_probe, "q"),
    ("nosqli_probe", srv.nosqli_probe, "user"),
    ("interp_probe", srv.interp_probe, "q"),
]


@pytest.mark.parametrize("name,fn,param", _PROBES)
@pytest.mark.asyncio
async def test_probe_dry_run_previews_without_sending(name, fn, param, fresh_context):
    res = await fn(target="http://127.0.0.1/x", param=param, dry_run=True)
    assert res["dry_run"] is True
    assert res["probe"] == name
    assert res["payload_count"] > 0 and res["payloads"]
    # it's a preview, not a detection run
    assert "verdict" not in res and "findings" not in res


@pytest.mark.asyncio
async def test_dry_run_bypasses_intrusive_gate_but_real_run_is_blocked(fresh_context):
    object.__setattr__(fresh_context.settings, "allow_intrusive", False)  # frozen dataclass
    # the preview works even with intrusive disabled (nothing is sent)
    preview = await srv.lfi_probe(target="http://127.0.0.1/x", param="q", dry_run=True)
    assert preview["dry_run"] is True
    # ...but a REAL run is still gated by the intrusive switch
    blocked = await srv.lfi_probe(target="http://127.0.0.1/x", param="q")
    assert blocked.get("error") == "disabled"


@pytest.mark.asyncio
async def test_dry_run_still_enforces_scope(fresh_context):
    # the scope guard stays ON even for a preview — an off-scope target is refused
    res = await srv.lfi_probe(target="http://8.8.8.8/x", param="q", dry_run=True)
    assert res["error"] == "out_of_scope"
