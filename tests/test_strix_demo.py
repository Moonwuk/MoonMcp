"""The `strix_demo` tool — verify the live-watch window without a real Strix run.

The demo must send NO network traffic and need neither Strix nor Docker; it just
streams canned lines into the log the console follows. These tests exercise the
argv builder and actually RUN the streamer child (with zero delay) to prove it
writes the confirmed-finding transcript.
"""

import os
import pathlib
import subprocess
import sys

# examples/ is not an installed package — make the repo root importable.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from examples.strix_mcp import server as strix  # noqa: E402


def test_demo_stream_argv_shape():
    argv = strix._demo_stream_argv("/tmp/x.log", "acme.test")
    assert argv[0] == sys.executable and argv[1] == "-c"
    assert "Strix (DEMO)" in argv[2]
    assert argv[-2:] == ["/tmp/x.log", "acme.test"]


def test_demo_stream_writes_confirmed_transcript(tmp_path):
    log = tmp_path / "demo.log"
    log.write_text("")  # the streamer appends to an existing file
    env = {**os.environ, "MOONMCP_DEMO_DELAY": "0"}  # run instantly
    subprocess.run(strix._demo_stream_argv(str(log), "acme.test"),
                   env=env, timeout=30, check=True)
    text = log.read_text()
    assert "acme.test" in text          # the target is echoed
    assert "CONFIRMED" in text          # the scripted finding lands
    assert "[done]" in text             # and the run completes


def test_demo_stream_is_network_free_source():
    # The embedded script must not IMPORT anything that touches the network — only
    # the stdlib basics. Inspect actual import statements, not prose.
    imports = [ln.strip() for ln in strix._DEMO_SCRIPT.splitlines()
               if ln.strip().startswith(("import ", "from "))]
    assert imports == ["import os, sys, time"]
