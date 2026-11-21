"""Gateway process hardening: no core dumps by any path."""

import subprocess
import sys

import pytest

PROBE = """
from agnusmail.modules.inbound.process import harden_process, is_dumpable
import resource
before = is_dumpable()
applied = sorted(harden_process())
print(before, is_dumpable(), resource.getrlimit(resource.RLIMIT_CORE), applied)
"""


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="prctl is Linux-only")
def test_the_gateway_process_cannot_dump_core() -> None:
    # A separate interpreter: hardening changes the process it runs in.
    out = subprocess.run(  # noqa: S603  (fixed interpreter and code)
        [sys.executable, "-c", PROBE], check=True, capture_output=True, text=True
    ).stdout.split(" ", 2)
    before, after, rest = out
    assert before == "True"  # a normal process is dumpable
    assert after == "False"  # RLIMIT_CORE alone is ignored by piped core_pattern
    assert rest.strip() == "(0, 0) ['not_dumpable', 'rlimit_core']"
