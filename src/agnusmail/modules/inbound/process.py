"""Process hardening for the inbound gateway: no core dumps, by any path.

Plaintext of external mail lives in this process's memory while it is encrypted. A core
dump would write it to disk. Two independent controls:

- ``RLIMIT_CORE = 0``: no core file. **Not enough on its own**: when the kernel's
  ``core_pattern`` pipes dumps to a program (systemd-coredump, apport), RLIMIT_CORE is
  ignored (core(5): "The RLIMIT_CORE limit is not enforced for core dumps that are piped
  to a program").
- ``prctl(PR_SET_DUMPABLE, 0)``: the process is not dumpable — no core dump at all, and
  other processes of the same user cannot ptrace it or read ``/proc/<pid>/mem``.

Swap is outside the process: the container must have no swap (compose: memswap_limit
equal to mem_limit).
"""

import ctypes
import ctypes.util
import sys

PR_GET_DUMPABLE = 3
PR_SET_DUMPABLE = 4


def _libc() -> ctypes.CDLL:
    return ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)


def is_dumpable() -> bool | None:
    """The kernel's view (Linux only; None elsewhere)."""
    if not sys.platform.startswith("linux"):
        return None
    return bool(_libc().prctl(PR_GET_DUMPABLE, 0, 0, 0, 0))


def harden_process() -> set[str]:
    """Apply what the platform supports; returns the controls that are in effect."""
    applied: set[str] = set()
    try:
        import resource
    except ImportError:  # Windows: local development only
        return applied
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if resource.getrlimit(resource.RLIMIT_CORE) == (0, 0):
        applied.add("rlimit_core")
    if sys.platform.startswith("linux"):
        _libc().prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
        if is_dumpable() is False:
            applied.add("not_dumpable")
    return applied


REQUIRED = frozenset({"rlimit_core", "not_dumpable"})
