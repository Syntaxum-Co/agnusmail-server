"""What ships in the package stays separate from what only tests use."""

import re
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[2] / "src" / "agnusmail"


def test_services_never_import_the_test_helpers() -> None:
    """``agnusmail.testing`` holds fakes (in-memory Redis, fake storage): no service may
    import it, or a misconfigured deployment could end up using them."""
    pattern = re.compile(r"^\s*(from|import)\s+agnusmail\.testing\b", re.MULTILINE)
    offenders = [
        str(path.relative_to(PACKAGE))
        for path in PACKAGE.rglob("*.py")
        if "testing" not in path.relative_to(PACKAGE).parts
        and pattern.search(path.read_text(encoding="utf-8"))
    ]
    assert offenders == []
