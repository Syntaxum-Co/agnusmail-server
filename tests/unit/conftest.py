import os
from collections.abc import Iterator

import pytest
from hypothesis import settings

from tests.unit.fakes import dispose_test_engines

# Fuzzing depth: the default keeps the suite fast; HYPOTHESIS_PROFILE=deep for a long run.
settings.register_profile("default", max_examples=100)
settings.register_profile("deep", max_examples=3000, deadline=None)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "default"))


@pytest.fixture(autouse=True)
def _dispose_sqlite_engines() -> Iterator[None]:
    yield
    dispose_test_engines()
