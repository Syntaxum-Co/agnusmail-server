"""Tests run as the local environment unless a test says otherwise.

The settings default to ``production`` (secure by default); the integration tests build
``Settings()`` from the process environment, so opt them into ``local`` here.
"""

import os

os.environ.setdefault("AGNUSMAIL_ENVIRONMENT", "local")
