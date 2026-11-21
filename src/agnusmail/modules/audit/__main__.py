"""Entry point: python -m agnusmail.modules.audit {verify,purge}."""

import sys

from agnusmail.modules.audit.cli import main

sys.exit(main())
