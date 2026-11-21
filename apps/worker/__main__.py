"""Background worker entry point: ``python -m apps.worker``.

Runs as the database runtime role; outside the local environment it refuses to start
with a privileged role. SIGTERM/SIGINT stop it after the current job.
"""

import signal
import sys
import threading

from prometheus_client import REGISTRY
from sqlalchemy.orm import sessionmaker

from agnusmail.core.config import get_settings
from agnusmail.core.logging import configure_logging
from agnusmail.infrastructure.database.roles import check_runtime_role
from agnusmail.infrastructure.database.session import create_db_engine
from agnusmail.infrastructure.metrics import DatabaseGauges, start_metrics
from agnusmail.modules import models as _all_models  # noqa: F401  (resolves every FK)
from agnusmail.modules.jobs.worker import Worker


def main() -> int:
    settings = get_settings()
    configure_logging(debug=settings.environment == "local")
    engine = create_db_engine(settings)
    try:
        check_runtime_role(engine, strict=settings.environment != "local")
        if start_metrics(settings):  # plus the queue/health gauges read from the database
            REGISTRY.register(DatabaseGauges(sessionmaker(bind=engine)))
        stop = threading.Event()
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
        signal.signal(signal.SIGINT, lambda *_: stop.set())
        Worker(sessionmaker(bind=engine, expire_on_commit=False), settings).run_forever(stop)
    finally:
        engine.dispose()
    return 0


if __name__ == "__main__":
    sys.exit(main())
