"""Background worker entry point: ``python -m agnusmail.apps.worker``.

Runs as the database runtime role; outside the local environment it refuses to start
with a privileged role. Extensions add their own jobs and schedule. SIGTERM/SIGINT stop
it after the current job.
"""

import signal
import sys
import threading

from prometheus_client import REGISTRY
from sqlalchemy.orm import sessionmaker

from agnusmail.core.config import get_settings
from agnusmail.core.logging import configure_logging
from agnusmail.extensions import from_settings
from agnusmail.infrastructure.database.roles import check_runtime_role
from agnusmail.infrastructure.database.session import create_db_engine
from agnusmail.infrastructure.metrics import DatabaseGauges, start_metrics
from agnusmail.modules import models as _all_models  # noqa: F401  (resolves every FK)
from agnusmail.modules.jobs.handlers import JOBS, SCHEDULE
from agnusmail.modules.jobs.queue import JobRegistry
from agnusmail.modules.jobs.worker import Worker


def main() -> int:
    settings = get_settings()
    configure_logging(debug=settings.environment == "local")
    extensions = from_settings(settings)
    registry = JobRegistry(extensions.jobs(JOBS))
    schedule = extensions.schedule(SCHEDULE)
    engine = create_db_engine(settings)
    try:
        check_runtime_role(engine, strict=settings.environment != "local")
        if start_metrics(settings):  # plus the queue/health gauges read from the database
            REGISTRY.register(DatabaseGauges(sessionmaker(bind=engine)))
        stop = threading.Event()
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
        signal.signal(signal.SIGINT, lambda *_: stop.set())
        factory = sessionmaker(bind=engine, expire_on_commit=False)
        Worker(factory, settings, registry=registry, schedule=schedule).run_forever(stop)
    finally:
        engine.dispose()
    return 0


if __name__ == "__main__":
    sys.exit(main())
