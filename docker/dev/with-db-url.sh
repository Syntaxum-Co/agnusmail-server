#!/bin/sh
# Development only: build AGNUSMAIL_DATABASE_URL from the .env parts (URL-encoding the
# password) pointing at the compose "postgres" service, then run the given command.
set -eu
AGNUSMAIL_DATABASE_URL="$(python -c 'import os, urllib.parse as u; e = os.environ; q = lambda k: u.quote(e[k], safe=""); print("postgresql+psycopg://%s:%s@postgres:5432/%s" % (q("AGNUSMAIL_DB_USER"), q("AGNUSMAIL_DB_PASSWORD"), q("AGNUSMAIL_DB_NAME")))')"
export AGNUSMAIL_DATABASE_URL
exec "$@"
