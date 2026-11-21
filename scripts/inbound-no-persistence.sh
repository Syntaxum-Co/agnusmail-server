#!/bin/sh
# Proof that no plaintext of external mail persists — on the real
# containers of the dev compose: gateway, Rspamd, PostgreSQL, Redis.
#
#   scripts/inbound-no-persistence.sh
#
# A random marker goes in the envelope, headers and body of an accepted message, a
# spam message Rspamd rejects (GTUBE) and an oversized one. Then the gateway is
# crashed with SIGSEGV, and the marker is searched in: the gateway's filesystem
# (read-only: nothing may change) and key volume, Rspamd's filesystem, the logs of the
# gateway, Rspamd and API, every table and every Redis key/value. It also checks the
# container has no swap and the process is not dumpable.
#
# Needs: Docker, the dev .env, and the test venv volume (scripts/… uses the same
# throwaway python:3.13-slim container as the test runs). Exit 0 = proof passed.
set -eu
cd "$(dirname "$0")/.."
SRC=$(pwd -W 2>/dev/null || pwd)
export MSYS_NO_PATHCONV=1
NETWORK=agnusmail_default
MARKER="testonly$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
FAILED=0

fail() { echo "FAIL: $*"; FAILED=1; }
ok() { echo "ok:   $*"; }

driver() {
  docker run --rm --network "$NETWORK" --env-file .env \
    -v "$SRC:/src:ro" -v agnusmail-test-venv:/venv -v agnusmail-test-uvcache:/root/.cache/uv \
    -e UV_PROJECT_ENVIRONMENT=/venv -e UV_LINK_MODE=copy python:3.13-slim sh -c '
      set -e
      mkdir /work && cd /src && tar --exclude=.venv --exclude=.git --exclude=__pycache__ -cf - . | tar -xf - -C /work
      cd /work
      export AGNUSMAIL_DATABASE_URL="$(python -c "import os,urllib.parse as u;q=lambda k:u.quote(os.environ[k],safe=\"\");print(f\"postgresql+psycopg://{q(\"AGNUSMAIL_DB_USER\")}:{q(\"AGNUSMAIL_DB_PASSWORD\")}@postgres:5432/{q(\"AGNUSMAIL_DB_NAME\")}\")")"
      export AGNUSMAIL_REDIS_URL="redis://redis:6379/0" PYTHONPATH=/work
      command -v uv >/dev/null 2>&1 || pip install -q uv==0.13.7 >/dev/null 2>&1
      uv sync --locked -q
      uv run --no-sync python scripts/inbound_persistence_driver.py "$@"' sh "$@"
}

echo "== services (gateway with the test helpers' SIWE domain, so it accepts their keys)"
docker compose --profile app up -d --build --wait migrate api rspamd >/dev/null 2>&1
DEV_FRONTEND_HOST=app.agnusmail docker compose --profile app up -d --force-recreate smtp-inbound >/dev/null 2>&1
GATEWAY=$(docker compose ps -q smtp-inbound)
for _ in $(seq 1 30); do
  docker compose logs smtp-inbound 2>&1 | grep -q inbound_smtp_listening && break
  sleep 1
done

echo "== container and process hardening"
set -- $(docker inspect -f '{{.HostConfig.ReadonlyRootfs}} {{.HostConfig.Memory}} {{.HostConfig.MemorySwap}}' "$GATEWAY")
[ "$1" = true ] && ok "read-only root filesystem" || fail "root filesystem is writable"
[ "$2" -gt 0 ] && [ "$2" = "$3" ] && ok "no swap (memory $2 = memory+swap $3)" || fail "swap allowed ($2/$3)"
# The gateway's PID (PID 1 is the init process, see compose "init: true").
PID=$(docker exec "$GATEWAY" sh -c 'for d in /proc/[0-9]*; do [ "$(tr "\000" " " < "$d/cmdline" 2>/dev/null)" = "python -m agnusmail.apps.smtp_inbound " ] && echo "${d#/proc/}"; done' | head -n 1)
[ -n "$PID" ] && [ "$PID" != 1 ] && ok "gateway runs as PID $PID under an init" || fail "gateway PID '$PID'"
if docker exec "$GATEWAY" cat "/proc/$PID/environ" >/dev/null 2>&1; then
  fail "gateway is dumpable (its /proc files are readable by its own user)"
else
  ok "gateway not dumpable (/proc/$PID closed even to its own user)"
fi

echo "== traffic with marker $MARKER"
ADDRESS=$(driver send "$MARKER")
ok "accepted 250, Rspamd rejected GTUBE 550, oversized 552 (to $ADDRESS)"

echo "== crash the gateway (SIGSEGV)"
# From inside: the init does not forward synchronous signals such as SIGSEGV.
docker exec "$GATEWAY" sh -c "kill -SEGV $PID"
for _ in $(seq 1 15); do
  [ "$(docker inspect -f '{{.State.Running}}' "$GATEWAY")" = false ] && break
  sleep 1
done
echo "      host core_pattern: $(docker run --rm python:3.13-slim cat /proc/sys/kernel/core_pattern)"
CODE=$(docker inspect -f '{{.State.ExitCode}}' "$GATEWAY")
[ "$CODE" = 139 ] && ok "gateway died of SIGSEGV (exit 139)" || fail "gateway did not crash (exit $CODE)"
# Mount points (bind mount, volume, the init binary) show up as changes; anything else
# is a write by the container.
CHANGES=$(docker diff "$GATEWAY" | grep -v -x -e 'A /dev-scripts' -e '[AC] /var/lib/agnusmail/gateway' \
  -e 'C /usr' -e 'C /usr/sbin' -e 'A /usr/sbin/docker-init' || true)
[ -z "$CHANGES" ] && ok "gateway filesystem unchanged (no file, no core)" || fail "gateway filesystem changed: $CHANGES"

echo "== search for the marker"
if docker run --rm -v agnusmail_gateway-key:/k:ro python:3.13-slim grep -rqa "$MARKER" /k; then
  fail "marker in the gateway key volume"
else
  ok "gateway key volume"
fi
if docker compose exec -T rspamd sh -c "grep -rlaI -e '$MARKER' / --exclude-dir=proc --exclude-dir=sys --exclude-dir=dev 2>/dev/null; grep -rla -e '$MARKER' /var/lib/rspamd /tmp 2>/dev/null" | grep -q .; then
  fail "marker in Rspamd's filesystem"
else
  ok "Rspamd filesystem"
fi
if docker compose logs --no-color smtp-inbound rspamd api 2>&1 | grep -q "$MARKER"; then
  fail "marker in the logs"
else
  ok "logs of gateway, Rspamd and API"
fi
if driver scan "$MARKER" "$ADDRESS"; then
  ok "every table and every Redis key/value (search controls passed)"
else
  fail "marker in PostgreSQL or Redis"
fi

echo "== restore the dev gateway"
docker compose --profile app up -d --force-recreate smtp-inbound >/dev/null 2>&1

[ "$FAILED" = 0 ] && echo "PASS: nothing in clear persisted" || echo "FAILED"
exit "$FAILED"
