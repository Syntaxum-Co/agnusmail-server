#!/bin/sh
# Cross-library interoperability test: OpenPGP.js (web client role) <-> server + Sequoia.
# Protocol v1 §14. Requires Docker. OpenPGP.js is built from a pinned commit because the
# released 6.x has no RFC 9980 support yet (v7 is unreleased); the build runs in a
# throwaway container and is used only by this test.
#
#   sh scripts/interop-openpgpjs.sh
set -eu

OPENPGPJS_COMMIT=8bc35df4887933a3b2661e3741b33ba5f347b935  # main, 2026-09-24
REPO=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export MSYS_NO_PATHCONV=1

docker volume create agnusmail-openpgpjs >/dev/null
docker run --rm -v agnusmail-openpgpjs:/build node:22 sh -ec "
  cd /build
  if [ \"\$(git rev-parse HEAD 2>/dev/null)\" != '$OPENPGPJS_COMMIT' ]; then
    rm -rf /build/* /build/.[!.]* 2>/dev/null || true
    git clone -q https://github.com/openpgpjs/openpgpjs.git . && git checkout -q $OPENPGPJS_COMMIT
  fi
  if [ ! -f dist/node/openpgp.min.mjs ]; then
    npm install -g --silent npm@12 >/dev/null 2>&1
    npm ci --ignore-scripts >/dev/null 2>&1 && npx rollup --config >/dev/null 2>&1
  fi"

python_side() {
  docker run --rm -v "$REPO:/src:ro" -v "$WORK:/work" -v agnusmail-test-venv:/venv \
    -v agnusmail-test-uvcache:/root/.cache/uv -e UV_PROJECT_ENVIRONMENT=/venv -w /src \
    python:3.13-slim sh -ec "pip install -q uv==0.13.7 >/dev/null 2>&1
      uv sync --locked -q >/dev/null 2>&1 || true
      uv run --no-sync python -m tests.interop.sequoia_side $1 /work"
}
js_side() {
  docker run --rm -v agnusmail-openpgpjs:/build:ro -v "$REPO/tests/interop:/code:ro" \
    -v "$WORK:/work" node:22 node /code/openpgpjs.mjs /build/dist/node/openpgp.min.mjs /work "$1"
}

python_side prepare
js_side step1
python_side check
js_side step2
echo "interop OK (OpenPGP.js $OPENPGPJS_COMMIT <-> Sequoia/pysequoia)"
