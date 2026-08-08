#!/usr/bin/env bash
# CI Docker smoke: build -> alembic upgrade -> API /api/v1/health.
# Expects Postgres and Redis on 127.0.0.1 (GitHub Actions service containers).
set -euo pipefail

IMAGE="${IMAGE:-analyzer-ci:local}"
POSTGRES_USER="${POSTGRES_USER:-analyzer}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-ci-postgres}"
POSTGRES_DB="${POSTGRES_DB:-analyzer}"
REDIS_PASSWORD="${REDIS_PASSWORD-}"
API_KEY="${ANALYZER_API_KEY:-ci-smoke-key}"

DATABASE_URL="postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@127.0.0.1:5432/${POSTGRES_DB}"
if [[ -n "${REDIS_PASSWORD}" ]]; then
  REDIS_URL="redis://:${REDIS_PASSWORD}@127.0.0.1:6379/0"
  BROKER_URL="redis://:${REDIS_PASSWORD}@127.0.0.1:6379/1"
  RESULT_URL="redis://:${REDIS_PASSWORD}@127.0.0.1:6379/2"
else
  REDIS_URL="redis://127.0.0.1:6379/0"
  BROKER_URL="redis://127.0.0.1:6379/1"
  RESULT_URL="redis://127.0.0.1:6379/2"
fi

echo "==> Building ${IMAGE}"
docker build -t "${IMAGE}" .

COMMON_ENV=(
  -e "ANALYZER_DATABASE_URL=${DATABASE_URL}"
  -e "ANALYZER_REDIS_URL=${REDIS_URL}"
  -e "ANALYZER_CELERY_BROKER_URL=${BROKER_URL}"
  -e "ANALYZER_CELERY_RESULT_BACKEND=${RESULT_URL}"
  -e "ANALYZER_API_KEY=${API_KEY}"
  -e "ANALYZER_DEBUG=false"
  -e "ANALYZER_RATE_LIMIT_PER_MINUTE=0"
  -e "ANALYZER_RATE_LIMIT_SYNC_PER_MINUTE=0"
)

echo "==> alembic upgrade head"
docker run --rm --network host "${COMMON_ENV[@]}" "${IMAGE}" alembic upgrade head

echo "==> starting API"
cid="$(docker run -d --network host "${COMMON_ENV[@]}" "${IMAGE}")"
cleanup() {
  docker logs "${cid}" || true
  docker rm -f "${cid}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> waiting for /api/v1/health"
ok=0
for i in $(seq 1 30); do
  if body="$(curl -fsS "http://127.0.0.1:8000/api/v1/health" 2>/dev/null)"; then
    echo "${body}"
    status_ok=0
    if echo "${body}" | grep -Eq '"status"[[:space:]]*:[[:space:]]*"healthy"'; then
      status_ok=1
    fi
    db_ok=0
    if echo "${body}" | grep -Eq '"database"[[:space:]]*:[[:space:]]*"ok"'; then
      db_ok=1
    fi
    if [[ "${status_ok}" -eq 1 && "${db_ok}" -eq 1 ]]; then
      ok=1
      break
    fi
  fi
  sleep 2
done

if [[ "${ok}" -ne 1 ]]; then
  echo "Health smoke failed" >&2
  exit 1
fi

echo "==> docker smoke OK"
