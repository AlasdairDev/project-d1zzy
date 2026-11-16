#!/bin/sh
# web:    wait for Postgres -> migrate -> (optionally) seed -> uvicorn
# worker: wait for Postgres + migrations -> arq
# other:  exec as-is (e.g. `python -m app.cli create-moderator ...`)
set -eu

wait_for_db() {
  python - <<'PY'
import asyncio, sys, time
import asyncpg
from app.config import get_settings

url = get_settings().database_url.replace("postgresql+asyncpg://", "postgresql://")
deadline = time.time() + 90
async def main():
    while True:
        try:
            conn = await asyncpg.connect(url)
            await conn.close()
            return
        except Exception as e:
            if time.time() > deadline:
                sys.exit(f"database not reachable: {e}")
            await asyncio.sleep(1)
asyncio.run(main())
PY
}

case "${1:-web}" in
  web)
    wait_for_db
    alembic upgrade head
    if [ "${SEED_DEMO_DATA:-false}" = "true" ]; then python -m app.cli seed; fi
    # shellcheck disable=SC2086
    exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers \
      --forwarded-allow-ips="${FORWARDED_ALLOW_IPS:-127.0.0.1}" ${UVICORN_EXTRA:-}
    ;;
  worker)
    wait_for_db
    # Let the web container apply migrations first.
    until alembic current 2>/dev/null | grep -q "(head)"; do sleep 2; done
    exec arq app.workers.settings.WorkerSettings
    ;;
  *)
    exec "$@"
    ;;
esac
