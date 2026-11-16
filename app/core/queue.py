import structlog
from arq import ArqRedis, create_pool
from arq.connections import RedisSettings

from app.config import get_settings

log = structlog.get_logger()


def redis_settings() -> RedisSettings:
    return RedisSettings.from_dsn(get_settings().redis_url)


class ArqQueue:
    """Thin wrapper so routes can enqueue without caring whether Redis is up.

    Enqueue failures are logged, not raised: every job also has a periodic cron sweep in the
    worker, so a dropped enqueue only delays work.
    """

    def __init__(self) -> None:
        self._pool: ArqRedis | None = None

    async def connect(self) -> ArqRedis:
        if self._pool is None:
            self._pool = await create_pool(redis_settings())
        return self._pool

    @property
    def redis(self) -> ArqRedis:
        if self._pool is None:
            raise RuntimeError("queue not connected")
        return self._pool

    async def enqueue(self, function: str, *args, **kwargs) -> None:
        try:
            pool = await self.connect()
            await pool.enqueue_job(function, *args, **kwargs)
        except Exception as e:  # noqa: BLE001
            log.warning("enqueue_failed", function=function, error=str(e))

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.aclose()
            self._pool = None


queue = ArqQueue()
