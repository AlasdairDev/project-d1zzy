from arq import cron

from app.config import get_settings
from app.core.queue import redis_settings
from app.db.session import dispose_engine
from app.main import configure_logging
from app.workers import tasks


async def startup(ctx) -> None:
    configure_logging(get_settings().log_level)


async def shutdown(ctx) -> None:
    await dispose_engine()


class WorkerSettings:
    functions = [tasks.send_email, tasks.pin_cids, tasks.relay_notifications]
    cron_jobs = [
        cron(tasks.poll_stripe, second={0}, run_at_startup=False),
        cron(tasks.poll_btcpay, second={15}),
        cron(tasks.poll_monero, second={30}),
        cron(tasks.expire_offers, minute={0}, second={45}),
    ]
    on_startup = startup
    on_shutdown = shutdown
    redis_settings = redis_settings()
    max_jobs = 20
    job_timeout = 120
