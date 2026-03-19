from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from app.auth.services.token_service import AuthTokenService
from psycopg_pool import AsyncConnectionPool
from app.core.logger import logger

schedular = AsyncIOScheduler()


def start_scheduler(pool: AsyncConnectionPool):
    async def run_delete_expired_tokens():
        async with pool.connection() as conn:
            service = AuthTokenService(conn)
            await service.delete_expired_tokens()

    schedular.add_job(
        run_delete_expired_tokens,
        trigger=CronTrigger(hour='*/6'),
        id="purge_expired_tokens",
        replace_existing=True
    )

    schedular.start()
    logger.info("Scheduler online")


def stop_schedular():
    logger.info("Closing Scheduler")
    schedular.shutdown()
