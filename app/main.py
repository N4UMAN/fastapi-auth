# import psycopg
from psycopg_pool import AsyncConnectionPool
from fastapi import FastAPI
from contextlib import asynccontextmanager
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from core.config import settings
# from src.tasks.cleanup import delete_expired_tokens


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.pool = AsyncConnectionPool(
        conninfo=str(settings.DATABASE_URI),
        open=False,
        min_size=1,
        max_size=10
    )

    scheduler = AsyncIOScheduler()
    # scheduler.add_job(delete_expired_tokens, 'cron', hour=3, args=[app.state.pool])
    scheduler.start()

    yield

    # 3. Clean Shutdown
    await app.state.pool.close()
    scheduler.shutdown()

app = FastAPI(title=settings.PROJECT_NAME, lifespan=lifespan)
