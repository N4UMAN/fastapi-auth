# import psycopg
from psycopg_pool import AsyncConnectionPool
from fastapi import FastAPI
from contextlib import asynccontextmanager
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from app.auth.routers.auth_router import auth_router
from app.core.config import settings
from app.core.redis.redis import redis_mgr
# from src.tasks.cleanup import delete_expired_tokens


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.pool = AsyncConnectionPool(
        conninfo=str(settings.DATABASE_URI),
        open=False,
        min_size=1,
        max_size=10
    )
    await app.state.pool.open()
    await app.state.pool.wait()

    await redis_mgr.init()

    scheduler = AsyncIOScheduler()
    # scheduler.add_job(delete_expired_tokens, 'cron', hour=3, args=[app.state.pool])
    scheduler.start()

    yield

    # Shutdown
    await app.state.pool.close()
    await redis_mgr.close()
    scheduler.shutdown()

app = FastAPI(title=settings.PROJECT_NAME, lifespan=lifespan)
app.include_router(auth_router, prefix='/api')
