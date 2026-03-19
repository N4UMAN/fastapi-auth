from psycopg_pool import AsyncConnectionPool
from fastapi import FastAPI
from contextlib import asynccontextmanager
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from app.auth.routers.auth_router import auth_router
from app.core.config import settings
from app.core.redis.redis import redis_mgr
from app.core.scheduler import start_scheduler, stop_schedular


@asynccontextmanager
async def lifespan(app: FastAPI):
    pool = AsyncConnectionPool(
        conninfo=str(settings.DATABASE_URI),
        open=False,
        min_size=1,
        max_size=10
    )
    await pool.open()
    await pool.wait()

    app.state.pool = pool
    await redis_mgr.init()

    start_scheduler(pool)

    yield

    # Shutdown
    await pool.close()
    await redis_mgr.close()
    stop_schedular()

app = FastAPI(title=settings.PROJECT_NAME, lifespan=lifespan)
app.include_router(auth_router, prefix='/api')
