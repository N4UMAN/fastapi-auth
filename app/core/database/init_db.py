from psycopg import AsyncConnection
from app.core.config import settings
from os import path
from app.core.logger import logger
import asyncio


async def init_tables():
    file_path = path.join(
        path.dirname(__file__),
        '..', '..', 'auth', 'models', 'auth_token.sql'
    )
    async with await AsyncConnection.connect(str(settings.DATABASE_URI)) as conn:
        async with conn.cursor() as cur:
            with open(file_path, 'r', encoding='utf-8') as file:
                sql = file.read()

            statements = [s.strip() for s in sql.split(';') if s.strip()]

            for stmt in statements:
                await cur.execute(stmt)

            await conn.commit()
            logger.info("Successfully initialized DB tables.")


if __name__ == "__main__":
    # Windows fix
    if hasattr(asyncio, "WindowsSelectorEventLoopPolicy"):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(init_tables())
