from psycopg import AsyncConnection
from psycopg_pool import AsyncConnectionPool
from fastapi import Depends, Request
from typing import Annotated


async def get_db(request: Request):
    pool: AsyncConnectionPool = request.app.state.pool

    async with pool.connection as conn:
        yield conn

DBConn = Annotated[AsyncConnection, Depends(get_db)]
