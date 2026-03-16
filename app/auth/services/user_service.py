from psycopg import AsyncConnection
from psycopg.errors import UniqueViolation
from pydantic import UUID4

from app.auth.schemas.user_schema import UserCreate


class UserService():
    def __init__(self, conn: AsyncConnection):
        self.conn = conn

    async def create_user(self, user: UserCreate):
        """
        Create and save user to database
        """

        columns = ["email", 'hashed_password', "created_at"]
        values = user.model_dump()

        params = tuple(values[col] for col in columns)

        query = f"""
            INSERT INTO users ({','.join(columns)})
            VALUES ({','.join(['%s'] * len(columns))})
            RETURNING id, email
        """
        try:
            async with self.conn.cursor() as curr:
                await curr.execute(query, params)
                row = await curr.fetchone()

                return row

        except UniqueViolation:
            raise ValueError(f"Email {user.email} already exists")
        except Exception as e:
            raise RuntimeError(f"Database error: {e}")
