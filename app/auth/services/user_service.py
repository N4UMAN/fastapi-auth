from typing import Annotated

from fastapi import Depends
from psycopg import AsyncConnection
from psycopg.errors import UniqueViolation
from psycopg.rows import dict_row
from pydantic import UUID4, EmailStr

from app.auth.schemas.user_schema import UserCreate, UserInDB
from app.core.database.database import DBConn


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

    async def get_user_by_email(self, email: EmailStr):
        """
        get user by email, if not found, raise exception
        """

        query = "SELECT * from users WHERE email ILIKE %s"

        try:
            async with self.conn.cursor(row_factory=dict_row) as curr:
                await curr.execute(query, (email,))
                user = await curr.fetchone()
        except Exception as e:
            raise RuntimeError(f"Database error: {e}")

        if user is None:
            raise ValueError(f"User with email {email} not found")

        return UserInDB.model_validate(user)

    async def get_user_by_id(self, user_id: UUID4):
        """
        Fetches a user by ID, raises ValueError if not found.
        """

        query = "SELECT * from users WHERE id = %s"

        try:
            async with self.conn.cursor(row_factory=dict_row) as curr:
                await curr.execute(query, (user_id, ))
                user = await curr.fetchone()
        except Exception as e:
            raise RuntimeError(f"Database error: {e}")

        if user is None:
            raise ValueError(f"User not found")

        return UserInDB.model_validate(user)


def get_user_service(conn: DBConn) -> UserService:
    return UserService(conn)


user_service_dependancy = Annotated[UserService, Depends(get_user_service)]
