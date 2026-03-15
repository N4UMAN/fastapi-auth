from pydantic import UUID4
from datetime import datetime, timedelta, timezone
from typing import Optional
import hashlib
from app.core.database.database import DBConn
from core.config import settings
from auth.schemas.auth_token_schema import TokenType, AuthTokenCreate
from psycopg import AsyncConnection
import secrets


class AuthTokenService:
    def __init__(self, conn: DBConn):
        self.conn = conn

    def _hash_token(self, token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def _generate_token_string(self, is_otp: bool = False) -> str:
        """
        Returns 32-bit token string. 
        Handles generation of OTP
        """
        if not is_otp:
            return secrets.token_urlsafe(32)

        return str(secrets.randbelow(10**6)).zfill(6)

    async def create_token(
        self,
        user_id: UUID4,
        token_type: TokenType,
        is_otp: bool = False
    ):
        """
        Generates a secure token, hashes it for the DB, and returns the 
        raw string to be sent to the user.
        """

        raw_token = self._generate_token_string(is_otp)
        token_hash = self._hash_token(raw_token)

        valid_token = AuthTokenCreate(
            user_id=user_id,
            token_hash=token_hash,
            token_type=token_type
        )

        values = valid_token.model_dump()
        values['token_type'] = values['token_type'].value

        columns = ['user_id', 'token_hash', 'token_type', 'issued_at', 'expires_at', 'is_revoked']
        params = tuple(values[col] for col in columns)

        query = f"""
            INSERT INTO auth_tokens ({','.join(columns)})
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id;
        """

        async with self.conn.cursor() as cur:
            await cur.execute(query, params)

            await self.conn.commit()

        return raw_token
