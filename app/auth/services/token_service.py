from fastapi import Depends, HTTPException, status
from jose import jwt
from pydantic import UUID4
from datetime import datetime, timedelta, timezone
from typing import Annotated
import hashlib
from app.core.database.database import DBConn
from app.core.config import settings
from app.auth.schemas.auth_token_schema import TokenType, AuthTokenCreate
from psycopg import AsyncConnection
from psycopg.rows import dict_row
import secrets


class AuthTokenService:
    def __init__(self, conn: AsyncConnection):
        self.conn = conn

    # --- Helpers ---
    @staticmethod
    def _hash_token(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    @staticmethod
    def _generate_token_string(is_otp: bool = False) -> str:
        """
        Returns 32-bit token string. 
        Handles generation of OTP
        """
        if not is_otp:
            return secrets.token_urlsafe(32)

        return str(secrets.randbelow(10**6)).zfill(6)

    @staticmethod
    def create_access_token(data: dict, expires_delta: timedelta | None = None):
        """
        Encodes a JWT access token with expiry and token type claims.
        expires_delta overrides the default TTL from settings if provided.
        """
        to_encode = data.copy()
        expire_at = datetime.now(timezone.utc) + (expires_delta or settings.TOKEN_TTL_CONFIG.get(TokenType.ACCESS))

        to_encode.update({"exp": expire_at, "type": TokenType.ACCESS.value})
        return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

    # --- Service Methods ---
    async def create_token(
        self,
        user_id: UUID4,
        token_type: TokenType,
        is_otp: bool = False
    ) -> str:
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
            try:
                await cur.execute(query, params)

                return raw_token
            except Exception as e:
                raise RuntimeError(f"Database error: {e}")

    async def revoke_token(
            self,
            token_id
    ):
        query = "UPDATE auth_tokens SET is_revoked = TRUE where id = %s"

        async with self.conn.cursor() as cur:
            await cur.execute(query, (token_id, ))
            if cur.rowcount == 0:
                raise ValueError(f"Token {token_id} not found")

            await self.conn.commit()

        return token_id

    async def verify_token(self, raw_token: str, token_type: TokenType) -> UUID4 | None:
        """
        Checks if a token is valid, hasn't expired, and isn't revoked.
        If valid, marks it revoked (consumed) and returns the user_id.
        """
        token_hash = self._hash_token(raw_token)

        # Find and revoke token
        query = """
        UPDATE auth_tokens 
        SET is_revoked = TRUE 
        WHERE token_hash = %s 
        AND token_type = %s 
        AND is_revoked = FALSE 
        AND expires_at > NOW()
        RETURNING user_id;
        """

        async with self.conn.cursor(row_factory=dict_row) as cur:
            try:
                await cur.execute(query, (token_hash, token_type.value))
                token_row = await cur.fetchone()

                if not token_row:
                    return None

                return token_row['user_id']

            except Exception as e:
                raise RuntimeError(f"Database error: {e}")

    async def rotate_access_token(self, raw_token, token_type: TokenType = TokenType.REFRESH) -> tuple[str, str]:
        """
        Verifies and revokes token before generating new refresh and access tokens.
        Returns raw token.
        """
        user_id = await self.verify_token(raw_token, token_type)

        refresh_token = await self.create_token(
            user_id,
            token_type,
            False
        )
        access_token = self.create_access_token({"sub": str(user_id)})

        return (access_token, refresh_token)

    async def grant_access_token(self, user_id) -> tuple[str, str]:
        """
        Grants access + refresh token on signin
        """

        refresh_token = await self.create_token(
            user_id,
            TokenType.REFRESH,
            False
        )

        access_token = self.create_access_token({"sub": str(user_id)})

        return (access_token, refresh_token)

    async def delete_expired_tokens(self) -> int:
        """
        CRON JOB Function: deletes all expired tokens
        """
        query = "DELETE FROM auth_tokens WHERE expires_at < NOW()"

        async with self.conn.cursor() as cur:
            try:
                await cur.execute(query)
                return await cur.rowcount

            except Exception as e:
                raise RuntimeError(f"Database error: {e}")


def get_auth_token_service(conn: DBConn) -> AuthTokenService:
    return AuthTokenService(conn)


token_dependency = Annotated[AuthTokenService, Depends(get_auth_token_service)]
