from uuid import UUID
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from pydantic import UUID4
from datetime import datetime, timedelta, timezone
from typing import Annotated
import hashlib
from app.core.database.database import DBConn
from core.config import settings
from auth.schemas.auth_token_schema import TokenType, AuthTokenCreate
from psycopg import AsyncConnection
import secrets
from auth.services.user_service import user_service_dependancy
from auth.schemas.user_schema import UserInDB


class AuthTokenService:
    def __init__(self, conn: AsyncConnection):
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

    def create_access_token(data: dict, expires_delta: timedelta | None = None):
        """
        Encodes a JWT access token with expiry and token type claims.
        expires_delta overrides the default TTL from settings if provided.
        """
        to_encode = data.copy()
        expire_at = datetime.now(timezone.utc) + (expires_delta or settings.TOKEN_TTL_CONFIG.get(TokenType.ACCESS))

        to_encode.update({"exp": expire_at, "type": TokenType.ACCESS})
        return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

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

    async def verify_token(self, raw_token: str, token_type: TokenType):
        """
        Checks if a token is valid, hasn't expired, and isn't revoked.
        If valid, marks it revoked (consumed) and returns the user_id.
        """
        token_hash = self._hash_token(raw_token)

        # Find the token
        query = """
        SELECT id, user_id FROM auth_tokens 
        WHERE token_hash = %s 
        AND token_type = %s
        AND is_revoked = FALSE 
        AND expires_at > NOW() 
        FOR UPDATE;
        """

        async with self.conn.cursor() as cur:
            try:
                await cur.execute(query, (token_hash, str(token_type)))
                token_row = await cur.fetchone()

                if not token_row:
                    return None

                # Mark token as revoked
                update_query = "UPDATE auth_tokens SET is_revoked = TRUE WHERE id = %s"
                await cur.execute(update_query, (token_row['id'],))
                await self.conn.commit()
            except Exception:
                await self.conn.rollback()
                raise

            return token_row['user_id']

    async def rotate_refresh_token(self, raw_token, token_type: TokenType = TokenType.REFRESH):
        """
        Verifies and revokes token before generating a new token.
        Returns raw token.
        """
        user_id = await self.verify_token(raw_token, token_type)

        token = await self.create_token(
            user_id,
            token_type,
            False
        )

        return (user_id, token)


def get_auth_token_service(conn: DBConn) -> AuthTokenService:
    return AuthTokenService(conn)


async def get_current_user(token: Annotated[str, Depends(OAuth2PasswordBearer(tokenUrl="/api/auth/login"))], user_service: user_service_dependancy):
    credential_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"}
    )

    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id = UUID(payload.get("sub"))

        if user_id is None:
            raise credential_exception

        user = await user_service.get_user_by_id(user_id)

    except JWTError as e:
        raise credential_exception
    except ValueError:
        raise credential_exception

    return user

token_dependancy = Annotated[AuthTokenService, Depends(get_auth_token_service)]
CurrentUser = Annotated[UserInDB, Depends(get_current_user)]
