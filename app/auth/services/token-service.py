from pydantic import UUID4
from datetime import datetime, timedelta, timezone
from typing import Optional
import hashlib
from core.database import DBConn
from core.config import settings
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

    )
