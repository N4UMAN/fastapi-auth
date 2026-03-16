from typing import Annotated
from core.config import settings
from fastapi.security import OAuth2PasswordBearer
from fastapi import Depends, HTTPException, status, Request
from datetime import datetime, timedelta
from core.logger import logger
from core.database.database import DBConn
from psycopg import AsyncConnection
from bcrypt import hashpw, checkpw, gensalt


class AuthTokenService():
    def __init__(self, conn: AsyncConnection):
        self.conn = conn

    def _hash_password(plan_pwd):
        """
        Hashes a password using bcrypt.
        bcrypt is slow by design (brute-force resistant), salt ensures same passwords hash differently.
        """
        return hashpw(plan_pwd.encode("utf-8"), gensalt()).decode("utf-8")

    def _verify_password(plain_password, hashed_password):
        """
        Checks plain password against a bcrypt hash.
        bcrypt embeds the salt in the hash, so no need to store or pass it separately.
        """
        try:
            return checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
        except ValueError:
            return False
