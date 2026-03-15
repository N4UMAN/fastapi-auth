from pydantic import BaseModel
from datetime import datetime
from enum import Enum


class TokenType(Enum):
    REFRESH = "refresh"
    EMAIL_VERIFICATION = 'email_verification'
    PASSWORD_RESET = 'password_reset'


class AuthToken(BaseModel):
    id: int
    token_type: TokenType
    issued_at: datetime
    expires_at: datetime
    is_revoked: bool
