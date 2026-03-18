from pydantic import BaseModel, UUID4, model_validator
from datetime import datetime, timezone, timedelta
from enum import Enum
from app.core.config import settings


class TokenType(Enum):
    ACCESS = "access"
    REFRESH = "refresh"
    EMAIL_VERIFICATION = 'email_verification'
    PASSWORD_RESET = 'password_reset'


class AuthToken(BaseModel):
    id: int
    token_type: TokenType
    issued_at: datetime
    expires_at: datetime
    is_revoked: bool


class AuthTokenCreate(BaseModel):
    user_id: UUID4
    token_hash: str
    token_type: TokenType
    issued_at: datetime
    expires_at: datetime
    is_revoked: bool = False

    @model_validator(mode='before')
    def init_dates(cls, values):
        now = datetime.now(timezone.utc)
        if values.get('issued_at') is None:
            values['issued_at'] = now
        if values.get('expires_at') is None:
            ttl = settings.TOKEN_TTL_CONFIG.get(values.get('token_type')) or timedelta(minutes=15)
            values['expires_at'] = now + ttl
        return values


class AuthRefreshRequest(BaseModel):
    raw_token: str


class AuthTokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
