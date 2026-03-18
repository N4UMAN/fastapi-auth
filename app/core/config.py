from datetime import timedelta

from fastapi_mail import ConnectionConfig
from pydantic import AnyUrl, EmailStr, computed_field
from pydantic_core import MultiHostUrl
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # App Settings
    PROJECT_NAME: str = "FastAPI Auth"
    DEBUG: bool = False

    # Database
    POSTGRES_USERNAME: str
    POSTGRES_PASSWORD: str
    POSTGRES_SERVER: str
    POSTGRES_PORT: int
    POSTGRES_DATABASE: str

    @computed_field
    @property
    def DATABASE_URI(self) -> AnyUrl:
        return str(MultiHostUrl.build(
            scheme="postgresql",
            username=self.POSTGRES_USERNAME,
            password=self.POSTGRES_PASSWORD,
            host=self.POSTGRES_SERVER,
            port=self.POSTGRES_PORT,
            path=self.POSTGRES_DATABASE,
        ))

    # Security
    SECRET_KEY: str
    HMAC_KEY: str
    ALGORITHM: str = "HS256"

    @computed_field
    @property
    def TOKEN_TTL_CONFIG(self) -> dict:
        """Token TTL configuration for different token types"""
        from app.auth.schemas.auth_token_schema import TokenType

        return {
            TokenType.EMAIL_VERIFICATION: timedelta(hours=2),
            TokenType.PASSWORD_RESET: timedelta(minutes=30),
            TokenType.REFRESH: timedelta(days=7),
            TokenType.ACCESS: timedelta(minutes=30)
        }

    # Load from .env file
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # Mail Settings
    MAIL_USERNAME: str
    MAIL_PASSWORD: str
    MAIL_FROM: EmailStr
    MAIL_FROM_NAME: str
    MAIL_PORT: int = 587
    MAIL_SERVER: str
    MAIL_STARTTLS: bool = True
    MAIL_SSL_TLS: bool = False

    @computed_field
    @property
    def MAIL_CONFIG(self) -> str:
        return ConnectionConfig(
            MAIL_USERNAME=self.MAIL_USERNAME,
            MAIL_PASSWORD=self.MAIL_PASSWORD,
            MAIL_FROM=self.MAIL_FROM,
            MAIL_FROM_NAME=self.MAIL_FROM_NAME,
            MAIL_PORT=self.MAIL_PORT,
            MAIL_SERVER=self.MAIL_SERVER,
            MAIL_STARTTLS=self.MAIL_STARTTLS,
            MAIL_SSL_TLS=self.MAIL_SSL_TLS,
            USE_CREDENTIALS=True
        )

    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379

    @computed_field
    @property
    def redis_url(self) -> str:
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}"

    # Auth Settings
    SIGNUP_LIMIT_IP: int = 3
    SIGNUP_LIMIT_DEVICE: int = 999
    SIGNUP_WINDOW: int = 86400

    @computed_field
    @property
    def signup_rate_limit_config(self) -> dict:
        return {
            "ip_limit": self.SIGNUP_LIMIT_IP,
            "device_limit": self.SIGNUP_LIMIT_DEVICE,
            "window": self.SIGNUP_WINDOW
        }


settings = Settings()
