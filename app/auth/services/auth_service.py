import hashlib
import hmac
from typing import Annotated
from uuid import UUID

from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from pydantic import EmailStr
from app.auth.schemas.user_schema import UserCreate, UserInDB
from app.core.config import settings
from fastapi import Depends, HTTPException, status, Request
from datetime import datetime, timedelta
from app.core.logger import logger
from bcrypt import hashpw, checkpw, gensalt
from app.auth.schemas.auth_schema import AuthenticateUser, SignupPayload
from app.auth.services.user_service import user_service_dependancy
from app.auth.services.token_service import token_dependency
from app.core.redis.redis import redis_mgr


class AuthService():

    def __init__(self, user_service: user_service_dependancy, token_service: token_dependency):
        self.user_service = user_service
        self.token_service = token_service

    # --- Helpers ---

    @staticmethod
    def _hash_password(plain_pwd: str) -> str:
        """
        Hashes a password using bcrypt.
        bcrypt is slow by design (brute-force resistant), salt ensures same passwords hash differently.
        """
        return hashpw(plain_pwd.encode("utf-8"), gensalt()).decode("utf-8")

    @staticmethod
    def _verify_password(plain_password: str, hashed_password: str) -> bool:
        """
        Checks plain password against a bcrypt hash.
        bcrypt embeds the salt in the hash, so no need to store or pass it separately.
        """
        try:
            return checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
        except ValueError:
            return False

    @staticmethod
    def _extract_client_info(request: Request) -> dict:
        """Extracts and hashes IP and user-agent from the incoming request."""
        ip_addr = request.client.host
        user_agent = request.headers.get('user-agent', 'unknown')

        ip_hash = hashlib.sha256(ip_addr.encode()).hexdigest()
        user_agent_hash = hashlib.sha256(user_agent.encode()).hexdigest()

        return {
            "ip": ip_addr,
            "ip_hash": ip_hash,
            "user_agent": user_agent,
            "user_agent_hash": user_agent_hash
        }

    @staticmethod
    def _normalize_device_fingerprint(raw_fingerprint: str) -> str:
        """
        HMAC-SHA256 hashes the device fingerprint using the app secret.
        Guards against None and empty string — both treated as unknown.
        """
        if not raw_fingerprint:
            return "unknown"

        return hmac.new(settings.HMAC_KEY.encode(), raw_fingerprint.encode(), hashlib.sha256).hexdigest()

    def _build_signup_limit_keys(self, request: Request, device_fingerprint: str) -> tuple[str, str]:
        """Derives Redis rate limit keys for signup from request IP and device fingerprint."""
        client_info = self._extract_client_info(request)
        device_hash = self._normalize_device_fingerprint(device_fingerprint)

        ip_key = f"signup:ip:{client_info['ip_hash']}"
        device_key = f"signup:device:{device_hash}"

        return ip_key, device_key

    def _build_login_limit_keys(self, request: Request, email: EmailStr) -> tuple[str, str]:
        """Derives Redis rate limit keys for login from request IP and user email."""
        client_info = self._extract_client_info(request)

        ip_key = f"login:ip:{client_info['ip_hash']}"
        user_key = f"login:user:{email}"

        return ip_key, user_key

    async def _check_signup_limit(self, request: Request, device_fingerprint: str) -> tuple[bool, str]:
        """Runs signup rate limit check via Lua script. Returns (allowed, reason)."""
        ip_key, device_key = self._build_signup_limit_keys(request, device_fingerprint)

        return await redis_mgr.check_signup_limit(ip_key, device_key)

    # --- Service Methods ---

    async def register_user(self, payload: SignupPayload, request: Request) -> dict:
        """
        Registers a new user.
        Checks signup rate limit, hashes password, persists user.
        Rolls back Redis counter on db failure.
        Returns success message — email verification handled separately (TODO).
        """
        allowed, message = await self._check_signup_limit(request, payload.device_fingerprint)

        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=message
            )

        hashed_pwd = self._hash_password(payload.password)

        user_data = UserCreate(
            email=payload.email,
            hashed_password=hashed_pwd
        )
        try:
            await self.user_service.create_user(user_data)
            # TODO: dispatch verification email to payload.email
            return {
                "status": "success",
                "message": "Please check your email for verification link.",
            }

        except ValueError as e:
            ip_key, device_key = self._build_signup_limit_keys(request, payload.device_fingerprint)
            await redis_mgr.roll_back_signup_counter(ip_key, device_key)

            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(e)
            )
        except RuntimeError as e:
            ip_key, device_key = self._build_signup_limit_keys(request, payload.device_fingerprint)
            await redis_mgr.roll_back_signup_counter(ip_key, device_key)

            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=str(e)
            )

    async def authenticate_user(self, user_data: AuthenticateUser, request: Request) -> dict:
        """
        Full login flow for a single attempt:
        1. Checks ban status and rate limits — raises 429 if blocked.
        2. Fetches user by email — raises 401 if not found (avoids email enumeration).
        3. Verifies password — raises 401 on mismatch.
        4. On any failure, applies a login penalty (increments fail counter, may trigger ban).
        5. On success, resets failure counters and issues access + refresh tokens.
        """

        ip_key, user_key = self._build_login_limit_keys(request, user_data.email)
        blocked, retry_after = await redis_mgr.check_login_rate(ip_key, user_key)

        if blocked:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many login attempts. Retry after {retry_after}."
            )

        try:
            db_user = await self.user_service.get_user_by_email(user_data.email)

        except ValueError as e:
            redis_mgr._apply_failed_login_penalty(ip_key, user_key)
            logger.warning(
                f"Failed login attempt — {str(e)}",
                extra={"email": user_data.email, "ip": request.client.host}
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Email or Password."
            )

        except RuntimeError as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=str(e)
            )

        if not self._verify_password(user_data.password, db_user.hashed_password):
            logger.warning(
                "Failed login attempt — invalid password",
                extra={"email": user_data.email, "ip": request.client.host}
            )

            redis_mgr._apply_failed_login_penalty(ip_key, user_key)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Email or Password."
            )

        await redis_mgr.reset_login_failures(ip_key, user_key)
        return await self.token_service.grant_access_token(db_user.id)


def get_auth_service(user_service: user_service_dependancy, token_service: token_dependency) -> AuthService:
    """Factory function — FastAPI resolves user_service and token_service via DI."""
    return AuthService(user_service, token_service)


async def get_current_user(
    token: Annotated[str, Depends(OAuth2PasswordBearer(tokenUrl="/api/auth/login"))],
    user_service: user_service_dependancy
) -> UserInDB:
    """
    Dependency that decodes the JWT, extracts user_id, and fetches the user from db.
    Raises 401 on any token or lookup failure.
    """
    credential_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"}
    )

    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id = UUID(payload.get("sub"))

        if user_id is None:
            logger.warning("Auth failure — Token payload missing 'sub' claim")
            raise credential_exception

        user = await user_service.get_user_by_id(user_id)

    except JWTError as e:
        logger.warning(
            f"Request failed — str{e}",
        )
        raise credential_exception
    except ValueError:
        raise credential_exception

    return user


auth_dependency = Annotated[AuthService, Depends(get_auth_service)]
CurrentUser = Annotated[UserInDB, Depends(get_current_user)]
