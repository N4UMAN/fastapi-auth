import hashlib
import hmac
from typing import Annotated
from app.auth.schemas.user_schema import UserCreate, UserReturn
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
    def _hash_password(plan_pwd):
        """
        Hashes a password using bcrypt.
        bcrypt is slow by design (brute-force resistant), salt ensures same passwords hash differently.
        """
        return hashpw(plan_pwd.encode("utf-8"), gensalt()).decode("utf-8")

    @staticmethod
    def _verify_password(plain_password, hashed_password):
        """
        Checks plain password against a bcrypt hash.
        bcrypt embeds the salt in the hash, so no need to store or pass it separately.
        """
        try:
            return checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
        except ValueError:
            return False

    @staticmethod
    def _extract_client_info(request: Request):
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
    def _normalize_device_fingerprint(raw_fingerprint: str):
        if raw_fingerprint is None:
            return "unknown"

        return hmac.new(settings.HMAC_KEY.encode(), raw_fingerprint.encode(), hashlib.sha256).hexdigest()

    # --- Service Methods ---
    async def authenticate_user(self, user: AuthenticateUser) -> UserReturn:
        """
        Fetches user by email, raises Exception if user not found or credentials invalid.
        """
        try:
            db_user = await self.user_service.get_user_by_email(user.email)

        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        except RuntimeError as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=str(e)
            )

        if not self._verify_password(user.password, db_user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Email or Password"
            )

        return await self.token_service.grant_access_token(db_user.id)

    async def register_user(self, payload: SignupPayload, request: Request):
        # Step 1. Limit validation
        allowed, message = await self.check_signup_limit(request, payload.device_fingerprint)

        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=message
            )

        hashed_pwd = self._hash_password(payload.password)

        # Step 2. Create user in db
        user_data = UserCreate(
            email=payload.email,
            hashed_password=hashed_pwd
        )
        try:
            await self.user_service.create_user(user_data)

            # Step 3. Email verification
            # TODO add mailing and return message

            return {
                "status": "success",
                "message": "Please check your email for verification link.",
            }

        except ValueError as e:
            ip_key, device_key = self._build_rate_limit_keys(request, payload.device_fingerprint)
            redis_mgr.roll_back_signup_counter(ip_key, device_key)

            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(e)
            )
        except RuntimeError as e:
            ip_key, device_key = self._build_rate_limit_keys(request, payload.device_fingerprint)
            redis_mgr.roll_back_signup_counter(ip_key, device_key)

            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=str(e)
            )

    async def check_signup_limit(self, request: Request, device_fingerprint: str) -> tuple[bool, str]:
        ip_key, device_key = self._build_rate_limit_keys(request, device_fingerprint)

        return await redis_mgr.check_signup_limit(ip_key, device_key)

    def _build_rate_limit_keys(self, request: Request, device_fingerprint: str) -> tuple[str, str]:
        client_info = self._extract_client_info(request)
        device_hash = self._normalize_device_fingerprint(device_fingerprint)

        ip_key = f"signup:ip:{client_info['ip_hash']}"
        device_key = f"signup:device:{device_hash}"

        return ip_key, device_key


def get_auth_service(user_service: user_service_dependancy, token_service: token_dependency) -> AuthService:
    return AuthService(user_service, token_service)


auth_dependency = Annotated[AuthService, Depends(get_auth_service)]
