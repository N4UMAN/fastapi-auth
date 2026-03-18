from fastapi import APIRouter, Request, HTTPException, status
from app.auth.schemas.auth_schema import AuthenticateUser, SignupPayload
from app.auth.services.token_service import token_dependency
from app.auth.schemas.auth_token_schema import AuthTokenResponse, AuthRefreshRequest
from app.auth.services.auth_service import auth_dependency

auth_router = APIRouter(prefix="/auth", tags=["Auth"])


@auth_router.post('/signup')
async def signup(payload: SignupPayload, request: Request, auth_service: auth_dependency):
    return await auth_service.register_user(payload, request)


@auth_router.post('/login', response_model=AuthTokenResponse)
async def login(payload: AuthenticateUser, auth_service: auth_dependency):
    access_token, refresh_token = await auth_service.authenticate_user(payload)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token
    }


@auth_router.post('/refresh', response_model=AuthTokenResponse)
async def rotate_token(
    body: AuthRefreshRequest,
    service: token_dependency
):
    try:
        access_token, refresh_token = await service.rotate_access_token(
            body.raw_token
        )

        if not refresh_token:
            raise Exception

        return {
            "access_token": access_token,
            "refresh_token": refresh_token
        }

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token."
        )
