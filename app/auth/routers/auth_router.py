from fastapi import APIRouter, Request, HTTPException, status
from auth.services.token_service import token_dependancy
from auth.schemas.auth_token_schema import AuthTokenResponse, AuthRefreshRequest

auth_router = APIRouter(prefix="/auth", tags=["Auth"])


@auth_router.post('/refresh', response_model=AuthTokenResponse)
async def rotate_token(
    body: AuthRefreshRequest,
    service: token_dependancy
):
    try:
        user_id, new_refresh_token = await service.rotate_refresh_token(
            body.raw_token
        )

        if not new_refresh_token:
            raise Exception

        access_token = service.create_access_token({"sub": str(user_id)})

        return {
            "access_token": access_token,
            "refresh_token": new_refresh_token
        }

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token."
        )
