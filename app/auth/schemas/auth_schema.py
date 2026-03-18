from pydantic import BaseModel, EmailStr


class AuthenticateUser(BaseModel):
    email: EmailStr
    password: str


class SignupPayload(AuthenticateUser):
    device_fingerprint: str
