from datetime import datetime, timezone

from pydantic import UUID4, BaseModel, EmailStr, Field


class UserBase(BaseModel):
    email: EmailStr


class UserCreate(UserBase):
    hashed_password: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class UserInDB(UserCreate):
    id: UUID4
    pass


class UserReturn(UserBase):
    pass
