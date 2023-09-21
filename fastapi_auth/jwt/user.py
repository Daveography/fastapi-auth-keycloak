from typing import Optional

from pydantic import UUID4, EmailStr

from fastapi_auth.user import APIUser


class JWTAPIUser(APIUser):
    sub: UUID4
    name: Optional[str] = None
    preferred_username: str
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    email: EmailStr

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def display_name(self) -> str:
        return self.preferred_username

    @property
    def identity(self) -> str:
        return str(self.sub)

    class Config:
        allow_mutation = False
