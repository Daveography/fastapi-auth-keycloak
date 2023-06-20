from typing import Optional

from pydantic import UUID4, EmailStr

from fastapi_auth.user import APIUser


class JWTAPIUser(APIUser):
    sid: UUID4
    name: Optional[str]
    preferred_username: str
    given_name: Optional[str]
    family_name: Optional[str]
    email: EmailStr

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def display_name(self) -> str:
        return self.preferred_username

    @property
    def identity(self) -> str:
        return str(self.sid)

    class Config:
        allow_mutation = False
