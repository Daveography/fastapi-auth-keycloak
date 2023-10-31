from typing import Optional

from pydantic import UUID4, EmailStr, Field

from fastapi_auth.jwt.keycloak.resource_access import KeycloakResourceAccess
from fastapi_auth.user import APIUser


class KeycloakUser(APIUser):
    id: UUID4 = Field(alias="sub")
    email: EmailStr
    preferred_username: str
    name: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    resource_access: Optional[KeycloakResourceAccess] = Field(default_factory=KeycloakResourceAccess)

    @property
    def display_name(self) -> str:
        return self.name if self.name is not None else self.preferred_username

    @property
    def identity(self) -> str:
        return str(self.id)

    def has_role(self, client: str, role: str) -> bool:
        if self.resource_access is not None and self.resource_access.has_client(client):
            return self.resource_access[client].has_role(role)

        return False
