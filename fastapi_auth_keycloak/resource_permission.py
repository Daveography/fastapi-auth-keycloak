from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field
from typing_extensions import Optional


class KeycloakResourcePermission(BaseModel):
    """
    A representation of an authorization resource in Keycloak.
    """

    id: UUID = Field(..., alias="rsid", description="The Id of the resource")
    name: Optional[str] = Field(default=None, alias="rsname", description="The name of the resource")
    scopes: Optional[list[str]] = Field(default_factory=list, description="A list of scopes available for the resource")

    model_config = ConfigDict(frozen=True)
