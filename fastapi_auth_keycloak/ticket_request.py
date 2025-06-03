from pydantic import BaseModel, Field, RootModel


class KeycloakResourceRequest(BaseModel):
    resource_id: str = Field(..., description="The Id of the resource")
    resource_scopes: list[str] = Field(default_factory=list, description="A list of scopes available for the resource")


class KeycloakPermissionTicketRequest(RootModel[list[KeycloakResourceRequest]]): ...
