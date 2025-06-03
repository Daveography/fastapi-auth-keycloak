from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, computed_field
from typing_extensions import Optional, Union

from .authorization import KeycloakAuthorization
from .resource_access import KeycloakResourceAccess


class KeycloakPermissions(BaseModel):
    """
    Holds user authorization permissions information from Keycloak.
    """

    scope: Optional[str] = Field(default=None, description="A list of scopes the user has been authorized to access")
    resource_access: Optional[KeycloakResourceAccess] = Field(
        default=None, description="The client role accesses that the user has"
    )
    authorization: Optional[KeycloakAuthorization] = Field(
        default=None, description="The authorization permissions that the user has"
    )

    @computed_field
    @property
    def scopes(self) -> list[str]:
        """
        A list of scopes the user has been authorized to access.

        Returns:
            list[str]: A list of scopes the user has been authorized to access.
        """

        return self.scope.split(" ") if self.scope is not None else []

    def has_client(self, client: str) -> bool:
        """
        Does the user have role accesses specified for the specified client?

        Args:
            client (str): The name of the client to check.

        Returns:
            bool: True if the user has role accesses for the specified client.
        """

        return self.resource_access is not None and self.resource_access.has_client(client)

    def has_role(self, client: str, role: str) -> bool:
        """
        Does the user have the specified role for the given client?

        Args:
            client (str): The name of the client to check within
            role (str): The name of the role to check for

        Returns:
            bool: True if the user has the specified role for the given client, otherwise False
        """

        if self.resource_access is not None and self.resource_access.has_client(client):
            return self.resource_access[client].has_role(role)

        return False

    def has_authorization(
        self,
        resource_name: Optional[str] = None,
        resource_id: Optional[UUID] = None,
        scope: Optional[Union[str, list[str]]] = None,
    ) -> bool:
        """
        Does the user have authorized access to the specified resource name (with optional scope(s))?

        Args:
            resource_name (str): The name of the resource to check.
            scope (str | list[str], optional): Also check against one or more specific scopes; if multiple scopes are
                provided, the user must have access to all of them. Defaults to None.

        Returns:
            bool: True if the user has permission to access the specified resource (with the all of the specified
                scopes if provided).
        """

        return self.authorization is not None and self.authorization.has_permission(resource_name, resource_id, scope)

    model_config = ConfigDict(frozen=True)
