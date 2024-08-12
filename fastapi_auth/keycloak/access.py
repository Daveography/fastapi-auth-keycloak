from pydantic import BaseModel, ConfigDict, Field, computed_field
from typing_extensions import Optional

from .authorization import KeycloakAuthorization
from .resource_access import KeycloakResourceAccess


class KeycloakAccess(BaseModel):
    """
    Holds user access and authorization information from Keycloak.
    """

    scope: str = Field(description="A list of scopes the user has been authorized to access")
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

        return self.scope.split(" ")

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

    def has_authorization_claim(self) -> bool:
        """
        Was the authorization claim provided?

        Returns:
            bool: True if the user has an authorization claim, otherwise False
        """

        return self.authorization is not None

    def has_permission(self, resource_name: str, scope: Optional[str] = None) -> bool:
        """
        Does the user have authorized access to the specified resource name (with optional scope)?

        Args:
            resource_name (str): The name of the resource to check.
            scope (str, optional): Also check against a specific scope.

        Returns:
            bool: True if the user has permission to access the specified resource (with the specified scope if
                    provided).
        """

        return self.authorization is not None and self.authorization.has_permission(resource_name, scope)

    model_config = ConfigDict(frozen=True)
