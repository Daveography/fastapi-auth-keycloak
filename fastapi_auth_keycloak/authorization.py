from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field
from typing_extensions import Optional, Union

from .resource_permission import KeycloakResourcePermission


class KeycloakAuthorization(BaseModel):
    """
    A representation of the authorization permissions that a Keycloak user has been granted.
    Requires a token issued using the grant type of `urn:ietf:params:oauth:grant-type:uma-ticket`.
    """

    permissions: list[KeycloakResourcePermission] = Field(
        default_factory=list, description="A list of resources the user has been authorized to access."
    )

    def has_permission(
        self,
        resource_name: Optional[str] = None,
        resource_id: Optional[UUID] = None,
        scope: Optional[Union[str, list[str]]] = None,
    ) -> bool:
        """
        Does the user have authorized access to the specified resource name or id (with optional scope(s))?
        If both resource_name and resource_id are provided, resource_id will be used.

        Args:
            resource_name (str): The name of the resource to check.
            resource_id (str): The id of the resource to check.
            scope (str | list[str], optional): Also check against one or more specific scopes; if multiple scopes are
                provided, the user must have access to all of them. Defaults to None.

        Returns:
            bool: True if the user has permission to access the specified resource (with the all of the specified
                scopes if provided).
        """

        if resource_name is None and resource_id is None:
            raise ValueError("Either resource_name or resource_id must be provided")

        if resource_name is not None:
            permission = next(filter(lambda p: p.name == resource_name, self.permissions), None)

        if resource_id is not None:
            permission = next(filter(lambda p: p.id == resource_id, self.permissions), None)

        if permission is None:
            return False

        if isinstance(scope, str):
            scope = [scope]

        scopes = set(scope or [])
        resource_scopes = set(permission.scopes or [])
        return scopes.issubset(resource_scopes)

    def __len__(self):
        return len(self.permissions)

    def __iter__(self):
        return iter(self.permissions)

    model_config = ConfigDict(frozen=True)
