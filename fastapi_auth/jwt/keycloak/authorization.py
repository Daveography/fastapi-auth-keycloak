from pydantic import BaseModel, Field
from typing_extensions import Optional

from .resource import KeycloakResource


class KeycloakAuthorization(BaseModel):
    """
    A representation of the authorization permissions that a Keycloak user has been granted.
    Requires a token issued using the grant type of urn:ietf:params:oauth:grant-type:uma-ticket.
    """

    permissions: list[KeycloakResource] = Field(
        default_factory=list, description="A list of resources the user has been authorized to access."
    )

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

        permission = next(filter(lambda p: p.name == resource_name, self.permissions), None)

        if permission is None:
            return False

        if scope and permission.scopes is not None:
            return scope in permission.scopes

        return True

    def __len__(self):
        return len(self.permissions)

    def __iter__(self):
        return iter(self.permissions)
