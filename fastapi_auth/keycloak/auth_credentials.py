import json

from starlette.authentication import AuthCredentials
from typing_extensions import Any, Optional

from .access import KeycloakAccess
from .resource_access import KeycloakResourceAccess
from .resource_permission import KeycloakResourcePermission

try:
    from keycloak import KeycloakOpenID
except ImportError:
    raise RuntimeError(
        "Install the package with the `keycloak` extra (fastapi-auth[keycloak]) to use the KeycloakAuthBackend"
    )


class KeycloakAuthCredentials(AuthCredentials):
    """
    starlette.authentication.AuthCredentials-compatible class enhanced for Keycloak user authorization.
    """

    def __init__(self, token: dict[str, Any], keycloak: Optional[KeycloakOpenID] = None) -> None:
        self.__token = json.dumps(token)
        self.__access = KeycloakAccess.model_validate(token)
        super().__init__(self.__access.scopes)
        self.__keycloak = keycloak

    @property
    def resource_access(self) -> Optional[KeycloakResourceAccess]:
        """The client role accesses that the user has"""
        return self.__access.resource_access

    @property
    def permissions(self) -> list[KeycloakResourcePermission]:
        """The authorization permissions that the user has"""
        return self.__access.authorization.permissions if self.__access.authorization is not None else []

    def has_client(self, client: str) -> bool:
        """
        Does the user have role accesses specified for the specified client?

        Args:
            client (str): The name of the client to check.

        Returns:
            bool: True if the user has role accesses for the specified client.
        """

        return self.__access.has_client(client)

    def has_role(self, client: str, role: str) -> bool:
        """
        Does the user have the specified role for the given client?

        Args:
            client (str): The name of the client to check within.
            role (str): The name of the role to check for.

        Returns:
            bool: True if the user has the specified role for the given client, otherwise False
        """

        return self.__access.has_role(client, role)

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

        if self.__access.has_authorization_claim():
            return self.__access.has_permission(resource_name, scope)

        if self.__keycloak is not None:
            permission = resource_name if scope is None else f"{resource_name}#{scope}"
            return self.__keycloak.has_uma_access(self.__token, permission).is_authorized

        return False
