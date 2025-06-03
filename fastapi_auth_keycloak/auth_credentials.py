from uuid import UUID

from starlette.authentication import AuthCredentials
from typing_extensions import Any, Never, Optional, Union

from .permissions import KeycloakPermissions
from .ticket_request import KeycloakPermissionTicketRequest, KeycloakResourceRequest
from .uma.exceptions import UMAAuthorizationRequired, UMAAuthorizationServerUnreachable

try:
    from keycloak import KeycloakOpenIDConnection, KeycloakUMA
    from keycloak.exceptions import KeycloakPostError, raise_error_from_response
except ImportError:
    raise RuntimeError(
        "Install the package with the `keycloak` extra (fastapi-auth[keycloak]) to use the KeycloakAuthBackend"
    )


class KeycloakAuthCredentials(AuthCredentials):
    """
    starlette.authentication.AuthCredentials-compatible class enhanced for Keycloak user authorization.
    """

    def __init__(self, token: dict[str, Any], keycloak: KeycloakOpenIDConnection) -> None:
        self.__access = KeycloakPermissions.model_validate(token)
        super().__init__(self.__access.scopes)
        self.__uma = KeycloakUMA(keycloak)

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

    async def authorize(self, resource_name: str, scope: Optional[Union[str, list[str]]] = None) -> None:
        """
        Asserts authorized access to the specified resource name with optional scope(s).
        Uses UMA 2.0 grant workflow: https://docs.kantarainitiative.org/uma/wg/oauth-uma-grant-2.0-09.html

        Args:
            resource_name (str): The name of the resource to check.
            scope (str | list[str], optional): Also check against one or more specific scopes; if multiple scopes are
                provided, the user must have access to all of them. Defaults to None.

        Returns:
            bool: True if the user has permission to access the specified resource (with the all of the specified
                scopes if provided).

        Raises:
            KeycloakPostError: If the resource was not found on the authorization server.
            HTTPException (401 Unauthorized with `WWW-Authenticate` header): If the user does not currently have
                authorization; clients should use the provided header to request authorization according to UMA 2.0.
            HTTPException (403 Forbidden): If the authorization server is unavailable.
        """

        if self.__access.has_authorization(resource_name=resource_name, scope=scope):
            return

        resource_id = await self.__get_resource_id(resource_name)

        await self.authorize_by_id(resource_id, scope)

    async def authorize_by_id(self, resource_id: str, scope: Optional[Union[str, list[str]]] = None) -> None:
        """
        Asserts authorized access to the specified resource id with optional scope(s).
        Uses UMA 2.0 grant workflow: https://docs.kantarainitiative.org/uma/wg/oauth-uma-grant-2.0-09.html

        Args:
            resource_id (str): The id of the resource to check.
            scope (str | list[str], optional): Also check against one or more specific scopes; if multiple scopes are
                provided, the user must have access to all of them. Defaults to None.

        Returns:
            bool: True if the user has permission to access the specified resource (with the all of the specified
                scopes if provided).

        Raises:
            KeycloakPostError: If the resource was not found on the authorization server.
            HTTPException (401 Unauthorized with `WWW-Authenticate` header): If the user does not currently have
                authorization; clients should use the provided header to request authorization according to UMA 2.0.
            HTTPException (403 Forbidden): If the authorization server is unavailable.
        """

        if self.__access.has_authorization(resource_id=UUID(resource_id), scope=scope):
            return

        if scope is None:
            scope = []
        if isinstance(scope, str):
            scope = [scope]

        await self.__raise_authorization_required({resource_id: scope})

    async def __get_resource_id(self, resource_name: str) -> str:
        resource_ids = await self.__uma.a_resource_set_list_ids(exact_name=True, name=resource_name, first=0, maximum=1)

        if not resource_ids:
            raise KeycloakPostError(f"Resource '{resource_name}' was not found")

        return resource_ids[0]  # type: ignore

    async def __raise_authorization_required(self, resources: dict[str, list[str]]) -> Never:
        try:
            realm_name = self.__uma.connection.realm_name

            if not realm_name:
                raise RuntimeError("Keycloak realm name was not set")

            well_known = await self.__uma.a__fetch_well_known()
            as_uri = well_known["issuer"]
            permission_endpoint = well_known["permission_endpoint"]
            ticket_request = KeycloakPermissionTicketRequest(
                [
                    KeycloakResourceRequest(resource_id=resource_id, resource_scopes=scopes)
                    for resource_id, scopes in resources.items()
                ]
            )
            ticket = await self.__get_permission_ticket(permission_endpoint, ticket_request)

        except Exception:
            raise UMAAuthorizationServerUnreachable()

        raise UMAAuthorizationRequired(realm=realm_name, as_uri=as_uri, ticket=ticket)

    async def __get_permission_ticket(self, endpoint: str, request: KeycloakPermissionTicketRequest) -> str:
        data_raw = await self.__uma.connection.a_raw_post(endpoint, data=request.model_dump_json())
        return raise_error_from_response(data_raw, KeycloakPostError)["ticket"]
