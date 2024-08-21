from typing_extensions import Any, Optional, Protocol, Union, runtime_checkable


@runtime_checkable
class UMAResourcePermission(Protocol):
    """
    A representation of a User-Managed Access (UMA) resource permission that a user has been granted.
    """

    @property
    def id(self) -> Any:
        """The Id of the resource."""
        ...

    @property
    def name(self) -> Optional[str]:
        """The name of the resource, if provided."""
        ...

    @property
    def scopes(self) -> Optional[list[str]]:
        """A list of scopes available for the resource, if provided."""
        ...


@runtime_checkable
class UMAAuthCredentials(Protocol):
    """
    starlette.authentication.AuthCredentials-compatible protocol enhanced for UMA user authorization.
    """

    @property
    def scopes(self) -> list[str]:
        """A list of scopes the user has been authorized to access."""
        ...

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

        ...

    async def authorize_by_id(self, resource_id: str, scope: Optional[Union[str, list[str]]] = None) -> None:
        """
        Asserts authorized access to the specified resource id with optional scope(s).
        Uses UMA 2.0 grant workflow: https://docs.kantarainitiative.org/uma/wg/oauth-uma-grant-2.0-09.html

        Args:
            resource_id (str): The id of the resource to check.
            scope (str | list[str], optional): Also check against one or more specific scopes; if multiple scopes are
                provided, the user must have access to all of them. Defaults to None.

        Raises:
            KeycloakPostError: If the resource was not found on the authorization server.
            HTTPException (401 Unauthorized with `WWW-Authenticate` header): If the user does not currently have
                authorization; clients should use the provided header to request authorization according to UMA 2.0.
            HTTPException (403 Forbidden): If the authorization server is unavailable.
        """

        ...
