from typing_extensions import Any, Optional, Protocol, runtime_checkable


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

        ...

    def load_permissions(self) -> None:
        """
        Loads all authorization permissions the user has been granted from the backend (if configured).
        """

        ...
