from collections.abc import Iterable

from starlette import status
from starlette.exceptions import HTTPException
from starlette.requests import Request
from typing_extensions import Any, Callable, Optional, Self, Union

from ..user import APIUser
from .proto import UMAAuthCredentials


class UMAAuthorized:
    """
    Ensures the authenticated user is authorized to access the specified resource (with optional scopes) using User-
    Managed Access (UMA). Required UMA-enabled backend like `KeycloakAuthBackend`.

    **NOTE**: Dependency MUST be instantiated, e.g.,:

    `Annotated[Authorized, Depends(Authorized("<resource name>", "<scope>"))]`
    """

    def __init__(
        self,
        resource: str,
        scope: Optional[Union[str, list[str]]] = None,
        decision: Callable[[Iterable[Any]], bool] = all,
    ):
        """
        Authorize the user to access the specified resource.

        Args:
            resource (str): The name of the UMA resource to authorize for.
            scope (str | list[str] | None, optional): Optional scope(s) to authorize for. Defaults to None.
            decision (Callable[[Iterable[Any]], bool], optional): If providing multiple scopes, specifies the decision
                function to apply against all scopes such as `any` or `all` or a custom callable. Defaults to `all`.
        """

        self.resource = resource

        if scope is None:
            self.scope = []
        elif isinstance(scope, str):
            self.scope = [scope]
        else:
            self.scope = scope

        self.decision = decision

    def __call__(self, request: Request) -> Self:
        if "user" not in request.scope or not request.user:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not authenticated")

        self.__user = request.user

        if "auth" not in request.scope or not request.auth:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not authorized")

        self.__auth: UMAAuthCredentials = request.auth

        if not self.decision([self.__auth.has_permission(self.resource, scope) for scope in self.scope]):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "User does not have permission to access resource")

        return self

    @property
    def user(self) -> APIUser:
        return self.__user

    @property
    def auth(self) -> UMAAuthCredentials:
        return self.__auth
