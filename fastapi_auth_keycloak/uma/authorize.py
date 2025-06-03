from starlette import status
from starlette.exceptions import HTTPException
from starlette.requests import Request
from typing_extensions import Optional, Self, Union

from ..api_user import APIUser
from .proto import UMAAuthCredentials


class UMAAuthorize:
    """
    Ensures the authenticated user is authorized to access the specified resource (with optional scopes) using User-
    Managed Access (UMA). Requires UMA-enabled backend like `KeycloakAuthBackend`.

    **NOTE**: Dependency MUST be instantiated, e.g.,:

    `Annotated[UMAAuthorize, Depends(UMAAuthorize("<resource name>", "<scope>"))]`
    """

    def __init__(self, resource: str, scope: Optional[Union[str, list[str]]] = None):
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

    async def __call__(self, request: Request) -> Self:
        if "user" not in request.scope or not request.user:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not authenticated")

        self.__user = request.user

        if "auth" not in request.scope or not request.auth:
            raise RuntimeError("Backend did not provide AuthCredentials")

        if not isinstance(request.auth, UMAAuthCredentials):
            raise RuntimeError("Backend did not provide UMA-compatible AuthCredentials")

        self.__auth = request.auth

        await self.__auth.authorize(self.resource, self.scope)

        return self

    @property
    def user(self) -> APIUser:
        return self.__user

    @property
    def auth(self) -> UMAAuthCredentials:
        return self.__auth
