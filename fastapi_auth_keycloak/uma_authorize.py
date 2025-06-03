from starlette.requests import Request
from typing_extensions import Self

from .auth_credentials import KeycloakAuthCredentials
from .uma.authorize import UMAAuthorize
from .user import KeycloakUser


class KeycloakUMAAuthorize(UMAAuthorize):
    """
    Ensures the authenticated user is authorized to access the specified resource (with optional scopes) using User-
    Managed Access (UMA). Requires `KeycloakAuthBackend`.

    **NOTE**: Dependency MUST be instantiated, e.g.,:

    `Annotated[KeycloakUMAAuthorize, Depends(KeycloakUMAAuthorize("<resource name>", "<scope>"))]`
    """

    async def __call__(self, request: Request) -> Self:
        if not isinstance(request.user, KeycloakUser):
            raise RuntimeError("Backend did not provide KeycloakUser")

        if not isinstance(request.auth, KeycloakAuthCredentials):
            raise RuntimeError("Backend did not provide KeycloakAuthCredentials")

        return await super().__call__(request)

    @property
    def user(self) -> KeycloakUser:
        return super().user  # type: ignore

    @property
    def auth(self) -> KeycloakAuthCredentials:
        return super().auth  # type: ignore
