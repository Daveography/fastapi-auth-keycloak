from starlette.datastructures import Secret

from fastapi_auth.jwt.backend import JWTAuthBackend
from fastapi_auth.jwt.keycloak.user import KeycloakUser


class KeycloakAuthBackend(JWTAuthBackend):
    def __init__(
        self,
        algorithm: str,
        audience: str,
        key: Secret,
    ) -> None:
        super().__init__(algorithm, audience, key, user_factory=KeycloakUser.parse_obj)
