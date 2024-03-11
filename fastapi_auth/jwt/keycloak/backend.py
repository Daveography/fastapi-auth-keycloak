from starlette.datastructures import Secret

from ..backend import JWTAuthBackend
from .user import KeycloakUser


class KeycloakAuthBackend(JWTAuthBackend):
    """
    An implementation of the Starlette `AuthenticationBackend` that parses JWT tokens from Keycloak for authentication.
    """

    def __init__(
        self,
        algorithm: str,
        audience: str,
        key: Secret,
    ) -> None:
        """
        Initializes a new instance of the `JWTAuthBackend` class.

        Args:
            algorithm (str): The JWT algorithm to use for token verification.
            audience (str): The expected audience for the token for verification
            key (Secret): They secret key used to verify the token.
        """

        super().__init__(algorithm, audience, key, user_factory=KeycloakUser.parse_obj)
