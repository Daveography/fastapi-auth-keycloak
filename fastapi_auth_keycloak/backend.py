from collections.abc import Iterable

from jwcrypto import jwk
from jwcrypto.common import JWException
from starlette.authentication import AuthenticationBackend, AuthenticationError
from starlette.datastructures import Secret
from starlette.requests import HTTPConnection
from typing_extensions import Any, Callable, Optional, Union

from .auth_credentials import KeycloakAuthCredentials
from .auth_header import AuthenticationHeader
from .public_key import PublicKey
from .user import KeycloakUser

try:
    from keycloak import KeycloakOpenIDConnection
except ImportError:
    raise RuntimeError(
        "Install the package with the `keycloak` extra (fastapi-auth[keycloak]) to use the KeycloakAuthBackend"
    )


class KeycloakAuthBackend(AuthenticationBackend):
    """
    An implementation of the Starlette `AuthenticationBackend` that parses JWT tokens issued by Keycloak for user
    authentication and authorization.
    """

    def __init__(
        self,
        url: str,
        realm: str,
        client_id: str,
        client_secret: Secret,
        audience: Union[str, Iterable[str]],
        authentication_required: bool = True,
        user_factory: Callable[[dict[str, Any]], KeycloakUser] = KeycloakUser.model_validate,
    ) -> None:
        """
        Initializes a new instance of the `KeycloakAuthBackend` class.

        Args:
            url (str): The base URL of the Keycloak Server.
            realm (str): The Keycloak Realm used for authentication.
            client_id (str): The Keycloak Client Id to use to configure this backend.
            client_secret (Secret): They Client Secret key for the Client Id.
            audience (str | Iterable[str]): The expected audience(s) for the token for verification.
            authentication_required (bool, optional): When `True`, an `AuthenticationError` is raised if Authentication
                is not provided; otherwise will permit the request to complete unauthenticated. Defaults to `True`.
            user_factory (Callable[[Dict[str, Any]], KeycloakUser], optional): A method to be called with the decoded
                JWT as the sole parameter in order to construct the user object. Defaults to
                `KeycloakUser.model_validate`.
        """

        self.__connection = KeycloakOpenIDConnection(
            server_url=url,
            realm_name=realm,
            client_id=client_id,
            client_secret_key=str(client_secret),
        )
        self.__keycloak = self.__connection.keycloak_openid

        self.__audience = audience
        self.__config = self.__keycloak.well_known()
        self.__algorithms = self.__config["id_token_signing_alg_values_supported"]
        self.__authentication_required = authentication_required
        self.__public_key = jwk.JWK.from_pem(PublicKey(self.__keycloak.public_key()).encode())
        self.__user_factory = user_factory

    async def authenticate(self, conn: HTTPConnection) -> Optional[tuple[KeycloakAuthCredentials, KeycloakUser]]:
        auth_header = AuthenticationHeader.get_from(conn.headers)

        if auth_header is None:
            if self.__authentication_required:
                raise AuthenticationError("Authentication is required")
            return None

        if auth_header.scheme.lower() != "bearer" or not auth_header.credential:
            # NOTE: This should be updated if we want to support something other than a Bearer token
            raise AuthenticationError("Invalid Authorization header")

        try:
            # Don't need to use the async method as we're providing the public key
            token = self.__keycloak.decode_token(
                auth_header.credential,
                key=self.__public_key,
                algs=self.__algorithms,
                check_claims={"exp": None, "aud": self.__audience},
            )

        except JWException as err:
            raise AuthenticationError(err)

        user = self.__user_factory(token)
        auth_cred = KeycloakAuthCredentials(token=token, keycloak=self.__connection)

        return auth_cred, user
