from collections.abc import Iterable

from jwcrypto import jwk
from jwcrypto.common import JWException
from starlette.authentication import AuthenticationBackend, AuthenticationError
from starlette.datastructures import Secret
from starlette.requests import HTTPConnection
from typing_extensions import Any, Callable, Literal, Optional, Union

from ..auth_header import AuthenticationHeader
from ..public_key import PublicKey
from .auth_credentials import KeycloakAuthCredentials
from .token_cache import TokenCache
from .user import KeycloakUser

try:
    from keycloak import KeycloakOpenID
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
        uma_authorization: Optional[Literal["ticket", "permission"]] = None,
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
            uma_authorization (Literal["ticket", "permission"] |, optional): If provided, specifies the type of
                authorization to use for User-Managed Access (UMA); if set to `ticket`, the backend will obtain and
                cache a `uma-ticket` from Keycloak, while `permission` will enable the returned
                `KeycloakAuthCredentials` to query Keycloak for any specific permissions requested.
            user_factory (Callable[[Dict[str, Any]], KeycloakUser], optional): A method to be called with the decoded
            JWT as the sole parameter in order to construct the user object. Defaults to `KeycloakUser.model_validate`.
        """

        self.__keycloak = KeycloakOpenID(
            server_url=url,
            realm_name=realm,
            client_id=client_id,
            client_secret_key=str(client_secret),
        )

        self.__audience = audience
        self.__config = self.__keycloak.well_known()
        self.__algorithms = self.__config["id_token_signing_alg_values_supported"]
        self.__authentication_required = authentication_required
        self.__public_key = jwk.JWK.from_pem(PublicKey(self.__keycloak.public_key()).encode())
        self.__uma_authorization = uma_authorization
        self.__user_factory = user_factory

        self.__token_cache = TokenCache()

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
            token = self.__keycloak.decode_token(
                auth_header.credential,
                key=self.__public_key,
                algs=self.__algorithms,
                check_claims={"aud": self.__audience},
            )

        except JWException as err:
            raise AuthenticationError(err)

        user = self.__user_factory(token)

        if "authorization" not in token and self.__uma_authorization == "ticket":
            token = await self.__get_uma_token(token)

        auth_cred = KeycloakAuthCredentials(
            token, self.__keycloak if self.__uma_authorization == "permission" else None
        )

        return auth_cred, user

    async def __get_uma_token(self, token: dict[str, Any]) -> dict[str, Any]:
        token_session_id = token["sid"]

        if token_session_id in self.__token_cache:
            return self.__token_cache[token_session_id]

        permissions = await self.__keycloak.a_uma_permissions(token)
        self.__token_cache[token_session_id] = permissions

        return permissions
