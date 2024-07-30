from starlette.datastructures import Secret
from typing_extensions import Optional

from ...hmac_key import HMACKey
from ..backend import JWTAuthBackend
from .user import KeycloakUser

try:
    from keycloak import KeycloakOpenID
except ImportError:
    raise RuntimeError(
        "Install the package with the `keycloak` extra (fastapi-auth[keycloak]) to use the KeycloakAuthBackend"
    )


class KeycloakAuthBackend(JWTAuthBackend):
    """
    An implementation of the Starlette `AuthenticationBackend` that parses JWT tokens from Keycloak for authentication.
    """

    def __init__(
        self,
        url: str,
        realm: str,
        client_id: str,
        client_secret: Secret,
        audience: str,
        hmac_key: Optional[HMACKey] = None,
    ) -> None:
        """
        Initializes a new instance of the `JWTAuthBackend` class.

        Args:
            url (str): The base URL of the Keycloak Server.
            realm (str): The Keycloak Realm used for authentication.
            client_id (str): The Keycloak Client Id to use to configure this backend.
            client_secret (Secret): They Client Secret key for the Client Id.
            audience (str): The expected audience for the token for verification
        """

        keycloak = KeycloakOpenID(
            server_url=url,
            realm_name=realm,
            client_id=client_id,
            client_secret_key=str(client_secret),
        )

        config = keycloak.well_known()
        algorithms: list[str] = config["id_token_signing_alg_values_supported"]  # type: ignore

        super().__init__(
            algorithms=algorithms,
            audience=audience,
            public_key=keycloak.public_key(),
            hmac_key=hmac_key,
            user_factory=KeycloakUser.model_validate,
        )
