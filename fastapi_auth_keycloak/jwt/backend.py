from collections.abc import Iterable

from jwcrypto import jwk, jwt
from jwcrypto.common import JWException
from starlette.authentication import AuthCredentials, AuthenticationBackend, AuthenticationError
from starlette.requests import HTTPConnection
from typing_extensions import Any, Callable, Dict, Optional, Tuple, Union

from ..auth_header import AuthenticationHeader
from ..public_key import PublicKey
from .user import JWTUser


class JWTAuthBackend(AuthenticationBackend):
    """
    An implementation of the Starlette `AuthenticationBackend` that parses basic JWT tokens for authentication.
    """

    def __init__(
        self,
        algorithms: Iterable[str],
        audience: Union[str, Iterable[str]],
        public_key: Union[PublicKey, str],
        authentication_required: bool = True,
        user_factory: Callable[[Dict[str, Any]], JWTUser] = JWTUser.model_validate,
    ) -> None:
        """
        Initializes a new instance of the `JWTAuthBackend` class.

        Args:
            algorithms (Iterable[str]): The accepted JWT algorithms to use for token verification.
            audience (str | Iterable[str]): The expected audience(s) for the token for verification.
            public_key (PublicKey |, str): They public key used to verify the token.
            authentication_required (bool, optional): When `True`, an `AuthenticationError` is raised if Authentication
                is not provided; otherwise will permit the request to complete unauthenticated. Defaults to `True`.
            user_factory (Callable[[Dict[str, Any]], JWTUser], optional): A method to be called with the decoded JWT
                as the sole parameter in order to construct the user object. Defaults to `JWTUser.model_validate`.
        """

        self.__algorithms = list(algorithms)
        self.__audience = audience
        self.__authentication_required = authentication_required
        self.__user_factory = user_factory

        if not isinstance(public_key, PublicKey):
            public_key = PublicKey(public_key)

        self._public_key = jwk.JWK.from_pem(public_key.encode())

    async def authenticate(self, conn: HTTPConnection) -> Optional[Tuple[AuthCredentials, JWTUser]]:
        auth_header = AuthenticationHeader.get_from(conn.headers)

        if auth_header is None:
            if self.__authentication_required:
                raise AuthenticationError("Authentication is required")
            return None

        if auth_header.scheme.lower() != "bearer" or not auth_header.credential:
            # NOTE: This should be updated if we want to support something other than a Bearer token
            raise AuthenticationError("Invalid Authorization header")

        try:
            cred_jwt = jwt.JWT(
                jwt=auth_header.credential, algs=self.__algorithms, check_claims={"aud": self.__audience}
            )
            cred_jwt.validate(self._public_key)
            token = jwt.json_decode(cred_jwt.claims)

        except JWException as err:
            raise AuthenticationError(err)

        user = self.__user_factory(token)
        scopes = token["scope"].split(" ") if "scope" in token else []

        return AuthCredentials(scopes), user
