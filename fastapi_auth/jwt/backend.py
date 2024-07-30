from collections.abc import Iterable

import jwt
from starlette.authentication import AuthCredentials, AuthenticationBackend, AuthenticationError, BaseUser
from starlette.requests import HTTPConnection
from typing_extensions import Any, Callable, Dict, Optional, Tuple, Union

from ..hmac_key import HMACKey
from ..public_key import PublicKey
from ..user import APIUser
from .user import JWTUser


class JWTAuthBackend(AuthenticationBackend):
    """
    An implementation of the Starlette `AuthenticationBackend` that parses JWT tokens for authentication.

    *NOTE*: This is mostly meant to be used as a base class for more specific auth providers that provide JWT tokens,
    such as Keycloak, but it can be used directly to get a basic `JWTUser` object.
    """

    def __init__(
        self,
        algorithms: Iterable[str],
        audience: str,
        public_key: Optional[Union[PublicKey, str]] = None,
        hmac_key: Optional[HMACKey] = None,
        user_factory: Callable[[Dict[str, Any]], APIUser] = JWTUser.model_validate,
    ) -> None:
        """
        Initializes a new instance of the `JWTAuthBackend` class.

        Args:
            algorithms (Iterable[str]): The JWT algorithms to use for token verification.
            audience (str): The expected audience for the token for verification
            key (Secret): They public key (or HMAC secret key) used to verify the token.
            user_factory (Callable[[Dict[str, Any]], APIUser], optional): A method to be called with the decoded JWT
                as the sole parameter in order to construct the user object. Defaults to `JWTUser.model_validate`.
        """
        if not public_key and not hmac_key:
            raise RuntimeError("Either a public key or HMAC key (or both) must be provided")

        self._algorithms = list(algorithms)
        self._audience = audience
        self._user_factory = user_factory

        if public_key is not None and not isinstance(public_key, PublicKey):
            public_key = PublicKey(public_key)

        self._public_key = public_key
        self._hmac_key = hmac_key

    async def authenticate(self, conn: HTTPConnection) -> Optional[Tuple[AuthCredentials, BaseUser]]:
        if "Authorization" in conn.headers:
            scheme, credential = self.__get_auth_scheme(conn.headers["Authorization"])

            if not scheme or scheme.lower() != "bearer" or not credential:
                raise AuthenticationError("Invalid authentication credentials")

            try:
                headers = jwt.get_unverified_header(credential)
                if "alg" in headers and headers["alg"].upper().startswith("HS"):
                    key = str(self._hmac_key)
                    if not key:
                        raise RuntimeError("JWT signed using HMAC, but HMAC key was not set on the backend")

                else:
                    if not self._public_key:
                        raise RuntimeError("Unable to decode JWT, public key was not set on the backend")
                    key = self._public_key.key

                token = jwt.decode(
                    jwt=credential,
                    key=key,  # type: ignore
                    algorithms=self._algorithms,
                    audience=self._audience,
                )

            except jwt.InvalidTokenError as err:
                raise AuthenticationError(err)

            user = self._user_factory(token)

            return AuthCredentials(["authenticated"]), user

        raise AuthenticationError("Not authenticated")

    @staticmethod
    def __get_auth_scheme(authorization_header_value: str) -> Tuple[str, str]:
        if not authorization_header_value:
            return "", ""
        scheme, _, param = authorization_header_value.partition(" ")
        return scheme, param
