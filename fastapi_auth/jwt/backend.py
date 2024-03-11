from typing import Any, Callable, Dict, Optional, Tuple

import jwt
from starlette.authentication import AuthCredentials, AuthenticationBackend, AuthenticationError, BaseUser
from starlette.datastructures import Secret
from starlette.requests import HTTPConnection

from ..user import APIUser
from .user import JWTUser


class JWTAuthBackend(AuthenticationBackend):
    def __init__(
        self,
        algorithm: str,
        audience: str,
        key: Secret,
        user_factory: Callable[[Dict[str, Any]], APIUser] = JWTUser.parse_obj,
    ) -> None:
        self.__algorithm = algorithm
        self.__audience = audience
        self.__key = key
        self.__user_factory = user_factory

    async def authenticate(self, conn: HTTPConnection) -> Optional[Tuple[AuthCredentials, BaseUser]]:
        if "Authorization" in conn.headers:
            scheme, credential = self.__get_auth_scheme(conn.headers["Authorization"])

            if not scheme or scheme.lower() != "bearer" or not credential:
                raise AuthenticationError("Invalid authentication credentials")

            try:
                token = jwt.decode(
                    jwt=credential,
                    key=str(self.__key),
                    algorithms=[self.__algorithm],
                    audience=self.__audience,
                )

            except jwt.InvalidTokenError as err:
                raise AuthenticationError(err)

            user = self.__user_factory(token)

            return AuthCredentials(["authenticated"]), user

        raise AuthenticationError("Not authenticated")

    @staticmethod
    def __get_auth_scheme(authorization_header_value: str) -> Tuple[str, str]:
        if not authorization_header_value:
            return "", ""
        scheme, _, param = authorization_header_value.partition(" ")
        return scheme, param
