import unittest
from unittest import mock
from uuid import uuid4

from starlette.datastructures import Headers
from starlette.requests import HTTPConnection

from fastapi_auth_keycloak import KeycloakAuthBackend, KeycloakUser

rs_public_key = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo"
    "4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u"
    "+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh"
    "kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ"
    "0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg"
    "cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc"
    "mwIDAQAB"
)


class KeycloakAuthBackendTests(unittest.IsolatedAsyncioTestCase):
    @mock.patch("fastapi_auth_keycloak.backend.KeycloakOpenIDConnection")
    @mock.patch("fastapi_auth_keycloak.backend.jwk")
    async def asyncSetUp(self, mock_jwk: mock.MagicMock, mock_connection: mock.MagicMock):
        self.mock_keycloak = mock_connection.return_value.keycloak_openid
        self.mock_keycloak.public_key.return_value = "<public key>"
        self.backend = KeycloakAuthBackend(
            url=mock.MagicMock(),
            realm=mock.MagicMock(),
            client_id=mock.MagicMock(),
            client_secret=mock.MagicMock(),
            audience=mock.MagicMock(),
        )

        self.http_mock = mock.MagicMock(HTTPConnection)
        self.http_mock.headers = Headers({"Authorization": "Bearer xzy123"})

    async def test_should_create_keycloak_user(self):
        sub = str(uuid4())
        self.mock_keycloak.decode_token.return_value = {
            "sub": sub,
            "email": "me@daveography.ca",
            "preferred_username": "my_user",
            "scope": "profile email",
        }

        http_mock = mock.MagicMock(HTTPConnection)
        http_mock.headers = Headers({"Authorization": "Bearer xzy123"})

        _, user = await self.backend.authenticate(http_mock)  # type: ignore

        self.assertIsNotNone(user)
        self.assertIsInstance(user, KeycloakUser)
        self.assertEqual(sub, user.identity)
        self.assertEqual("my_user", user.display_name)
        self.assertTrue(user.is_authenticated)

    async def test_should_get_public_key_from_keycloak(self):
        self.mock_keycloak.public_key.assert_called_once()
