import unittest
from unittest import mock
from uuid import uuid4

from starlette.datastructures import Headers
from starlette.requests import HTTPConnection

from fastapi_auth.jwt.keycloak import KeycloakAuthBackend, KeycloakUser


class KeycloakAuthBackendTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.backend = KeycloakAuthBackend(
            algorithm=mock.MagicMock(),
            audience=mock.MagicMock(),
            key=mock.MagicMock(),
        )

    @mock.patch("fastapi_auth.jwt.backend.jwt")
    async def test_should_create_keycloak_user(self, mock_jwt: mock.MagicMock):
        sub = str(uuid4())
        mock_jwt.decode.return_value = {
            "sub": sub,
            "email": "me@alphalayer.ai",
            "preferred_username": "my_user",
        }

        http_mock = mock.MagicMock(HTTPConnection)
        http_mock.headers = Headers({"Authorization": "Bearer xzy123"})

        _, user = await self.backend.authenticate(http_mock)  # type: ignore

        self.assertIsNotNone(user)
        self.assertIsInstance(user, KeycloakUser)
        self.assertEqual(sub, user.identity)
        self.assertEqual("my_user", user.display_name)
        self.assertTrue(user.is_authenticated)
