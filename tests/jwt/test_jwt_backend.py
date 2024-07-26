import unittest
from unittest import mock
from uuid import uuid4

from starlette.authentication import AuthenticationError
from starlette.datastructures import Headers
from starlette.requests import HTTPConnection

from fastapi_auth.jwt import JWTAuthBackend, JWTUser


class JWTAuthBackendTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.backend = JWTAuthBackend(
            algorithms=mock.MagicMock(),
            audience=mock.MagicMock(),
            key=mock.MagicMock(),
        )

    @mock.patch("fastapi_auth.jwt.backend.jwt")
    async def test_should_create_user_for_authorization_bearer_header(self, mock_jwt: mock.MagicMock):
        sub = str(uuid4())
        mock_jwt.decode.return_value = {
            "sub": sub,
        }

        http_mock = mock.MagicMock(HTTPConnection)
        http_mock.headers = Headers({"Authorization": "Bearer xzy123"})

        creds, user = await self.backend.authenticate(http_mock)  # type: ignore

        self.assertIsNotNone(creds)
        self.assertIn("authenticated", creds.scopes)

        self.assertIsNotNone(user)
        self.assertIsInstance(user, JWTUser)
        self.assertEqual(sub, user.identity)
        self.assertEqual(sub, user.display_name)
        self.assertTrue(user.is_authenticated)

    async def test_should_raise_if_no_authorization_header(self):
        http_mock = mock.MagicMock(HTTPConnection)
        http_mock.headers = Headers({})

        with self.assertRaises(AuthenticationError):
            await self.backend.authenticate(http_mock)

    async def test_should_raise_if_authorization_empty(self):
        http_mock = mock.MagicMock(HTTPConnection)
        http_mock.headers = Headers({"Authorization": ""})

        with self.assertRaises(AuthenticationError):
            await self.backend.authenticate(http_mock)

    async def test_should_raise_if_authorization_scheme_not_bearer(self):
        http_mock = mock.MagicMock(HTTPConnection)
        http_mock.headers = Headers({"Authorization": "Basic xzy123"})

        with self.assertRaises(AuthenticationError):
            await self.backend.authenticate(http_mock)

    async def test_should_raise_if_authorization_credential_empty(self):
        http_mock = mock.MagicMock(HTTPConnection)
        http_mock.headers = Headers({"Authorization": "Bearer"})

        with self.assertRaises(AuthenticationError):
            await self.backend.authenticate(http_mock)
