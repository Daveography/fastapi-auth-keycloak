import unittest
from unittest import mock
from uuid import uuid4

from starlette.authentication import AuthenticationError
from starlette.datastructures import Headers
from starlette.requests import HTTPConnection

from fastapi_auth import JWTAuthBackend, JWTUser, PublicKey


class JWTAuthBackendTests(unittest.IsolatedAsyncioTestCase):
    @mock.patch("fastapi_auth.jwt.backend.jwk")
    async def asyncSetUp(self, mock_jwk: mock.MagicMock):
        self.backend = JWTAuthBackend(
            algorithms=mock.MagicMock(),
            audience=mock.MagicMock(),
            public_key=mock.MagicMock(PublicKey),
        )

    @mock.patch("fastapi_auth.jwt.backend.jwt")
    async def test_should_create_user_for_authorization_bearer_header(self, mock_jwt: mock.MagicMock):
        sub = str(uuid4())
        mock_jwt.json_decode.return_value = {
            "sub": sub,
        }

        http_mock = mock.MagicMock(HTTPConnection)
        http_mock.headers = Headers({"Authorization": "Bearer xzy123"})

        _, user = await self.backend.authenticate(http_mock)  # type: ignore

        self.assertIsNotNone(user)
        self.assertIsInstance(user, JWTUser)
        self.assertEqual(sub, user.identity)
        self.assertEqual(sub, user.display_name)
        self.assertTrue(user.is_authenticated)

    @mock.patch("fastapi_auth.jwt.backend.jwt")
    async def test_should_return_auth_credentials_with_scopes_if_provided(self, mock_jwt: mock.MagicMock):
        sub = str(uuid4())
        mock_jwt.json_decode.return_value = {"sub": sub, "scope": "profile email"}

        http_mock = mock.MagicMock(HTTPConnection)
        http_mock.headers = Headers({"Authorization": "Bearer xzy123"})

        creds, _ = await self.backend.authenticate(http_mock)  # type: ignore

        self.assertIsNotNone(creds)
        self.assertIn("profile", creds.scopes)
        self.assertIn("email", creds.scopes)

    @mock.patch("fastapi_auth.jwt.backend.jwt")
    async def test_should_return_empty_auth_credentials_if_no_scopes_provided(self, mock_jwt: mock.MagicMock):
        sub = str(uuid4())
        mock_jwt.json_decode.return_value = {"sub": sub}

        http_mock = mock.MagicMock(HTTPConnection)
        http_mock.headers = Headers({"Authorization": "Bearer xzy123"})

        creds, _ = await self.backend.authenticate(http_mock)  # type: ignore

        self.assertIsNotNone(creds)
        self.assertNotIn("profile", creds.scopes)
        self.assertNotIn("email", creds.scopes)

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

    @mock.patch("fastapi_auth.jwt.backend.jwk")
    async def test_should_return_none_if_no_authorization_header_and_auth_not_required(self, mock_jwk: mock.MagicMock):
        backend = JWTAuthBackend(
            algorithms=mock.MagicMock(),
            audience=mock.MagicMock(),
            public_key=mock.MagicMock(PublicKey),
            authentication_required=False,
        )

        http_mock = mock.MagicMock(HTTPConnection)
        http_mock.headers = Headers({})

        result = await backend.authenticate(http_mock)

        self.assertIsNone(result)
