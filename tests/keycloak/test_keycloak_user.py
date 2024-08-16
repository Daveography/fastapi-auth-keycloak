import unittest
from unittest import mock
from uuid import uuid4

from starlette.datastructures import Headers
from starlette.requests import HTTPConnection

from fastapi_auth.keycloak import KeycloakAuthBackend


class KeycloakUserTests(unittest.IsolatedAsyncioTestCase):
    @mock.patch("fastapi_auth.keycloak.backend.KeycloakOpenID")
    @mock.patch("fastapi_auth.keycloak.backend.jwk")
    async def asyncSetUp(self, mock_jwk: mock.MagicMock, mock_keycloak: mock.MagicMock):
        self.mock_keycloak = mock_keycloak.return_value
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

    async def test_should_set_id_from_jwt_sub_field(self):
        sub = uuid4()
        self.mock_keycloak.decode_token.return_value = {
            "sub": str(sub),
            "email": "me@alphalayer.ai",
            "preferred_username": "my_user",
            "scope": "profile email",
        }

        _, user = await self.backend.authenticate(self.http_mock)  # type: ignore

        self.assertEqual(sub, user.id)  # type: ignore

    async def test_should_set_identity_from_jwt_sub_field(self):
        sub = str(uuid4())
        self.mock_keycloak.decode_token.return_value = {
            "sub": sub,
            "email": "me@alphalayer.ai",
            "preferred_username": "my_user",
            "scope": "profile email",
        }

        _, user = await self.backend.authenticate(self.http_mock)  # type: ignore

        self.assertEqual(sub, user.identity)

    async def test_display_name_should_be_full_name_when_provided(self):
        sub = str(uuid4())
        self.mock_keycloak.decode_token.return_value = {
            "sub": sub,
            "email": "me@alphalayer.ai",
            "preferred_username": "my_user",
            "scope": "profile email",
            "name": "FirstName LastName",
        }

        _, user = await self.backend.authenticate(self.http_mock)  # type: ignore

        self.assertEqual("FirstName LastName", user.display_name)

    async def test_display_name_should_be_preferred_name_when_full_name_not_provided(self):
        sub = str(uuid4())
        self.mock_keycloak.decode_token.return_value = {
            "sub": sub,
            "email": "me@alphalayer.ai",
            "preferred_username": "my_user",
            "scope": "profile email",
        }

        _, user = await self.backend.authenticate(self.http_mock)  # type: ignore

        self.assertEqual("my_user", user.display_name)

    async def test_should_be_true_when_user_is_in_expected_group(self):
        sub = str(uuid4())
        self.mock_keycloak.decode_token.return_value = {
            "sub": sub,
            "email": "me@alphalayer.ai",
            "preferred_username": "my_user",
            "scope": "profile email",
            "groups": ["/alpha-app/administrators"],
        }

        _, user = await self.backend.authenticate(self.http_mock)  # type: ignore

        self.assertIsNotNone(user.groups)  # type: ignore
        self.assertTrue("/alpha-app/administrators" in user.groups)  # type: ignore

    async def test_should_be_false_when_user_is_not_in_group(self):
        sub = str(uuid4())
        self.mock_keycloak.decode_token.return_value = {
            "sub": sub,
            "email": "me@alphalayer.ai",
            "preferred_username": "my_user",
            "scope": "profile email",
            "groups": ["/alpha-app/users"],
        }

        _, user = await self.backend.authenticate(self.http_mock)  # type: ignore

        self.assertIsNotNone(user.groups)  # type: ignore
        self.assertFalse("/alpha-app/administrators" in user.groups)  # type: ignore

    async def test_should_be_none_groups_are_not_provided(self):
        sub = str(uuid4())
        self.mock_keycloak.decode_token.return_value = {
            "sub": sub,
            "email": "me@alphalayer.ai",
            "preferred_username": "my_user",
            "scope": "profile email",
        }

        _, user = await self.backend.authenticate(self.http_mock)  # type: ignore

        self.assertIsNone(user.groups)  # type: ignore
