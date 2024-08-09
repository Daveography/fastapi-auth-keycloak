import unittest
from unittest import mock
from uuid import uuid4

from starlette.datastructures import Headers
from starlette.requests import HTTPConnection

from fastapi_auth import KeycloakAuthBackend


class KeycloakAuthCredentialsTests(unittest.IsolatedAsyncioTestCase):
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

    async def test_should_provide_scopes(self):
        sub = str(uuid4())
        self.mock_keycloak.decode_token.return_value = {
            "sub": sub,
            "email": "me@alphalayer.ai",
            "preferred_username": "my_user",
            "scope": "profile email",
        }

        http_mock = mock.MagicMock(HTTPConnection)
        http_mock.headers = Headers({"Authorization": "Bearer xzy123"})

        cred, _ = await self.backend.authenticate(http_mock)  # type: ignore

        self.assertIsNotNone(cred)
        self.assertIn("profile", cred.scopes)
        self.assertIn("email", cred.scopes)

    async def test_should_be_true_when_user_has_expected_resource_access_role(self):
        sub = str(uuid4())
        self.mock_keycloak.decode_token.return_value = {
            "sub": sub,
            "email": "me@alphalayer.ai",
            "preferred_username": "my_user",
            "scope": "profile email",
            "resource_access": {"alpha-app": {"roles": ["super-user"]}},
        }

        cred, _ = await self.backend.authenticate(self.http_mock)  # type: ignore

        self.assertTrue(cred.has_role("alpha-app", "super-user"))  # type: ignore

    async def test_should_be_false_when_user_does_not_have_resource_access_role(self):
        sub = str(uuid4())
        self.mock_keycloak.decode_token.return_value = {
            "sub": sub,
            "email": "me@alphalayer.ai",
            "preferred_username": "my_user",
            "scope": "profile email",
            "resource_access": {"alpha-app": {"roles": ["regular-user"]}},
        }

        cred, _ = await self.backend.authenticate(self.http_mock)  # type: ignore

        self.assertFalse(cred.has_role("alpha-app", "super-user"))  # type: ignore

    async def test_should_be_false_when_user_has_no_resource_access_roles(self):
        sub = str(uuid4())
        self.mock_keycloak.decode_token.return_value = {
            "sub": sub,
            "email": "me@alphalayer.ai",
            "preferred_username": "my_user",
            "scope": "profile email",
        }

        cred, _ = await self.backend.authenticate(self.http_mock)  # type: ignore

        self.assertFalse(cred.has_role("alpha-app", "super-user"))  # type: ignore

    async def test_should_be_true_when_user_has_authorized_permission(self):
        sub = str(uuid4())
        self.mock_keycloak.decode_token.return_value = {
            "sub": sub,
            "email": "me@alphalayer.ai",
            "preferred_username": "my_user",
            "scope": "profile email",
            "authorization": {
                "permissions": [
                    {"rsid": "3105879b-116c-41ad-b415-2aa932fe7789", "rsname": "test-resource", "scopes": ["test"]}
                ]
            },
        }

        cred, _ = await self.backend.authenticate(self.http_mock)  # type: ignore

        self.assertTrue(cred.has_permission("test-resource"))  # type: ignore

    async def test_should_be_false_when_user_does_not_have_authorized_permission(self):
        sub = str(uuid4())
        self.mock_keycloak.decode_token.return_value = {
            "sub": sub,
            "email": "me@alphalayer.ai",
            "preferred_username": "my_user",
            "scope": "profile email",
            "authorization": {
                "permissions": [
                    {"rsid": "3105879b-116c-41ad-b415-2aa932fe7789", "rsname": "test-resource", "scopes": ["test"]}
                ]
            },
        }

        cred, _ = await self.backend.authenticate(self.http_mock)  # type: ignore

        self.assertFalse(cred.has_permission("secure-resource"))  # type: ignore

    async def test_should_be_true_when_user_has_authorized_permission_with_scope(self):
        sub = str(uuid4())
        self.mock_keycloak.decode_token.return_value = {
            "sub": sub,
            "email": "me@alphalayer.ai",
            "preferred_username": "my_user",
            "scope": "profile email",
            "authorization": {
                "permissions": [
                    {"rsid": "3105879b-116c-41ad-b415-2aa932fe7789", "rsname": "test-resource", "scopes": ["test"]}
                ]
            },
        }

        cred, _ = await self.backend.authenticate(self.http_mock)  # type: ignore

        self.assertTrue(cred.has_permission("test-resource", scope="test"))  # type: ignore

    async def test_should_be_false_when_user_does_not_have_authorized_permission_for_scope(self):
        sub = str(uuid4())
        self.mock_keycloak.decode_token.return_value = {
            "sub": sub,
            "email": "me@alphalayer.ai",
            "preferred_username": "my_user",
            "scope": "profile email",
            "authorization": {
                "permissions": [
                    {"rsid": "3105879b-116c-41ad-b415-2aa932fe7789", "rsname": "test-resource", "scopes": ["test"]}
                ]
            },
        }

        cred, _ = await self.backend.authenticate(self.http_mock)  # type: ignore

        self.assertFalse(cred.has_permission("test-resource", scope="write"))  # type: ignore

    async def test_should_be_false_when_user_has_no_authorized_permissions(self):
        sub = str(uuid4())
        self.mock_keycloak.decode_token.return_value = {
            "sub": sub,
            "email": "me@alphalayer.ai",
            "preferred_username": "my_user",
            "scope": "profile email",
        }

        cred, _ = await self.backend.authenticate(self.http_mock)  # type: ignore

        self.assertFalse(cred.has_permission("test-resource"))  # type: ignore
        self.assertFalse(cred.has_permission("test-resource", scope="write"))  # type: ignore
