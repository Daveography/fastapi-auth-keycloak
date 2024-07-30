import unittest
from unittest import mock
from uuid import uuid4

from starlette.datastructures import Headers
from starlette.requests import HTTPConnection

from fastapi_auth import PublicKey
from fastapi_auth.jwt.keycloak import KeycloakAuthBackend


@mock.patch("fastapi_auth.jwt.backend.jwt")
class KeycloakUserTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        with mock.patch("fastapi_auth.jwt.keycloak.backend.KeycloakOpenID") as mock_keycloak:
            mock_keycloak.return_value.public_key.return_value = mock.MagicMock(PublicKey)
            self.backend = KeycloakAuthBackend(
                url=mock.MagicMock(),
                realm=mock.MagicMock(),
                client_id=mock.MagicMock(),
                client_secret=mock.MagicMock(),
                audience=mock.MagicMock(),
            )

        self.http_mock = mock.MagicMock(HTTPConnection)
        self.http_mock.headers = Headers({"Authorization": "Bearer xzy123"})

    async def test_should_set_id_from_jwt_sub_field(self, mock_jwt: mock.MagicMock):
        sub = uuid4()
        mock_jwt.decode.return_value = {
            "sub": str(sub),
            "email": "me@alphalayer.ai",
            "preferred_username": "my_user",
        }

        _, user = await self.backend.authenticate(self.http_mock)  # type: ignore

        self.assertEqual(sub, user.id)  # type: ignore

    async def test_should_set_identity_from_jwt_sub_field(self, mock_jwt: mock.MagicMock):
        sub = str(uuid4())
        mock_jwt.decode.return_value = {
            "sub": sub,
            "email": "me@alphalayer.ai",
            "preferred_username": "my_user",
        }

        _, user = await self.backend.authenticate(self.http_mock)  # type: ignore

        self.assertEqual(sub, user.identity)

    async def test_display_name_should_be_full_name_when_provided(self, mock_jwt: mock.MagicMock):
        sub = str(uuid4())
        mock_jwt.decode.return_value = {
            "sub": sub,
            "email": "me@alphalayer.ai",
            "preferred_username": "my_user",
            "name": "FirstName LastName",
        }

        _, user = await self.backend.authenticate(self.http_mock)  # type: ignore

        self.assertEqual("FirstName LastName", user.display_name)

    async def test_display_name_should_be_preferred_name_when_full_name_not_provided(self, mock_jwt: mock.MagicMock):
        sub = str(uuid4())
        mock_jwt.decode.return_value = {
            "sub": sub,
            "email": "me@alphalayer.ai",
            "preferred_username": "my_user",
        }

        _, user = await self.backend.authenticate(self.http_mock)  # type: ignore

        self.assertEqual("my_user", user.display_name)

    async def test_should_be_true_when_user_has_expected_resource_access_role(self, mock_jwt: mock.MagicMock):
        sub = str(uuid4())
        mock_jwt.decode.return_value = {
            "sub": sub,
            "email": "me@alphalayer.ai",
            "preferred_username": "my_user",
            "resource_access": {"alpha-app": {"roles": ["super-user"]}},
        }

        _, user = await self.backend.authenticate(self.http_mock)  # type: ignore

        self.assertTrue(user.resource_access.has_client("alpha-app"))  # type: ignore
        self.assertTrue(user.resource_access["alpha-app"].has_role("super-user"))  # type: ignore
        self.assertTrue(user.has_role("alpha-app", "super-user"))  # type: ignore

    async def test_should_be_false_when_user_does_not_have_resource_access_role(self, mock_jwt: mock.MagicMock):
        sub = str(uuid4())
        mock_jwt.decode.return_value = {
            "sub": sub,
            "email": "me@alphalayer.ai",
            "preferred_username": "my_user",
            "resource_access": {"alpha-app": {"roles": ["regular-user"]}},
        }

        _, user = await self.backend.authenticate(self.http_mock)  # type: ignore

        self.assertTrue(user.resource_access.has_client("alpha-app"))  # type: ignore
        self.assertFalse(user.resource_access["alpha-app"].has_role("super-user"))  # type: ignore
        self.assertFalse(user.has_role("alpha-app", "super-user"))  # type: ignore

    async def test_should_be_false_when_user_has_no_resource_access_roles(self, mock_jwt: mock.MagicMock):
        sub = str(uuid4())
        mock_jwt.decode.return_value = {
            "sub": sub,
            "email": "me@alphalayer.ai",
            "preferred_username": "my_user",
        }

        _, user = await self.backend.authenticate(self.http_mock)  # type: ignore

        self.assertFalse(user.resource_access.has_client("alpha-app"))  # type: ignore
        self.assertFalse(user.has_role("alpha-app", "super-user"))  # type: ignore

    async def test_should_be_true_when_user_is_in_expected_group(self, mock_jwt: mock.MagicMock):
        sub = str(uuid4())
        mock_jwt.decode.return_value = {
            "sub": sub,
            "email": "me@alphalayer.ai",
            "preferred_username": "my_user",
            "groups": ["/alpha-app/administrators"],
        }

        _, user = await self.backend.authenticate(self.http_mock)  # type: ignore

        self.assertIsNotNone(user.groups)  # type: ignore
        self.assertTrue("/alpha-app/administrators" in user.groups)  # type: ignore

    async def test_should_be_false_when_user_is_not_in_group(self, mock_jwt: mock.MagicMock):
        sub = str(uuid4())
        mock_jwt.decode.return_value = {
            "sub": sub,
            "email": "me@alphalayer.ai",
            "preferred_username": "my_user",
            "groups": ["/alpha-app/users"],
        }

        _, user = await self.backend.authenticate(self.http_mock)  # type: ignore

        self.assertIsNotNone(user.groups)  # type: ignore
        self.assertFalse("/alpha-app/administrators" in user.groups)  # type: ignore

    async def test_should_be_none_groups_are_not_provided(self, mock_jwt: mock.MagicMock):
        sub = str(uuid4())
        mock_jwt.decode.return_value = {
            "sub": sub,
            "email": "me@alphalayer.ai",
            "preferred_username": "my_user",
        }

        _, user = await self.backend.authenticate(self.http_mock)  # type: ignore

        self.assertIsNone(user.groups)  # type: ignore

    async def test_should_be_true_when_user_has_authorized_permission(self, mock_jwt: mock.MagicMock):
        sub = str(uuid4())
        mock_jwt.decode.return_value = {
            "sub": sub,
            "email": "me@alphalayer.ai",
            "preferred_username": "my_user",
            "authorization": {
                "permissions": [
                    {"rsid": "3105879b-116c-41ad-b415-2aa932fe7789", "rsname": "test-resource", "scopes": ["test"]}
                ]
            },
        }

        _, user = await self.backend.authenticate(self.http_mock)  # type: ignore

        self.assertTrue(user.has_permission("test-resource"))  # type: ignore

    async def test_should_be_false_when_user_does_not_have_authorized_permission(self, mock_jwt: mock.MagicMock):
        sub = str(uuid4())
        mock_jwt.decode.return_value = {
            "sub": sub,
            "email": "me@alphalayer.ai",
            "preferred_username": "my_user",
            "authorization": {
                "permissions": [
                    {"rsid": "3105879b-116c-41ad-b415-2aa932fe7789", "rsname": "test-resource", "scopes": ["test"]}
                ]
            },
        }

        _, user = await self.backend.authenticate(self.http_mock)  # type: ignore

        self.assertFalse(user.has_permission("secure-resource"))  # type: ignore

    async def test_should_be_true_when_user_has_authorized_permission_with_scope(self, mock_jwt: mock.MagicMock):
        sub = str(uuid4())
        mock_jwt.decode.return_value = {
            "sub": sub,
            "email": "me@alphalayer.ai",
            "preferred_username": "my_user",
            "authorization": {
                "permissions": [
                    {"rsid": "3105879b-116c-41ad-b415-2aa932fe7789", "rsname": "test-resource", "scopes": ["test"]}
                ]
            },
        }

        _, user = await self.backend.authenticate(self.http_mock)  # type: ignore

        self.assertTrue(user.has_permission("test-resource", scope="test"))  # type: ignore

    async def test_should_be_false_when_user_does_not_have_authorized_permission_for_scope(
        self, mock_jwt: mock.MagicMock
    ):
        sub = str(uuid4())
        mock_jwt.decode.return_value = {
            "sub": sub,
            "email": "me@alphalayer.ai",
            "preferred_username": "my_user",
            "authorization": {
                "permissions": [
                    {"rsid": "3105879b-116c-41ad-b415-2aa932fe7789", "rsname": "test-resource", "scopes": ["test"]}
                ]
            },
        }

        _, user = await self.backend.authenticate(self.http_mock)  # type: ignore

        self.assertFalse(user.has_permission("test-resource", scope="write"))  # type: ignore

    async def test_should_be_false_when_user_has_no_authorized_permissions(self, mock_jwt: mock.MagicMock):
        sub = str(uuid4())
        mock_jwt.decode.return_value = {
            "sub": sub,
            "email": "me@alphalayer.ai",
            "preferred_username": "my_user",
        }

        _, user = await self.backend.authenticate(self.http_mock)  # type: ignore

        self.assertFalse(user.has_permission("test-resource"))  # type: ignore
        self.assertFalse(user.has_permission("test-resource", scope="write"))  # type: ignore
