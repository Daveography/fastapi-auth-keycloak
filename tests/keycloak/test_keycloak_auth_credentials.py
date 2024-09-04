import unittest
from unittest import mock
from uuid import uuid4

from starlette.datastructures import Headers
from starlette.requests import HTTPConnection

from fastapi_auth.keycloak import KeycloakAuthBackend
from fastapi_auth.uma.exceptions import UMAAuthorizationRequired


class KeycloakAuthCredentialsTests(unittest.IsolatedAsyncioTestCase):
    @mock.patch("fastapi_auth.keycloak.backend.KeycloakOpenIDConnection")
    @mock.patch("fastapi_auth.keycloak.backend.jwk")
    async def asyncSetUp(self, mock_jwk: mock.MagicMock, mock_connection: mock.MagicMock):
        self.mock_connection = mock_connection.return_value
        self.mock_keycloak = self.mock_connection.keycloak_openid
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

        self.assertTrue(cred.has_role("alpha-app", "super-user"))

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

        self.assertFalse(cred.has_role("alpha-app", "super-user"))

    async def test_should_be_false_when_user_has_no_resource_access_roles(self):
        sub = str(uuid4())
        self.mock_keycloak.decode_token.return_value = {
            "sub": sub,
            "email": "me@alphalayer.ai",
            "preferred_username": "my_user",
            "scope": "profile email",
        }

        cred, _ = await self.backend.authenticate(self.http_mock)  # type: ignore

        self.assertFalse(cred.has_role("alpha-app", "super-user"))

    async def test_should_succeed_when_user_has_authorized_permission(self):
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

        await cred.authorize("test-resource")

    async def test_should_succeed_when_user_has_authorized_permission_with_scope(self):
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

        await cred.authorize("test-resource", scope="test")

    async def test_should_succeed_when_user_has_authorized_permission_by_id_with_scope(self):
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

        await cred.authorize_by_id("3105879b-116c-41ad-b415-2aa932fe7789", scope="test")

    @mock.patch("fastapi_auth.keycloak.auth_credentials.KeycloakUMA")
    async def test_should_raise_authorization_required_when_not_authorized_for_resource(self, mock_uma: mock.MagicMock):
        mock_uma.return_value.a_resource_set_list_ids = mock.AsyncMock(
            return_value=["fb5d53ad-c64e-4b73-881e-7e32a8d274ab"]
        )

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

        with mock.patch.object(cred, "_KeycloakAuthCredentials__raise_authorization_required") as mock_raise:
            await cred.authorize("secure-resource")

        mock_raise.assert_called_once()

    @mock.patch("fastapi_auth.keycloak.auth_credentials.KeycloakUMA")
    async def test_should_raise_authorization_required_when_not_authorized_for_resource_scope(
        self, mock_uma: mock.MagicMock
    ):
        mock_uma.return_value.a_resource_set_list_ids = mock.AsyncMock(
            return_value=["3105879b-116c-41ad-b415-2aa932fe7789"]
        )

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

        with mock.patch.object(cred, "_KeycloakAuthCredentials__raise_authorization_required") as mock_raise:
            await cred.authorize("test-resource", scope="write")

        mock_raise.assert_called_once()

    @mock.patch("fastapi_auth.keycloak.auth_credentials.KeycloakUMA")
    async def test_should_raise_authorization_required_when_user_has_no_authorized_permissions(
        self, mock_uma: mock.MagicMock
    ):
        mock_uma.return_value.a_resource_set_list_ids = mock.AsyncMock(
            return_value=["3105879b-116c-41ad-b415-2aa932fe7789"]
        )

        sub = str(uuid4())
        self.mock_keycloak.decode_token.return_value = {
            "sub": sub,
            "email": "me@alphalayer.ai",
            "preferred_username": "my_user",
            "scope": "profile email",
        }

        cred, _ = await self.backend.authenticate(self.http_mock)  # type: ignore

        with mock.patch.object(cred, "_KeycloakAuthCredentials__raise_authorization_required") as mock_raise:
            await cred.authorize("test-resource")

        mock_raise.assert_called_once()

        with mock.patch.object(cred, "_KeycloakAuthCredentials__raise_authorization_required") as mock_raise:
            await cred.authorize("test-resource", scope="write")

        mock_raise.assert_called_once()

    @mock.patch("fastapi_auth.keycloak.auth_credentials.KeycloakUMA")
    async def test_raise_authorization_required_should_have_www_authenticate_header(self, mock_uma: mock.MagicMock):
        mock_uma.return_value.a_resource_set_list_ids = mock.AsyncMock(
            return_value=["3105879b-116c-41ad-b415-2aa932fe7789"]
        )
        mock_uma.return_value.a__fetch_well_known = mock.AsyncMock(
            return_value={"issuer": "http://auth-server", "permission_endpoint": "http://auth-server/permission"}
        )
        mock_uma.return_value.connection.realm_name = "test-realm"

        sub = str(uuid4())
        self.mock_keycloak.decode_token.return_value = {
            "sub": sub,
            "email": "me@alphalayer.ai",
            "preferred_username": "my_user",
            "scope": "profile email",
        }

        cred, _ = await self.backend.authenticate(self.http_mock)  # type: ignore

        with mock.patch.object(cred, "_KeycloakAuthCredentials__get_permission_ticket") as mock_ticket:
            mock_ticket.return_value = "ticket-123"

            with self.assertRaises(UMAAuthorizationRequired) as err:
                await cred.authorize("test-resource")

            self.assertIsNotNone(err.exception.headers)
            self.assertIn("WWW-Authenticate", err.exception.headers)  # type: ignore

            auth_header = err.exception.headers["WWW-Authenticate"]  # type: ignore
            self.assertIsNotNone(auth_header)
            self.assertEqual('UMA realm="test-realm", as_uri="http://auth-server", ticket="ticket-123"', auth_header)
