import unittest
from unittest import mock
from uuid import uuid4

from starlette.datastructures import Headers
from starlette.requests import HTTPConnection

from fastapi_auth import HMACKey, PublicKey
from fastapi_auth.jwt.keycloak import KeycloakAuthBackend, KeycloakUser


class KeycloakAuthBackendTests(unittest.IsolatedAsyncioTestCase):
    @mock.patch("fastapi_auth.jwt.backend.jwt")
    async def test_should_create_keycloak_user(self, mock_jwt: mock.MagicMock):
        with mock.patch("fastapi_auth.jwt.keycloak.backend.KeycloakOpenID") as mock_keycloak:
            mock_keycloak_client = mock_keycloak.return_value
            mock_keycloak_client.public_key.return_value = "public_key"
            self.backend = KeycloakAuthBackend(
                url=mock.MagicMock(),
                realm=mock.MagicMock(),
                client_id=mock.MagicMock(),
                client_secret=mock.MagicMock(),
                audience=mock.MagicMock(),
            )

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

    async def test_should_get_algorithms_from_keycloak_well_known(self):
        with mock.patch("fastapi_auth.jwt.keycloak.backend.KeycloakOpenID") as mock_keycloak:
            mock_keycloak_client = mock_keycloak.return_value
            mock_keycloak_client.public_key.return_value = "public_key"
            mock_keycloak_client.well_known.return_value = {"id_token_signing_alg_values_supported": ["RS256"]}
            self.backend = KeycloakAuthBackend(
                url=mock.MagicMock(),
                realm=mock.MagicMock(),
                client_id=mock.MagicMock(),
                client_secret=mock.MagicMock(),
                audience=mock.MagicMock(),
            )

        mock_keycloak_client.well_known.assert_called_once()
        self.assertListEqual(["RS256"], self.backend._algorithms)

    async def test_should_get_public_key_from_keycloak(self):
        with mock.patch("fastapi_auth.jwt.keycloak.backend.KeycloakOpenID") as mock_keycloak:
            mock_keycloak_client = mock_keycloak.return_value
            mock_keycloak_client.public_key.return_value = "public_key"
            self.backend = KeycloakAuthBackend(
                url=mock.MagicMock(),
                realm=mock.MagicMock(),
                client_id=mock.MagicMock(),
                client_secret=mock.MagicMock(),
                audience=mock.MagicMock(),
            )

        mock_keycloak_client.public_key.assert_called_once()
        self.assertIsInstance(self.backend._key, PublicKey)
        self.assertEqual("-----BEGIN PUBLIC KEY-----\npublic_key\n-----END PUBLIC KEY-----", str(self.backend._key))

    async def test_should_use_hmac_key_if_provided(self):
        with mock.patch("fastapi_auth.jwt.keycloak.backend.KeycloakOpenID") as mock_keycloak:
            mock_keycloak_client = mock_keycloak.return_value
            mock_keycloak_client.public_key.return_value = "public_key"
            self.backend = KeycloakAuthBackend(
                url=mock.MagicMock(),
                realm=mock.MagicMock(),
                client_id=mock.MagicMock(),
                client_secret=mock.MagicMock(),
                audience=mock.MagicMock(),
                hmac_key=HMACKey("hmac_key"),
            )

        mock_keycloak_client.public_key.assert_not_called()
        self.assertIsInstance(self.backend._key, HMACKey)
        self.assertEqual("hmac_key", str(self.backend._key))
