import unittest
from unittest.mock import MagicMock
from uuid import uuid4

from fastapi_auth_keycloak import KeycloakAuthCredentials, KeycloakResourcePermission
from fastapi_auth_keycloak.uma import proto


class KeycloakUMAProtocolTests(unittest.TestCase):
    def test_should_implement_uma_resource_permission_protocol(self):
        perm = KeycloakResourcePermission(rsid=uuid4(), rsname="test", scopes=["read", "write"])
        self.assertIsInstance(perm, proto.UMAResourcePermission)

    def test_should_implement_uma_auth_credentials_protocol(self):
        auth = KeycloakAuthCredentials(
            keycloak=MagicMock(),
            token={
                "sub": str(uuid4()),
                "email": "me@daveography.ca",
                "preferred_username": "my_user",
                "scope": "profile email",
            },
        )
        self.assertIsInstance(auth, proto.UMAAuthCredentials)
