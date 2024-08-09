import time
import unittest
from datetime import datetime, timezone
from unittest import mock

from fastapi import FastAPI
from fastapi.testclient import TestClient
from jwcrypto import jwk, jwt
from starlette.middleware.authentication import AuthenticationMiddleware
from typing_extensions import Any

from fastapi_auth import KeycloakAuthBackend

# Keys generated from https://jwt.io/
rs_public_key = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
mwIDAQAB
-----END PUBLIC KEY-----
"""

rs_private_key = """
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKj
MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
qgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulg
p2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlR
ZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwi
VuNd9tybAgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskV
laAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2jx4GDjI1ZTXg++0AMJ8
sJ74pWzVDOfmCEQ/7wXs3+cbnXhKriO8Z036q92Qc1+N87SI38nkGa0ABH9CN83H
mQqt4fB7UdHzuIRe/me2PGhIq5ZBzj6h3BpoPGzEP+x3l9YmK8t/1cN0pqI+dQwY
dgfGjackLu/2qH80MCF7IyQaseZUOJyKrCLtSD/Iixv/hzDEUPfOCjFDgTpzf3cw
ta8+oE4wHCo1iI1/4TlPkwmXx4qSXtmw4aQPz7IDQvECgYEA8KNThCO2gsC2I9PQ
DM/8Cw0O983WCDY+oi+7JPiNAJwv5DYBqEZB1QYdj06YD16XlC/HAZMsMku1na2T
N0driwenQQWzoev3g2S7gRDoS/FCJSI3jJ+kjgtaA7Qmzlgk1TxODN+G1H91HW7t
0l7VnL27IWyYo2qRRK3jzxqUiPUCgYEAx0oQs2reBQGMVZnApD1jeq7n4MvNLcPv
t8b/eU9iUv6Y4Mj0Suo/AU8lYZXm8ubbqAlwz2VSVunD2tOplHyMUrtCtObAfVDU
AhCndKaA9gApgfb3xw1IKbuQ1u4IF1FJl3VtumfQn//LiH1B3rXhcdyo3/vIttEk
48RakUKClU8CgYEAzV7W3COOlDDcQd935DdtKBFRAPRPAlspQUnzMi5eSHMD/ISL
DY5IiQHbIH83D4bvXq0X7qQoSBSNP7Dvv3HYuqMhf0DaegrlBuJllFVVq9qPVRnK
xt1Il2HgxOBvbhOT+9in1BzA+YJ99UzC85O0Qz06A+CmtHEy4aZ2kj5hHjECgYEA
mNS4+A8Fkss8Js1RieK2LniBxMgmYml3pfVLKGnzmng7H2+cwPLhPIzIuwytXywh
2bzbsYEfYx3EoEVgMEpPhoarQnYPukrJO4gwE2o5Te6T5mJSZGlQJQj9q4ZB2Dfz
et6INsK0oG8XVGXSpQvQh3RUYekCZQkBBFcpqWpbIEsCgYAnM3DQf3FJoSnXaMhr
VBIovic5l0xFkEHskAjFTevO86Fsz1C2aSeRKSqGFoOQ0tmJzBEs1R6KqnHInicD
TQrKhArgLXX4v3CddjfTRJkFWDbE/CkvKZNOrcf1nhaGCPspRJj2KUkj1Fhl9Cnc
dn/RsYEONbwQSjIfMPkvxF+8HQ==
-----END PRIVATE KEY-----
"""


class KeycloakUMATicketIntegrationTests(unittest.IsolatedAsyncioTestCase):
    @mock.patch("fastapi_auth.keycloak.backend.KeycloakOpenID.public_key")
    @mock.patch("fastapi_auth.keycloak.backend.KeycloakOpenID.well_known")
    async def asyncSetUp(self, mock_well_known: mock.MagicMock, mock_public_key: mock.MagicMock):
        mock_well_known.return_value = {"id_token_signing_alg_values_supported": ["RS256"]}
        mock_public_key.return_value = rs_public_key
        backend = KeycloakAuthBackend(
            url=mock.MagicMock(),
            realm=mock.MagicMock(),
            client_id=mock.MagicMock(),
            client_secret=mock.MagicMock(),
            audience=["alphalayer", "api"],
            uma_authorization="ticket",
        )

        app = FastAPI()
        app.add_middleware(AuthenticationMiddleware, backend=backend)

        @app.get("/")
        async def root():
            return {"message": "Hello World"}

        self.client = TestClient(app, raise_server_exceptions=False)

    @mock.patch("fastapi_auth.keycloak.backend.KeycloakOpenID.a_uma_permissions")
    async def test_should_obtain_uma_ticket_if_no_auth_permissions(self, mock_uma_permissions: mock.AsyncMock):
        claims: dict[str, Any] = {
            "aud": "alphalayer",
            "email": "dave@alphalayer.ai",
            "name": "Dave Sutherland",
            "preferred_username": "Dave",
            "sid": "2368dcf2-e3af-468d-9bf6-5f12baeb5442",
            "sub": "8dd881da-8522-4f33-9674-29a2c33474f0",
            "scope": "profile email",
            "exp": datetime.now(tz=timezone.utc).timestamp() + 300,
        }

        uma_claims = claims.copy()
        uma_claims["authorization"] = {
            "permissions": [
                {
                    "rsid": "83800223-136c-4148-9b29-c963dedc6375",
                    "rsname": "accounts",
                    "scopes": ["accounts:register", "accounts:read"],
                },
            ]
        }
        mock_uma_permissions.return_value = uma_claims

        token = self._jwt(claims)
        response = self.client.get("/", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(200, response.status_code)
        self.assertEqual({"message": "Hello World"}, response.json())
        mock_uma_permissions.assert_called_once()

    @mock.patch("fastapi_auth.keycloak.backend.KeycloakOpenID.a_uma_permissions")
    async def test_should_not_obtain_uma_ticket_if_auth_permissions_in_token(
        self, mock_uma_permissions: mock.AsyncMock
    ):
        claims: dict[str, Any] = {
            "aud": "alphalayer",
            "email": "dave@alphalayer.ai",
            "name": "Dave Sutherland",
            "preferred_username": "Dave",
            "sid": "2368dcf2-e3af-468d-9bf6-5f12baeb5442",
            "sub": "8dd881da-8522-4f33-9674-29a2c33474f0",
            "scope": "profile email",
            "exp": datetime.now(tz=timezone.utc).timestamp() + 300,
            "authorization": {
                "permissions": [
                    {
                        "rsid": "83800223-136c-4148-9b29-c963dedc6375",
                        "rsname": "accounts",
                        "scopes": ["accounts:register", "accounts:read"],
                    },
                ]
            },
        }

        token = self._jwt(claims)
        response = self.client.get("/", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(200, response.status_code)
        self.assertEqual({"message": "Hello World"}, response.json())
        mock_uma_permissions.assert_not_called()

    @mock.patch("fastapi_auth.keycloak.backend.KeycloakOpenID.a_uma_permissions")
    async def test_should_use_cached_uma_ticket_while_valid(self, mock_uma_permissions: mock.AsyncMock):
        claims: dict[str, Any] = {
            "aud": "alphalayer",
            "email": "dave@alphalayer.ai",
            "name": "Dave Sutherland",
            "preferred_username": "Dave",
            "sid": "2368dcf2-e3af-468d-9bf6-5f12baeb5442",
            "sub": "8dd881da-8522-4f33-9674-29a2c33474f0",
            "scope": "profile email",
            "exp": datetime.now(tz=timezone.utc).timestamp() + 300,
        }

        uma_claims = claims.copy()
        uma_claims["authorization"] = {
            "permissions": [
                {
                    "rsid": "83800223-136c-4148-9b29-c963dedc6375",
                    "rsname": "accounts",
                    "scopes": ["accounts:register", "accounts:read"],
                },
            ]
        }
        mock_uma_permissions.return_value = uma_claims

        token = self._jwt(claims)
        response = self.client.get("/", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(200, response.status_code)
        self.assertEqual({"message": "Hello World"}, response.json())

        response = self.client.get("/", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(200, response.status_code)

        mock_uma_permissions.assert_called_once()

    @mock.patch("fastapi_auth.keycloak.backend.KeycloakOpenID.a_uma_permissions")
    async def test_should_obtain_new_uma_ticket_if_cached_token_expired(self, mock_uma_permissions: mock.AsyncMock):
        claims: dict[str, Any] = {
            "aud": "alphalayer",
            "email": "dave@alphalayer.ai",
            "name": "Dave Sutherland",
            "preferred_username": "Dave",
            "sid": "2368dcf2-e3af-468d-9bf6-5f12baeb5442",
            "sub": "8dd881da-8522-4f33-9674-29a2c33474f0",
            "scope": "profile email",
            "exp": datetime.now(tz=timezone.utc).timestamp() + 1,
        }

        uma_claims = claims.copy()
        uma_claims["authorization"] = {
            "permissions": [
                {
                    "rsid": "83800223-136c-4148-9b29-c963dedc6375",
                    "rsname": "accounts",
                    "scopes": ["accounts:register", "accounts:read"],
                },
            ]
        }
        mock_uma_permissions.return_value = uma_claims

        token = self._jwt(claims)
        response = self.client.get("/", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(200, response.status_code)
        self.assertEqual({"message": "Hello World"}, response.json())

        time.sleep(1)

        response = self.client.get("/", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(200, response.status_code)

        self.assertEqual(2, mock_uma_permissions.call_count)

    def _jwt(self, claims: dict[str, Any]) -> str:
        token = jwt.JWT(header={"alg": "RS256"}, claims=claims)
        token.make_signed_token(jwk.JWK.from_pem(rs_private_key.encode()))
        return token.serialize()
