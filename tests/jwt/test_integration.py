import unittest

from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.middleware.authentication import AuthenticationMiddleware

from fastapi_auth import PublicKeySecret
from fastapi_auth.jwt import JWTAPIUser, JWTAuthBackend

# Key and JWT generated from https://jwt.io/
rs_public_key = PublicKeySecret(
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo"
    "4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u"
    "+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh"
    "kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ"
    "0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg"
    "cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc"
    "mwIDAQAB"
)
jwt = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkRhdmUgU3V0aGVybGFuZCIsImFkbWluIjp0cnVlL"
    "CJpYXQiOjE1MTYyMzkwMjIsImF1ZCI6ImFscGhhbGF5ZXIiLCJzaWQiOiIyMzY4ZGNmMi1lM2FmLTQ2OGQtOWJmNi01ZjEyYmFlYjU0NDIiLCJwcmV"
    "mZXJyZWRfdXNlcm5hbWUiOiJEYXZlIiwiZW1haWwiOiJkYXZlQGFscGhhbGF5ZXIuYWkifQ.jkukL3hs8ffFG1Luiz0q8oJkCf99hoPVOt9ZzQ9CKf"
    "6Xgia7gN2enQviHtJ9BCeqhxyX59xyAzN2e1pA7HK6OLkE2MJ1rwLZtCxYFh9dOXlBXnxHQ-ug0QoWqXfEjNd3svBLxvC6JJ4prVVKl28qE_J_RrwH"
    "QfsOomzf0GLDbuT5vAQoP5eXn3R9oXy64k9nC2uGKYVrI3cgMvgNv6FAaw3v-JprF1ByhX9vH70_eA_wnd8iqbWUt5LPBd4kTB05evLNAm3MB4pxPf"
    "WNLxtAg8XJ81EBNcaTMK_Qf5RMmjMFwiwxLGfpSLO3TgacI_2PvNHQFk1wf8fbTnLtms4SsQ"
)
invalid_jwt = (  # Generated with a different key pair
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkRhdmUgU3V0aGVybGFuZCIsImFkbWluIjp0cnVlL"
    "CJpYXQiOjE1MTYyMzkwMjIsImF1ZCI6ImFscGhhbGF5ZXIiLCJlbWFpbCI6ImRhdmVAYWxwaGFsYXllci5haSIsInByZWZlcnJlZF91c2VybmFtZSI"
    "6IkRhdmUiLCJzaWQiOiIyMzY4ZGNmMi1lM2FmLTQ2OGQtOWJmNi01ZjEyYmFlYjU0NDIifQ.m773HgfXRulF9AV9PxqYoRjOPvq1oNG-953y2NTFxG"
    "k_-_g0Ln8XlVfVxC-eOyK39hGm6J_gTEzBYrwEvE2SZhc3ys0urYVP_hfkE6dSZdUzxZPu71_pCA2_LjxAzaPTCFa2speqUcQ1vEin5pvTL1C8xMEW"
    "Aw-lSFV0NMJEZsrb-UkkC5jlRKDiQMvRRGpq6LVWzq9qm4QAI05ty6duF3ieJhpkYyafHQ6oVHYZOt6WdhV8QEZU-8NEXkUMd0ntEOLunhtL2J0fTF"
    "0swgvHggd6YAYV5n6dxSLJ2VSrJs0vA5RfYthzkHTVU3_npQb_xb6VwzZNkZ6lqQV8jYxIxPpCqvdTRMbX2muoZ7iVlceEZbrQXjaA5-ym9RMWTfMs"
    "7oO4oWXlroghaxMMy7M5uukYOhA7TGoWfNHTeThaq607t7rHNk-GMS5ow6Qt5nMxk54ou4CupyLksfR8m_3j1rNeKCI1wx1aOQuyY25nMDW69U1rGa"
    "JjJA5HI5H62_ODts80hBsiSL-B92Id01NAMhq53YoEJMnyGSZPo94_LGsd_rMvuC34CAAN2dsn580HEr3KpDOFDm-8mo--ZNJ8EIieI_TrMJnvc2un"
    "jtaE9GPGHGi_pgaZRPfBckf5mGQruyHVmS33dxXwg4mIxSHCJ_EWTo01g2scE4dzn64yogo"
)

backend = JWTAuthBackend(
    algorithm="RS256",
    audience="alphalayer",
    key=rs_public_key,
    user_factory=JWTAPIUser.parse_obj,
)

app = FastAPI()
app.add_middleware(AuthenticationMiddleware, backend=backend)


@app.get("/")
async def root():
    return {"message": "Hello World"}


client = TestClient(app, raise_server_exceptions=False)


class IntegrationTests(unittest.TestCase):
    def test_should_succeed_with_valid_token(self):
        response = client.get("/", headers={"Authorization": f"Bearer {jwt}"})
        self.assertEqual(200, response.status_code)
        self.assertEqual({"message": "Hello World"}, response.json())

    def test_should_fail_without_token(self):
        response = client.get("/me")
        self.assertEqual(400, response.status_code)
        self.assertEqual("Not authenticated", response.text)

    def test_should_fail_with_invalid_token(self):
        response = client.get("/", headers={"Authorization": f"Bearer {invalid_jwt}"})
        self.assertEqual(400, response.status_code)
        self.assertEqual("Signature verification failed", response.text)
