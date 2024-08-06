import unittest

from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.middleware.authentication import AuthenticationMiddleware

from fastapi_auth import PublicKey
from fastapi_auth.jwt import JWTAuthBackend

# Key and JWT generated from https://jwt.io/
rs_public_key = PublicKey(
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo"
    "4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u"
    "+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh"
    "kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ"
    "0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg"
    "cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc"
    "mwIDAQAB"
)
jwt = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZSwiYXVkIjoiYWxwaGFsYXllciIsImVtYWlsIjoiZGF2ZUBhbHBoYWxheWVyL"
    "mFpIiwiaWF0IjoxNTE2MjM5MDIyLCJuYW1lIjoiRGF2ZSBTdXRoZXJsYW5kIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiRGF2ZSIsInNpZCI6IjIzNjh"
    "kY2YyLWUzYWYtNDY4ZC05YmY2LTVmMTJiYWViNTQ0MiIsInN1YiI6IjhkZDg4MWRhLTg1MjItNGYzMy05Njc0LTI5YTJjMzM0NzRmMCJ9.Eu2XQFTv"
    "X8QLHQEVVrtyf9mdIaRTrUVRnMGS8AjJRAaovwWt1sMtnLtHcAH8zMgJSC6ykJpoHa1W-SlrBHGjzkzTLAIZZIdbF8NDemDzumNwrwrgl7mKuVYkX8"
    "MIHy-Z5sRjvVjoCnxsdKiY9XJ5YB50b0H6dkpaecXVseM1qv08WMhCgzlYLKPOK1wYONLXqdOHTXjxYFyPuaPyYVkZLpmlhB7gUHdDD4odmI7xrKsd"
    "ENdOzq8Xp5F18f_x8qsB85wTaD5PwdTo7f7R6xn-9e_U8VKLI7zC9VKfyuOIdjdyw0dqMXMLBS9Jq2J75ECLGNAskgML6Zsw8lhjN1GXIw"
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
    algorithms=["RS256"],
    audience=["alphalayer", "api"],
    public_key=rs_public_key,
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
