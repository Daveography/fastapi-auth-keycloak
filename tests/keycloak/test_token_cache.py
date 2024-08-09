import time
import unittest
from datetime import datetime, timezone
from uuid import uuid4

from fastapi_auth.keycloak.token_cache import TokenCache


class KeycloakTokenCacheTests(unittest.TestCase):
    def test_should_cache_and_get_token_before_expiry(self):
        cache = TokenCache()
        token = {
            "sid": str(uuid4()),
            "exp": datetime.now(tz=timezone.utc).timestamp() + 2,
        }
        cache[token["sid"]] = token

        self.assertIn(token["sid"], cache)
        self.assertEqual(token, cache[token["sid"]])

    def test_should_not_get_token_after_expiry(self):
        cache = TokenCache()
        token = {
            "sid": str(uuid4()),
            "exp": datetime.now(tz=timezone.utc).timestamp() + 1,
        }
        cache[token["sid"]] = token

        time.sleep(1)

        self.assertNotIn(token["sid"], cache)

    def test_should_not_add_expired_token(self):
        cache = TokenCache()
        token = {
            "sid": str(uuid4()),
            "exp": datetime.now(tz=timezone.utc).timestamp() - 1,
        }
        cache[token["sid"]] = token

        self.assertNotIn(token["sid"], cache)

    def test_should_not_find_token_not_added(self):
        cache = TokenCache()
        token = {
            "sid": str(uuid4()),
            "exp": datetime.now(tz=timezone.utc).timestamp() + 2,
        }
        cache[token["sid"]] = token

        self.assertNotIn(str(uuid4()), cache)
