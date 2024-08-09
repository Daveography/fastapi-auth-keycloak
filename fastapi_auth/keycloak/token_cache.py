from datetime import datetime, timezone
from functools import partial

from cachetools import TLRUCache
from pydantic import TypeAdapter
from typing_extensions import Any

dt_adapter = TypeAdapter(datetime)


def token_cache_ttu(_key, token: dict[str, Any], _now) -> datetime:
    return dt_adapter.validate_python(token["exp"])


utcnow = partial(datetime.now, tz=timezone.utc)


class TokenCache(TLRUCache[str, dict[str, Any]]):
    """
    Configures a TLRU (Time-aware Least Recently Used) cache for Keycloak tokens. Cached tokens expire according to the
    expiry (`exp` claim) of the token.
    """

    def __init__(self):
        super().__init__(maxsize=100, ttu=token_cache_ttu, timer=utcnow)  # type: ignore
