from starlette.datastructures import Secret


class HMACKey(Secret):
    """
    A wrapper for an HMAC (HS256, HS384, or HS512) key that should not be revealed in tracebacks etc.
    """
