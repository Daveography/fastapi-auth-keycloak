from starlette.datastructures import Secret


class PublicKeySecret(Secret):
    """
    A wrapper for a public key string that should otherwise not be revealed in tracebacks etc.
    When cast to a string, the value will be wrapped with`-----BEGIN PUBLIC KEY-----` and `-----END PUBLIC KEY-----`
    """

    def __str__(self) -> str:
        return f"-----BEGIN PUBLIC KEY-----\n{self._value}\n-----END PUBLIC KEY-----"
