from starlette.datastructures import Secret


class PublicKeySecret(Secret):
    def __str__(self) -> str:
        return f"-----BEGIN PUBLIC KEY-----\n{self._value}\n-----END PUBLIC KEY-----"
