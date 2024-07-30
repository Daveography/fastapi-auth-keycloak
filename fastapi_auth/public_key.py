from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes


class PublicKey:
    def __init__(self, key: str) -> None:
        pem = self._wrap_if_needed(key)
        self.__key = serialization.load_pem_public_key(pem.encode())

    @property
    def key(self) -> PublicKeyTypes:
        return self.__key

    def _wrap_if_needed(self, value: str) -> str:
        if "BEGIN PUBLIC KEY" not in value:
            value = f"-----BEGIN PUBLIC KEY-----\n{value}\n-----END PUBLIC KEY-----"
        return value

    def __str__(self) -> str:
        return self.key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
