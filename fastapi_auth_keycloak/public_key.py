from pydantic import AfterValidator, RootModel
from typing_extensions import Annotated


def _wrap_if_needed(value: str) -> str:
    if "BEGIN PUBLIC KEY" not in value:
        value = f"-----BEGIN PUBLIC KEY-----\n{value}\n-----END PUBLIC KEY-----"
    return value


class PublicKey(RootModel[str]):
    """Wrapper for a public key string. Ensures that the key is in PEM format."""

    root: Annotated[str, AfterValidator(_wrap_if_needed)]

    def encode(self) -> bytes:
        return self.root.encode()

    def __str__(self) -> str:
        return self.root
