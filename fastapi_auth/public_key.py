from pydantic import AfterValidator, RootModel
from typing_extensions import Annotated


def _wrap_if_needed(value: str) -> str:
    if "BEGIN PUBLIC KEY" not in value:
        value = f"-----BEGIN PUBLIC KEY-----\n{value}\n-----END PUBLIC KEY-----"
    return value


class PublicKey(RootModel[str]):
    root: Annotated[str, AfterValidator(_wrap_if_needed)]

    def __str__(self) -> str:
        return self.root
