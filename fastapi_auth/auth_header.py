from pydantic import BaseModel
from starlette.datastructures import Headers
from typing_extensions import Self


class AuthenticationHeader(BaseModel):
    """Helper class to parse an HTTP Authorization header."""

    scheme: str
    credential: str

    @classmethod
    def get_from(cls, headers: Headers) -> Self | None:
        if "Authorization" not in headers:
            return None

        auth_header = headers["Authorization"]
        scheme, _, param = auth_header.partition(" ")
        return cls(scheme=scheme, credential=param)
