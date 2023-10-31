from pydantic import root_validator

from fastapi_auth.user import APIUser


class JWTUser(APIUser):
    sub: str

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def display_name(self) -> str:
        return self.sub

    @property
    def identity(self) -> str:
        return self.sub


class JWTAPIUser(JWTUser):
    @root_validator(pre=True)
    def warn_of_deprecation(cls, values):
        from warnings import warn

        warn(
            "JWTAPIUser is deprecated, use JWTUser instead; JWTAPIUser will be removed in a future release",
            DeprecationWarning,
            2,
        )
        return values
