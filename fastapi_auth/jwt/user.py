from pydantic import Field

from ..user import APIUser


class JWTUser(APIUser):
    """
    A user that has been provided via a JSON Web Token (JWT).

    Provides only the standard `sub` claim, but maps it to the `identity` and `display_name` properties.

    *NOTE*: This is mostly meant to be a base class for more specific auth providers that provide JWT tokens, such as
    Keycloak. It is not meant to be used directly in most cases.
    """

    sub: str = Field(..., description="The subject of the JWT, which is a unique identifier for the user")

    @property
    def display_name(self) -> str:
        """
        The display name for this user; this is the same as the `sub` claim by default.

        Returns:
            str: The display name for this user
        """
        return self.sub

    @property
    def identity(self) -> str:
        """
        A unique identity string for the user as provided by the underlying auth provider; this is the same as the
        `sub` claim by default.

        Returns:
            str: _description_
        """
        return self.sub
