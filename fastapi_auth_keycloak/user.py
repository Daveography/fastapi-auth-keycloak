from typing import Optional

from pydantic import UUID4, EmailStr, Field

from .api_user import APIUser


class KeycloakUser(APIUser):
    """
    Represents a user provided by Keycloak via a JSON Web Token (JWT).
    """

    id: UUID4 = Field(..., alias="sub", description="The unique identifier for the user")
    email: EmailStr = Field(..., description="The email address for the user")
    preferred_username: str = Field(..., description="The preferred username for the user")
    name: Optional[str] = Field(default=None, description="The full name of the user")
    given_name: Optional[str] = Field(default=None, description="The first name of the user")
    family_name: Optional[str] = Field(default=None, description="The last name of the user")
    groups: Optional[list[str]] = Field(
        default=None,
        description=(
            "A list of group names the user is a member of; only populated if a `Group Membership` mapper to the"
            "`groups` claim has been added to the Keycloak client"
        ),
    )

    @property
    def display_name(self) -> str:
        """
        Returns the full name of the user if it is provided, otherwise the preferred username specified in Keycloak.

        Returns:
            str: A display name for the user
        """

        return self.name if self.name is not None else self.preferred_username

    @property
    def identity(self) -> str:
        """
        A unique identifier string for the user; this is the user's ID (UUID) from Keycloak.

        Returns:
            str: A string representation of the user's ID
        """

        return str(self.id)
