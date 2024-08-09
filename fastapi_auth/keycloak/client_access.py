from pydantic import BaseModel, ConfigDict, Field


class KeycloakClientAccess(BaseModel):
    """
    A representation of the role access that a user has via a specific client in Keycloak.
    """

    roles: list[str] = Field(..., description="A list of role names that the user has for this client")

    def has_role(self, role: str) -> bool:
        """
        Does a user have this role in this client?

        Args:
            role (str): The name of the role to check for.

        Returns:
            bool: True if user has the specified role in this client.
        """

        return role in self.roles

    def __len__(self):
        return len(self.roles)

    def __iter__(self):
        return iter(self.roles)

    def __getitem__(self, item):
        return self.roles[item]

    model_config = ConfigDict(frozen=True)
