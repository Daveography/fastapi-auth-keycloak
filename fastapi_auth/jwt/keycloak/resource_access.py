from pydantic import BaseModel, Field

from .client_access import KeycloakClientAccess


class KeycloakResourceAccess(BaseModel):
    """
    A representation of the client role accesses that a Keycloak user has been granted.
    """

    __root__: dict[str, KeycloakClientAccess] = Field(
        default_factory=dict, description="A mapping of client names and the roles that the user has for that client"
    )

    @property
    def clients(self) -> dict[str, KeycloakClientAccess]:
        """
        A mapping of client names to the role access that the user has for that client.

        Returns:
            dict[str, KeycloakClientAccess]: A dictionary of client names and roles for each.
        """
        return self.__root__

    def has_client(self, client: str) -> bool:
        """
        Does the user have role accesses specified for the specified client?

        Args:
            client (str): The name of the client to check.

        Returns:
            bool: True if the user has role accesses for the specified client.
        """

        return client in self.__root__

    def __len__(self):
        return len(self.__root__)

    def __iter__(self):
        return iter(self.__root__)

    def __getitem__(self, item):
        return self.__root__[item]
