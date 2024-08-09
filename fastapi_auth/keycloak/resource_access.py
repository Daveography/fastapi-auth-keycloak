from pydantic import ConfigDict, Field, RootModel

from .client_access import KeycloakClientAccess


class KeycloakResourceAccess(RootModel[dict[str, KeycloakClientAccess]]):
    """
    A representation of the client role accesses that a Keycloak user has been granted.
    """

    root: dict[str, KeycloakClientAccess] = Field(
        default_factory=dict, description="A mapping of client names and the roles that the user has for that client"
    )

    @property
    def clients(self) -> dict[str, KeycloakClientAccess]:
        """
        A mapping of client names to the role access that the user has for that client.

        Returns:
            dict[str, KeycloakClientAccess]: A dictionary of client names and roles for each.
        """
        return self.root

    def has_client(self, client: str) -> bool:
        """
        Does the user have role accesses specified for the specified client?

        Args:
            client (str): The name of the client to check.

        Returns:
            bool: True if the user has role accesses for the specified client.
        """

        return client in self.root

    def __len__(self):
        return len(self.root)

    def __iter__(self):
        return iter(self.root)

    def __getitem__(self, item):
        return self.root[item]

    model_config = ConfigDict(frozen=True)
