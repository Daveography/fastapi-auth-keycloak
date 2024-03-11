from pydantic import BaseModel, Field

from .client_access import KeycloakClientAccess


class KeycloakResourceAccess(BaseModel):
    __root__: dict[str, KeycloakClientAccess] = Field(default_factory=dict)

    @property
    def clients(self) -> dict[str, KeycloakClientAccess]:
        return self.__root__

    def has_client(self, client: str) -> bool:
        return client in self.__root__

    def __len__(self):
        return len(self.__root__)

    def __iter__(self):
        return iter(self.__root__)

    def __getitem__(self, item):
        return self.__root__[item]
