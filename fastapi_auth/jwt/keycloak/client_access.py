from pydantic import BaseModel


class KeycloakClientAccess(BaseModel):
    roles: list[str]

    def has_role(self, role: str) -> bool:
        return role in self.roles

    def __len__(self):
        return len(self.roles)

    def __iter__(self):
        return iter(self.roles)

    def __getitem__(self, item):
        return self.roles[item]
