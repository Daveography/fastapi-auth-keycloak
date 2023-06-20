from abc import ABC, abstractmethod

from pydantic import BaseModel
from starlette.authentication import BaseUser


class APIUser(ABC, BaseUser, BaseModel):
    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    @abstractmethod
    def display_name(self) -> str:
        raise NotImplementedError()

    @property
    @abstractmethod
    def identity(self) -> str:
        raise NotImplementedError()

    class Config:
        allow_mutation = False
