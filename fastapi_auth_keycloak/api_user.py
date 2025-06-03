from abc import ABC, abstractmethod

from pydantic import BaseModel, ConfigDict
from starlette.authentication import BaseUser


class APIUser(ABC, BaseUser, BaseModel):
    """
    A base class for FastAPI user objects that are provided by an authentication provider.
    """

    @property
    def is_authenticated(self) -> bool:
        """
        Is the user authenticated? (Should always be true when a user has been provided)

        Returns:
            bool: True if the user is authenticated.
        """
        return True

    @property
    @abstractmethod
    def display_name(self) -> str:
        """
        The display name of the user; this is determined by the subclass.

        Returns:
            str: The display name of the user.
        """
        raise NotImplementedError()

    @property
    @abstractmethod
    def identity(self) -> str:
        """
        A unique identity string for the user as provided by the underlying auth provider.

        Returns:
            str: A string that uniquely identifies this user.
        """
        raise NotImplementedError()

    model_config = ConfigDict(frozen=True)
