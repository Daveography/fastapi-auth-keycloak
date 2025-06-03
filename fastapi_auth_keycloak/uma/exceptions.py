from starlette import status
from starlette.exceptions import HTTPException


class UMAAuthorizationRequired(HTTPException):
    def __init__(self, realm: str, as_uri: str, ticket: str) -> None:
        super().__init__(
            status.HTTP_401_UNAUTHORIZED,
            headers={"WWW-Authenticate": f'UMA realm="{realm}", as_uri="{as_uri}", ticket="{ticket}"'},
        )


class UMAAuthorizationServerUnreachable(HTTPException):
    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            headers={"Warning": '199 - "UMA Authorization Server Unreachable"'},
        )
