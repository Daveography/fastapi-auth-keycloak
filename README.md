# Keycloak Authentication Backend for FastAPI

Provides [Starlette](https://www.starlette.io/)/[FastAPI](https://fastapi.tiangolo.com/) Authentication backend modules for [Keycloak](https://www.keycloak.org/).


## Install

```bash
pip install fastapi-auth-keycloak
```


## Examples

```python
from fastapi import FastAPI, HTTPException, Request, status
from fastapi_auth_keycloak import KeycloakUser, KeycloakAuthBackend
from starlette.datastructures import Secret
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware

backend = KeycloakAuthBackend(
    url="https://my-keycloak.com/",
    realm="my-realm",
    client_id="70a82a5a-b671-4acb-9ecf-b5dcce0305e3",
    client_secret=Secret("<client-secret>"),
    audience="my_aud", # This can be a list of accepted audiences, or an empty list for any
    # authentication_required=False, <- Set this to allow unauthenticated requests; defaults to `True`
)

app = FastAPI()
app.add_middleware(AuthenticationMiddleware, backend=backend)

@app.get("/user/name")
def get_current_user_identity(request: Request):
    return request.user.display_name

@app.get("/privileged/area")
def get_privileged_data(request: Request):
    if not request.auth.has_role(client="alpha-app", role="super-user"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not authenticated.")

    return {"OMG TOP SECRET"}

@app.get("/no-homers")
def get_no_homers_data(request: Request):
    if request.user.groups is not None and "/homers/simpson" in request.user.groups:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not authenticated.")

    return {"Welcome Homer Glumplich!"}
```

### UMA Authorization
This module supports using [User-Managed Access (UMA) 2.0 Grant for OAuth 2.0 Authorization](https://docs.kantarainitiative.org/uma/wg/oauth-uma-grant-2.0-09.html) to authorize access to resources via the `KeycloakAuthCredentials` object, provided via `Request.auth`.

If the user's JWT does not currently authorize them to access the specified resource and scope(s) if provided, the `authorize` method will throw an HTTP 401 response with a `WWW-Authenticate` header to indicate to the client that they should obtain a UMA 2.0-compliant Requesting Party Token (RPT, of type `urn:ietf:params:oauth:grant-type:uma-ticket`) to be authorized to access the resource. See the [specification](https://docs.kantarainitiative.org/uma/wg/oauth-uma-grant-2.0-09.html) for details.

```python
from fastapi import FastAPI, HTTPException, Request, status
from fastapi_auth_keycloak import KeycloakUser, KeycloakAuthBackend
from starlette.datastructures import Secret
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware

backend = KeycloakAuthBackend(
    url="https://my-keycloak.com/",
    realm="my-realm",
    client_id="70a82a5a-b671-4acb-9ecf-b5dcce0305e3",
    client_secret=Secret("<client-secret>"),
    audience="my_aud",
)

app = FastAPI()
app.add_middleware(AuthenticationMiddleware, backend=backend)

@app.get("/user/name")
def get_current_user_identity(request: Request):
    return request.user.display_name

@app.get("/privileged/area")
def get_privileged_data(request: Request):
    # Assert user is authorized
    request.auth.authorize(resource_name="privileged_data", scope="privileged_data:read")
    return {"What privilege!"}
```

You can also authorize by a specific Resource Id if you have it:

```python
@app.get("/privileged/area/{id}")
def get_privileged_data(request: Request, id: str):
    request.auth.authorize_by_id(resource_id=id, scope="privileged_data:read")
    return {f"Looks like you are allowed to see area {id}!"}
```

FastAPI-Auth also provides a `UMAAuthorize` class that can be used as a FastAPI dependency to authorize endpoint resources:

```python
from fastapi import Depends
from fastapi_auth_keycloak.uma import UMAAuthorized
from typing_extensions import Annotated

@app.post("/privileged/area")
def add_privileged_data(
    authorized: Annotated[UMAAuthorize, Depends(UMAAuthorize("privileged_data", "privileged_data:write"))]
):
    # The dependency has already asserted the user is authorized, so you can jump straight to your endpoint logic.
    # You can also access the user and auth objects from the injected object:
    user_id = authorized.user.identity
    scopes = authorized.auth.scopes
```

If you need to check other Keycloak-specific (e.g., not OAuth2 or UMA2 standard) claims, you can instead use the `KeycloakUMAAuthorize` dependency:

```python
from fastapi import Depends
from fastapi_auth_keycloak import KeycloakUMAAuthorized
from typing_extensions import Annotated

@app.post("/privileged/area")
def add_privileged_data(
    authorized: Annotated[KeycloakUMAAuthorized, Depends(KeycloakUMAAuthorized("privileged_data", "privileged_data:write"))]
):
    # Also check if a user has a specific client role:
    if authorized.auth.has_role(client="my_realm_client", role="my_client_role"):
        # Do other stuff
        ...
```

### Basic JWT

This library also provides an Auth Backend for barebones JWTs:

```python
from fastapi import FastAPI, HTTPException, Request, status
from fastapi_auth_keycloak import PublicKey
from fastapi_auth_keycloak.jwt import JWTUser, JWTAuthBackend
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware

backend = JWTAuthBackend(
    algorithms=["RS256"],
    audience="my_aud", # This can be a list of accepted audiences, or an empty list for any
    key=PublicKey("<public key>"),
    # authentication_required=False, <- Set this to allow unauthenticated requests; defaults to `True`
)

app = FastAPI()
app.add_middleware(AuthenticationMiddleware, backend=backend)

@app.get("/user/identity")
def get_current_user_identity(request: Request):
    return request.user.identity
```

## Contributing

This package utilizes [Poetry](https://python-poetry.org) for dependency management and [pre-commit](https://pre-commit.com/) for ensuring code formatting is automatically done and code style checks are performed.

```bash
git clone https://github.com/Daveography/fastapi-auth-keycloak.git fastapi-auth-keycloak
cd fastapi-auth-keycloak
pip install poetry
poetry install
poetry run pre-commit install
poetry run pre-commit autoupdate
```
