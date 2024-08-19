# FastAPI Authentication Modules

Provides Starlette/FastAPI Authentication backend modules for these Authentication methods:
- JSON Web Token (JWT)
- Keycloak JWT

# Install
```bash
poetry source add --priority=supplemental alphalayer https://pkgs.dev.azure.com/alphalayerai/Packages/_packaging/Python/pypi/simple/
poetry add --source alphalayer fastapi-auth
```

If using Keycloak:
```bash
poetry add --source alphalayer fastapi-auth[keycloak]
```

## Examples

### Basic JWT

```python
from fastapi import FastAPI, HTTPException, Request, status
from fastapi_auth import PublicKey
from fastapi_auth.jwt import JWTUser, JWTAuthBackend
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

### Keycloak JWT

```python
from fastapi import FastAPI, HTTPException, Request, status
from fastapi_auth.keycloak import KeycloakUser, KeycloakAuthBackend
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

#### Keycloak Authorization / UMA
This module supports using Keycloak Authorization to secure resources via the returned `KeycloakAuthCredentials` object, provided via `Request.auth`. Any `uma-ticket` token is accepted by default.

You can also enable the `query_uma_authorization` option, which allows the `KeycloakAuthCredentials` to query the Keycloak server on demand to determine if the user is authorized to access the requested resource if the current token is missing authorization information.

```python
from fastapi import FastAPI, HTTPException, Request, status
from fastapi_auth.keycloak import KeycloakUser, KeycloakAuthBackend
from starlette.datastructures import Secret
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware

backend = KeycloakAuthBackend(
    url="https://my-keycloak.com/",
    realm="my-realm",
    client_id="70a82a5a-b671-4acb-9ecf-b5dcce0305e3",
    client_secret=Secret("<client-secret>"),
    audience="my_aud",
    query_uma_authorization=True,
)

app = FastAPI()
app.add_middleware(AuthenticationMiddleware, backend=backend)

@app.get("/user/name")
def get_current_user_identity(request: Request):
    return request.user.display_name

@app.get("/privileged/area")
def get_privileged_data(request: Request):
    if not request.auth.has_permission(resource_name="privileged_data", scope="privileged_data:read"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not authenticated.")

    return {"What privilege!"}
```

FastAPI-Auth also provides a `UMAAuthorized` class that can be used as a FastAPI dependency to authorize requests:

```python
from fastapi import Depends
from fastapi_auth.uma import UMAAuthorized
from typing_extensions import Annotated

@app.post("/privileged/area")
def add_privileged_data(
    authorized: Annotated[UMAAuthorized, Depends(UMAAuthorized("privileged_data", "privileged_data:write"))]
):
    # Request will fail if the user is not authorized, so you can just jump straight into the write logic here.
    # You can also access the user and auth objects from the injected object:
    user_id = authorized.user.identity
    scopes = authorized.auth.scopes
```

## Contributing

This package utilizes [Poetry](https://python-poetry.org) for dependency management and [pre-commit](https://pre-commit.com/) for ensuring code formatting is automatically done and code style checks are performed.

You'll also want to set up and use `pyenv` to manage Python versions. See [Managing Multiple Python Versions With pyenv](https://realpython.com/intro-to-pyenv/) for an introduction to pyenv. Download and install for [Linux & Mac](https://github.com/pyenv/pyenv) or [Windows](https://github.com/pyenv-win/pyenv-win).

```bash
git clone https://github.com/alpha-layer/fastapi-auth.git fastapi-auth
cd fastapi-auth
pyenv update
pyenv install 3.9.13
pyenv local 3.9.13
pip install poetry
poetry install
poetry run pre-commit install
poetry run pre-commit autoupdate
```
