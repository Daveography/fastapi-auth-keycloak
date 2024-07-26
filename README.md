# FastAPI Authentication Modules

Provides FastAPI backend modules for these Authentication methods:
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
    audience="my_aud",
    key=PublicKey("<public key>"),
)

app = FastAPI()
app.add_middleware(AuthenticationMiddleware, backend=backend)

@app.get("/user/identity")
def get_current_user_identity(request: Request):
    return request.user.identity
```

#### If JWTs signed using HMAC (i.e., HS256, HS384, HS512)
```python
from fastapi_auth import HMACKey

backend = JWTAuthBackend(
    algorithms=["RS256"],
    audience="my_aud",
    key=HMACKey("<private HMAC shared key>"),
)

```

### Keycloak JWT

```python
from fastapi import FastAPI, HTTPException, Request, status
from fastapi_auth.jwt.keycloak import KeycloakUser, KeycloakAuthBackend
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
    if not user.has_role(client="alpha-app", role="super-user"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not authenticated.")

    return {"OMG TOP SECRET"}

@app.get("/no-homers")
def get_no_homers_data(request: Request):
    if user.groups is not None and "/homers/simpson" in user.groups:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not authenticated.")

    return {"Welcome Homer Glumplich!"}
```


#### If JWTs signed using HMAC (i.e., HS256, HS384, HS512)
```python
from fastapi_auth import HMACKey

backend = KeycloakAuthBackend(
    url="https://my-keycloak.com/",
    realm="my-realm",
    client_id="70a82a5a-b671-4acb-9ecf-b5dcce0305e3",
    client_secret=Secret("<client-secret>"),
    audience="my_aud",
    hmac_key=HMACKey("<private HMAC shared key>"),
)

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
