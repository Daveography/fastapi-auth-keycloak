# FastAPI Authentication Modules

Provides FastAPI backend modules for these Authentication methods:
- JSON Web Token (JWT)
- Keycloak JWT

## Examples

### Raw JWT

```python
from fastapi import FastAPI, HTTPException, Request, status
from fastapi_auth import PublicKeySecret
from fastapi_auth.jwt import JWTUser, JWTAuthBackend
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware

backend = JWTAuthBackend(
    algorithm="RS256",
    audience="my_aud",
    key=PublicKeySecret("<public key>"),
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
from fastapi_auth import PublicKeySecret
from fastapi_auth.jwt.keycloak import KeycloakUser, KeycloakAuthBackend
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware

backend = KeycloakAuthBackend(
    algorithm="RS256",
    audience="my_aud",
    key=PublicKeySecret("<public key>"),
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
