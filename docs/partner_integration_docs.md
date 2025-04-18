# Middleware Integration Guide for Keycloak Token Validation

## Overview

This middleware is designed to integrate with applications to validate user tokens and scopes issued by Keycloak. It ensures that only authorized users can access protected resources based on their roles or permissions. This document will guide you through the process of integrating the middleware into your application.

## Prerequisites

Before integrating the middleware, ensure the following:

- **Python version**: Ensure you are using Python 3.11 or higher.
- **Keycloak Setup**: A Keycloak instance should be running, and client credentials must be configured.
- **Dependencies**: Check the security module repository: https://production.eng.it/gitlab/icos/security/coordination-module/-/tree/main/reverse_proxy_api?ref_type=heads

## Add the Middleware to Your Application

In your FastAPI or any Python application, you need to add the middleware to handle token validation.
Middleware source code: https://production.eng.it/gitlab/icos/security/coordination-module/-/blob/4ea1af4b5f2fb90abca3312d0f92e6986c29a575/reverse_proxy_api/src/middleware.py

Add the middleware in your app's code, check [example](https://production.eng.it/gitlab/icos/security/coordination-module/-/blob/main/reverse_proxy_api/src/app.py?ref_type=heads) 

```python
from .middleware import validate_keycloak
```

```python
APP.middleware("http")(validate_keycloak)
```

**Configuration Options**

You will need keycloak running, for development and testing you can deploy the application and keycloak with docker.
```sh
git clone https://production.eng.it/gitlab/icos/security/coordination-module.git
cd reverse_proxy_api && docker-compose up --build -d
```

Keycloak configuration (example):
```python
KEYCLOAK_SERVER_URL: http://keycloak:8080
KEYCLOAK_CLIENT_ID: coordination
KEYCLOAK_REALM_NAME: icos
KEYCLOAK_CLIENT_SECRET_KEY: Km4OI7UNO1i4iOwQfUBAJ6rW4INSEyFD
KEYCLOAK_RESOURCE_SERVER_ID: Default Resource
KEYCLOAK_AUDIENCE: Default Resource
```

## Testing and evaluate the integration

### Retrieve a token
```sh
curl --location 'http://localhost:8080/realms/icos/protocol/openid-connect/token' --header 'Content-Type: application/x-www-form-urlencoded' --data-urlencode 'grant_type=password' --data-urlencode 'client_id=coordination' --data-urlencode 'username=daniel.nikoloski@xlab.si' --data-urlencode 'password=<password>' --data-urlencode 'client_secret=<client secret key>'
```

### Validate the user permissions / scopes
```sh
curl --header 'Authorization: Bearer <bearer-token>' http://127.0.0.1:8000/wazuh
```

