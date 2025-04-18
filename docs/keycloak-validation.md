## Development

Run the application in development mode with:
```bash
cd reverse_proxy_api
python3 -m venv venv
source venv/bin/activate
uvicorn src.app:APP --host 0.0.0.0 --port 8000 --reload
```
The application will be served on `localhost:8000` by default.

## Running Keycloak and API app with Docker

To run the keycloak server on a Docker container, please execute the following from the root directory:

```bash
cd reverse_proxy_api && docker-compose up --build -d
```

## Setting up Keycloak

- Create realm
- Create client
- In clients `Authorization`, you will need to create `Resources`, `Scopes`, `Policies` and `Permissions`
    - Learn More here: 
        - [Keycloak Permission Overview](https://www.keycloak.org/docs/latest/authorization_services/index.html#_permission_overview)
        - [Resources, scopes, permissions and policies in Keycloak](https://stackoverflow.com/questions/42186537/resources-scopes-permissions-and-policies-in-keycloak)

## Configure environtment correctly inside the docker-compose.yaml
```yaml
KEYCLOAK_SERVER_URL: http://keycloak:8080
KEYCLOAK_CLIENT_ID: coordination
KEYCLOAK_REALM_NAME: icos
KEYCLOAK_CLIENT_SECRET_KEY: Km4OI7UNO1i4iOwQfUBAJ6rW4INSEyFD
KEYCLOAK_RESOURCE_SERVER_ID: Default Resource
KEYCLOAK_AUDIENCE: Default Resource
```

### Once environment variables are set, restart API app container
```sh
docker-compose up --build -d app
```

## Evaluate the permissions with token

### To retrieve token
```bash
curl --location 'http://localhost:8080/realms/icos/protocol/openid-connect/token' --header 'Content-Type: application/x-www-form-urlencoded' --data-urlencode 'grant_type=password' --data-urlencode 'client_id=coordination' --data-urlencode 'username=daniel.nikoloski@xlab.si' --data-urlencode 'password=<password>' --data-urlencode 'client_secret=<client secret key>'
```
### To validate the users permissions / scopes
```bash
curl --header 'Authorization: Bearer <bearer-token>' http://127.0.0.1:8000/wazuh
```