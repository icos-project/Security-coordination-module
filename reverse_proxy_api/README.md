# Reverse proxy api

Get keycloak token:
```sh
curl --location 'https://keycloak.dev.icos.91.109.56.214.sslip.io/realms/icos-dev/protocol/openid-connect/token' --header 'Content-Type: application/x-www-form-urlencoded' --data-urlencode 'grant_type=password' --data-urlencode 'client_id=coordination-module' --data-urlencode 'username=daniel.nikoloski@xlab.si' --data-urlencode 'password=<password>' --data-urlencode 'client_secret=<secret>'
```

Query wazuh with the token:
```sh
curl --header 'Authorization: Bearer <token>' http://127.0.0.1:8000/wazuh/
```