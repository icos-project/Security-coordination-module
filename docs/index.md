# Security coordination

[Api definition](api)

[Wazuh](wazuh)

**Endpoints when running locally**:

- openapi specification: http://localhost:8000/docs
- prometheus metrics: http://localhost:8000/wazuh-prometheus/metrics

## Development

Run the application in development mode with:
```bash
python -m uvicorn src.app:APP --reload
```

The application will be served on `localhost:8000` by default.

## Security

All calls to the Security coordination module require a valid Authorization token
from Keycloak.