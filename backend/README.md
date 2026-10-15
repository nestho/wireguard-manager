# WireGuard Manager API

This service is the first backend milestone for WireGuard Manager. It deliberately starts with a small, testable API foundation; it does **not** connect to routers or perform peer changes yet.

## Current scope

- FastAPI application and versioned `/api/v1` route namespace
- Liveness endpoint at `GET /healthz`
- Readiness endpoint at `GET /api/v1/health`
- Explicit API metadata and consistent error handling
- Unit tests for health endpoints
- No router credentials, private keys, or peer configuration are accepted or stored in this milestone

## Run locally

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
uvicorn wireguard_manager_api.main:app --reload --app-dir backend
```

Open `http://127.0.0.1:8000/docs` for the local OpenAPI page.

Run tests:

```bash
python -m pytest backend/tests
```

## Security status

This is an initial development scaffold, **not production-ready**. Do not expose it to a network or use it to manage real routers until authentication, authorization, secret storage, request limits, security logging, and RouterOS connection safeguards are implemented and reviewed.

The next milestone should add authenticated router inventory with encrypted credential storage and read-only connection testing. Mutating peer operations must remain disabled until address allocation, dry-run preview, explicit confirmation, and rollback behavior are implemented.
