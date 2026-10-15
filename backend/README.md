# WireGuard Manager API

FastAPI backend for authenticated WireGuard inventory and controlled RouterOS management. The frontend is still a separate demo and is not connected to this API.

## Run locally

Requires Python 3.11+.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
cp backend/.env.example .env
# Set WGM_JWT_SECRET and WGM_ENCRYPTION_KEY to freshly generated secrets.
alembic upgrade head
uvicorn wireguard_manager_api.main:app --reload --app-dir backend
```

Generate secrets with:

```bash
python -c 'import secrets; print(secrets.token_urlsafe(48))'
python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

Never commit the generated values. For production, inject secrets through a secret manager and use a database supported by SQLAlchemy. Apply reviewed migrations before deploying the new application version; startup intentionally does not create or alter tables.

Run tests with `python -m pytest backend/tests`. API documentation is available at `http://127.0.0.1:8000/docs`.

## Implemented

- Versioned API, health checks, JWT access tokens, Argon2 password hashing, and admin/operator/viewer RBAC.
- Admin-only initial bootstrap and user provisioning.
- SQLAlchemy persistence models and an initial Alembic migration.
- Fernet-encrypted router credentials and an encrypted private-key field.
- Router registration, TLS-verified RouterOS REST connectivity test, read-only peer discovery, point-in-time traffic counters, and bounded read-only diagnostics.
- IP-literal host validation to reduce DNS rebinding/SSRF risk; public router addresses disabled by default.
- Peer address validation, router-side overlap checks, dry-run preview, and create/revoke endpoints guarded by `WGM_ENABLE_PEER_MUTATIONS=false` by default. Creation attempts compensating deletion if persistence fails; revocation disables peers so re-enable rollback is possible.
- Hash-linked audit records with chain verification.

## Important limitations

This is **not production-ready**. Live peer creation/revocation remains deliberately disabled until router-side rollback and IP allocation reconciliation are verified. Client configuration/QR delivery, refresh-session revocation, rate limiting, background metrics history, external secret management, off-host tamper-resistant audit retention, frontend integration, and real-device integration testing remain outstanding. Do not expose this service to the public internet without a deployment-specific security review, TLS termination, firewalling, and operational backups.
