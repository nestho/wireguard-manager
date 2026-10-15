# WireGuard Manager API

FastAPI backend for authenticated multi-platform WireGuard inventory and controlled RouterOS/Linux server management. The frontend is still a separate demo and is not connected to this API.

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
- RouterOS registration, TLS-verified REST connectivity test, read-only peer discovery, point-in-time traffic counters, and bounded diagnostics.
- Linux SSH onboarding with pinned SHA256 host-key fingerprints, encrypted private-key storage, distro/kernel/package-manager detection, and package plans for Debian/Ubuntu, Fedora/RHEL family, openSUSE/SLES, and Alpine.
- Linux interface/peer discovery, point-in-time counters, and gated peer create/revoke with `wg set`, `wg-quick save`, explicit confirmation, and compensating rollback attempts.
- Audited Linux client config and QR delivery with no-store response headers.
- IP-literal host validation to reduce DNS rebinding/SSRF risk; public router addresses disabled by default.
- Peer address validation, router-side overlap checks, dry-run preview, and create/revoke endpoints guarded by `WGM_ENABLE_PEER_MUTATIONS=false` by default. Creation attempts compensating deletion if persistence fails; revocation disables peers so re-enable rollback is possible.
- Audited WireGuard `.conf` and QR PNG delivery with strict server key/endpoint input validation and no-store response headers. Treat both outputs as secrets: the QR embeds the entire client configuration.
- Hash-linked audit records with chain verification.

## Linux server setup and safety

Linux API routes are documented at `/docs` under `linux-servers` and `linux-peers`. Registration requires a private SSH key and an independently verified `SHA256:` host-key fingerprint. The API pins the fingerprint and rejects hostnames to avoid DNS rebinding. Public SSH targets are blocked unless `WGM_ALLOW_PUBLIC_LINUX_HOSTS=true` is deliberately configured after egress review.

Inspect a server before requesting its install plan. Package installation is limited to recognized OS/package-manager combinations and runs via `sudo -n`; it requires explicit confirmation. Linux package installation and peer changes are disabled by default (`WGM_ENABLE_LINUX_MUTATIONS=false`). Peer create/revoke currently targets active `wg-quick` managed interfaces with `/etc/wireguard/<interface>.conf`, calls `wg-quick save`, and attempts compensating rollback. Keep mutations disabled until tests against your exact distributions, sudo rules and WireGuard versions are completed. Never use root SSH if a restricted sudo account can satisfy the operational needs.

## Important limitations

This is **not production-ready**. RouterOS and Linux mutation gates remain disabled by default. SSH install and Linux peer lifecycle are implemented but require integration testing against supported distributions and sudo policies; timeouts after remote changes can still leave an ambiguous outcome. Rate limiting, background metrics history, external secret management, off-host tamper-resistant audit retention, frontend-to-API integration, and production hardening remain outstanding. Do not expose this service to the public internet without a deployment-specific security review, TLS termination, firewalling, and operational backups.
