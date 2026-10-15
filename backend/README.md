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
- Admin-controlled Linux VPN optimizer: read-only host inspection, evidence-based sysctl recommendations, and optional allowlisted tuning behind a default-off feature flag.
- Audited Linux client config and QR delivery with no-store response headers.
- IP-literal host validation to reduce DNS rebinding/SSRF risk; public router addresses disabled by default.
- Peer address validation, router-side overlap checks, dry-run preview, and create/revoke endpoints guarded by default-off mutation gates.
- Hash-linked audit records with chain verification.

## Linux VPN server optimizer

See [linux-vpn-optimizer.md](linux-vpn-optimizer.md). The read-only endpoint `POST /api/v1/linux-servers/{id}/optimizer/inspect` collects kernel/CPU/memory/network-interface/sysctl/qdisc/NIC-offload/module/WireGuard snapshots and separates actionable recommendations from manual checks.

The apply endpoint `POST /api/v1/linux-servers/{id}/optimizer/apply` is admin-only, requires `confirm=true`, and remains disabled unless `WGM_ENABLE_LINUX_OPTIMIZER_MUTATIONS=true` is deliberately configured. Current automatic changes are limited to socket receive/send buffer ceilings and the network receive backlog. Kernel upgrades/reboots, CPU governor, IRQ/RPS/XPS, NIC offloads, MTU, routes/firewall/forwarding, and congestion control are not changed automatically.

## Linux server setup and safety

Linux API routes are documented at `/docs` under `linux-servers`, `linux-peers`, and `linux-optimizer`. Registration requires a private SSH key and an independently verified `SHA256:` host-key fingerprint. Public SSH targets are blocked unless `WGM_ALLOW_PUBLIC_LINUX_HOSTS=true` is deliberately configured after egress review.

Inspect a server before requesting an install plan. Package installation is limited to recognized OS/package-manager combinations and runs via `sudo -n`; it requires explicit confirmation. Linux package installation, peer changes, and optimizer changes are disabled by default. Keep gates off until tests against exact distributions, sudo rules, WireGuard versions, and expected traffic loads are completed.

## Important limitations

This is **not production-ready**. Remote mutation operations need integration tests and careful reconciliation after timeouts. Rate limiting, background metrics history, external secret management, off-host tamper-resistant audit retention, frontend-to-API integration, and production hardening remain outstanding. Do not expose this service to the public internet without a deployment-specific security review, TLS termination, firewalling, and operational backups.
