# WireGuard Manager API

FastAPI backend for early-stage, multi-platform WireGuard inventory and controlled RouterOS/Linux server operations. The frontend remains a separate demo and is **not connected** to this API.

> [!WARNING]
> This project is **not production-ready**. Live peer create/revoke and Linux install operations are disabled by default. Integration testing, deployment hardening, timeout reconciliation, rate limiting, off-host audit retention, and frontend integration remain outstanding.

## Contents

- [Requirements](#requirements)
- [Local setup](#local-setup)
- [Configuration](#configuration)
- [Implemented features](#implemented-features)
- [API routes](#api-routes)
- [Role model](#role-model)
- [Linux SSH and sudo requirements](#linux-ssh-and-sudo-requirements)
- [Safe mutation workflow](#safe-mutation-workflow)
- [Testing](#testing)
- [Operational limitations](#operational-limitations)

## Requirements

- Python 3.11+
- A SQLAlchemy-supported database; SQLite is the local default
- For RouterOS: HTTPS reachability and a dedicated account permitted to read the required REST resources
- For Linux: SSH reachability, public-key authentication, an independently verified SHA256 host-key fingerprint, and carefully scoped non-interactive sudo permissions for the specific commands used

## Local setup

Run these commands from the repository root:

~~~bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
cp backend/.env.example .env
~~~

Generate independent secrets:

~~~bash
python -c 'import secrets; print(secrets.token_urlsafe(48))'
python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
~~~

Set the generated values as WGM_JWT_SECRET and WGM_ENCRYPTION_KEY in the protected environment. Never commit them. Configure WGM_BOOTSTRAP_ADMIN_USERNAME and WGM_BOOTSTRAP_ADMIN_PASSWORD only for initial bootstrap; remove the bootstrap password from the environment after creating the admin account.

~~~bash
alembic upgrade head
uvicorn wireguard_manager_api.main:app --reload --app-dir backend
~~~

- API base URL: http://127.0.0.1:8000
- OpenAPI / Swagger UI: http://127.0.0.1:8000/docs
- Liveness: GET /healthz
- Readiness: GET /api/v1/health

The application deliberately does not create or mutate database schemas at startup. Apply reviewed Alembic migrations before deploying a new version.

## Configuration

See [backend/.env.example](.env.example). Main settings:

| Variable | Description | Default |
|---|---|---|
| WGM_DATABASE_URL | SQLAlchemy database URL | sqlite:///./wireguard-manager.db |
| WGM_JWT_SECRET | Access-token signing secret | Empty; configure a strong random secret |
| WGM_ENCRYPTION_KEY | Fernet encryption key for stored credentials/keys | Empty; configure and back up securely |
| WGM_ACCESS_TOKEN_MINUTES | Access-token lifetime | 15 |
| WGM_BOOTSTRAP_ADMIN_USERNAME | One-time bootstrap username | Empty |
| WGM_BOOTSTRAP_ADMIN_PASSWORD | One-time bootstrap password | Empty |
| WGM_ALLOWED_ORIGINS | CORS origin allowlist | http://localhost:5173 |
| WGM_ALLOW_PUBLIC_ROUTER_HOSTS | Permit public RouterOS target IPs | false |
| WGM_ALLOW_PUBLIC_LINUX_HOSTS | Permit public Linux SSH target IPs | false |
| WGM_ENABLE_PEER_MUTATIONS | Permit RouterOS peer create/revoke | false |
| WGM_ENABLE_LINUX_MUTATIONS | Permit Linux install and peer create/revoke | false |

These defaults are restrictive by design. Only change host/mutation settings after reviewing network egress controls, credentials, permissions, and rollback behavior.

## Implemented features

### Identity, authorization, and data protection
- JWT access authentication and refresh-token rotation/revocation.
- Argon2 password hashing.
- Admin, operator, and viewer roles.
- One-time admin bootstrap and admin user provisioning.
- SQLAlchemy models with Alembic migrations.
- Fernet encryption for stored RouterOS credentials, Linux SSH private keys, and peer private keys.
- Hash-linked audit events and admin-only chain verification.

### RouterOS provider
- Register RouterOS targets and test REST connectivity over HTTPS with TLS verification.
- Read WireGuard interfaces/peers and current traffic counters.
- Run bounded read-only diagnostics.
- Validate peer addresses and interface selection, and check local and remote address overlaps before writes.
- Guard peer creation/revocation with WGM_ENABLE_PEER_MUTATIONS=false by default, explicit confirmation, and compensating rollback attempts.
- Generate client config and QR PNG outputs with audit events and no-store response headers.

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

Not production-ready. Current gaps include:
- Frontend-to-API integration and frontend authentication/session handling.
- Complete integration and failure-injection tests against real supported RouterOS/Linux versions.
- Robust reconciliation for ambiguous timeout-after-write and rollback failure scenarios.
- Rate limiting, production deployment manifests, and full deployment hardening.
- External secret-manager support and tested key rotation/recovery procedures.
- Tamper-resistant off-host audit retention.
- Historical traffic/metrics storage, alerting, and monitoring.
- End-to-end and accessibility tests.

Do not expose this API directly to the public internet. Use a private management network, TLS termination, firewall rules, least-privilege device credentials, protected secrets, database/key backups, and a documented recovery process.
