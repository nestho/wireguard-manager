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

### Linux provider
- Register servers using SSH public-key authentication and pinned SHA256 host-key fingerprints.
- Reject DNS hostnames; target hosts must be IP literals. Public target IPs are blocked unless explicitly allowed.
- Inspect distribution/version, kernel, package manager, and wg / wg-quick availability.
- Preview WireGuard package installation for Debian/Ubuntu (apt-get), Fedora/RHEL family (dnf/yum), openSUSE/SLES (zypper), and Alpine (apk).
- Discover active WireGuard interfaces and remote peers, including current handshake and RX/TX counters.
- Validate peer addresses and interface names, check local and server-side address overlaps, and require an active wg-quick-managed interface with /etc/wireguard/<interface>.conf for persistent peer operations.
- Guard package installation and peer create/revoke with WGM_ENABLE_LINUX_MUTATIONS=false by default, explicit confirmation, and rollback attempts.
- Generate audited client config and QR outputs with no-store headers.

## API routes

The live OpenAPI schema at /docs is authoritative for exact request and response bodies.

| Method | Endpoint | Access / behavior |
|---|---|---|
| GET | /healthz | Liveness |
| GET | /api/v1/health | Readiness |
| POST | /api/v1/admin/bootstrap | One-time bootstrap; configured and no users must exist |
| POST | /api/v1/auth/login | Login / token issuance |
| POST | /api/v1/auth/refresh | Refresh-token rotation |
| POST | /api/v1/auth/logout | Refresh-token revocation |
| GET | /api/v1/auth/me | Current user |
| POST | /api/v1/auth/users | Admin provisions users |
| GET / POST | /api/v1/routers | List/register RouterOS targets |
| POST | /api/v1/routers/{router_id}/test | Connectivity test |
| GET | /api/v1/routers/{router_id}/wireguard/peers | Read live interfaces/peers |
| GET | /api/v1/routers/{router_id}/traffic | Point-in-time counters |
| GET | /api/v1/routers/{router_id}/diagnostics | Bounded read-only checks |
| POST | /api/v1/routers/{router_id}/peers/preview | Dry-run address/interface validation |
| POST | /api/v1/routers/{router_id}/peers | Guarded create; requires confirmation and mutation flag |
| DELETE | /api/v1/routers/{router_id}/peers/{peer_id}?confirm=true | Guarded disable/revoke |
| POST | /api/v1/routers/{router_id}/peers/{peer_id}/config | Sensitive client config download |
| POST | /api/v1/routers/{router_id}/peers/{peer_id}/qr | Sensitive client QR download |
| GET / POST | /api/v1/linux-servers | List/register Linux servers |
| POST | /api/v1/linux-servers/{server_id}/inspect | Inspect host and detect install plan |
| POST | /api/v1/linux-servers/{server_id}/install/preview | Preview package install |
| POST | /api/v1/linux-servers/{server_id}/install | Guarded package install |
| GET | /api/v1/linux-servers/{server_id}/peers | Local peer inventory |
| GET | /api/v1/linux-servers/{server_id}/peers/remote | Remote interfaces/peers and current counters |
| POST | /api/v1/linux-servers/{server_id}/peers/preview | Dry-run Linux peer validation |
| POST | /api/v1/linux-servers/{server_id}/peers | Guarded Linux peer create |
| DELETE | /api/v1/linux-servers/{server_id}/peers/{peer_id}?confirm=true | Guarded Linux peer revoke |
| POST | /api/v1/linux-servers/{server_id}/peers/{peer_id}/config | Sensitive client config download |
| POST | /api/v1/linux-servers/{server_id}/peers/{peer_id}/qr | Sensitive client QR download |
| GET | /api/v1/admin/audit/verify | Admin verifies audit chain |

Most API routes require Authorization: Bearer <access-token>. Admin-only, operator/admin, and authenticated-user policies are enforced server-side. Consult the OpenAPI docs for required JSON schemas and error responses.

## Role model

| Role | Intended access |
|---|---|
| admin | User administration, host registration, privileged host and peer operations, audit verification |
| operator | Routine registered-host inspection, diagnostics, discovery and guarded peer workflows |
| viewer | Authenticated read access where the route permits any authenticated user |

Route-level checks are authoritative; this table is a high-level summary rather than a replacement for the API schema.

## Linux SSH and sudo requirements

- Verify the SSH host key fingerprint independently and supply it in SHA256 format during registration.
- Use an unprivileged account with an SSH key. Do not use root SSH if restricted sudo is sufficient.
- The implementation uses non-interactive sudo -n; interactive password prompts cannot be completed by the API.
- Review and narrowly scope sudoers permissions to the exact commands needed by the selected workflow.
- Keep the SSH target private by default. DNS names are rejected; public IPs require WGM_ALLOW_PUBLIC_LINUX_HOSTS=true and egress review.
- Test each supported distribution and version in an isolated lab. Distribution-family detection does not guarantee every derivative/version behaves identically.

## Safe mutation workflow

1. Keep both mutation flags disabled while configuring and testing.
2. Register a test host and inspect it.
3. Run the appropriate preview endpoint and review all addresses, interfaces, and commands.
4. Validate least-privilege credentials and the target's persistent configuration.
5. In an isolated lab, enable only the required mutation flag for the test deployment.
6. Explicitly confirm the operation, then verify both remote state and local database state.
7. Test failure and rollback paths, including connection timeouts and database failures.
8. Disable the mutation flag again until the operational process is approved.

Rollback is best-effort, not a distributed transaction. If a request times out after a remote write, inspect the remote host before retrying; the remote operation may have succeeded even if the API did not return success.

## Testing

From the repository root:

~~~bash
python -m pip install -e ".[dev]"
alembic upgrade head
python -m pytest backend/tests
~~~

The GitHub Actions workflow also builds the frontend, validates migrations, and runs backend tests on pull requests and pushes to main. Automated tests are not a substitute for RouterOS/Linux integration tests.

## Operational limitations

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
