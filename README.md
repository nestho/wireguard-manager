# WireGuard Manager

**WireGuard Manager** is an early-stage, self-hosted management API and frontend prototype for WireGuard deployments on **MikroTik RouterOS** and **Linux servers**.

> [!IMPORTANT]
> **Development status — not production-ready.** The FastAPI backend contains real inventory, discovery, diagnostics, and guarded mutation endpoints. The React dashboard is still a standalone demo and is **not connected to the backend**. Live write operations are disabled by default. Passing CI/unit tests does not replace integration tests against your actual RouterOS versions, Linux distributions, SSH/sudo policy, and deployment environment.

<p align="center">
  <a href="https://nestho.github.io/wireguard-manager/"><strong>Open the frontend demo →</strong></a>
  &nbsp; · &nbsp;
  <a href="https://github.com/nestho/wireguard-manager/actions/workflows/ci.yml"><strong>CI workflow</strong></a>
  &nbsp; · &nbsp;
  <a href="https://github.com/nestho/wireguard-manager/blob/main/backend/README.md"><strong>Backend setup</strong></a>
</p>

## Table of contents

- [What is implemented](#what-is-implemented)
- [Architecture](#architecture)
- [Frontend demo](#frontend-demo)
- [Backend capabilities](#backend-capabilities)
- [API overview](#api-overview)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Security and operational guardrails](#security-and-operational-guardrails)
- [Testing and CI](#testing-and-ci)
- [Repository layout](#repository-layout)
- [Known limitations and roadmap](#known-limitations-and-roadmap)
- [Contributing](#contributing)
- [License](#license)

## What is implemented

| Area | Status | Notes |
|---|---|---|
| React dashboard | Demo only | Responsive pages, synthetic data, local browser persistence; not connected to the API |
| Authentication | Implemented in API | JWT access tokens, rotating/revocable refresh tokens, Argon2 password hashing |
| Authorization | Implemented in API | Admin, operator, and viewer roles |
| Database | Implemented | SQLAlchemy models and Alembic migrations; schema is not auto-mutated at app startup |
| Secret storage | Implemented | Fernet-encrypted router credentials, Linux SSH private keys, and stored peer private-key material |
| MikroTik RouterOS | Early integration | Registration, TLS-verified connectivity checks, read-only WireGuard discovery, point-in-time counters, diagnostics |
| Linux WireGuard servers | Early integration | SSH onboarding with pinned host-key fingerprints, host inspection, distro/package-manager detection, install preview, interface/peer discovery, counters |
| Peer lifecycle | Implemented behind safety gates | Address validation, dry-run preview, explicit confirmation, guarded create/revoke, compensating rollback attempts |
| Client configuration / QR | Implemented in API | Audited config and QR delivery; outputs contain private key material and must be handled as secrets |
| Audit trail | Implemented | Hash-linked audit events and admin chain verification; not tamper-proof against an administrator who can rewrite the database |
| Traffic history | Not implemented | API returns point-in-time counters, not historical time series |
| Linux performance optimizer | Not included in current main | Do not treat work in an unmerged PR as a shipped feature |

## Architecture

~~~text
Browser
  └── React + TypeScript + Vite frontend
      └── Static demo data and browser-local state only
          (no API calls to the backend yet)

FastAPI backend
  ├── JWT authentication and role checks
  ├── SQLAlchemy + Alembic persistence
  ├── RouterOS provider ── HTTPS / RouterOS REST API
  ├── Linux provider ───── SSH with pinned host-key fingerprint
  └── Audit events ─────── hash-linked database records
~~~

The frontend and API are separate deliverables today. The demo's routers, peers, traffic charts, diagnostics, and audit events are illustrative; they do not represent the database or live infrastructure. API operations must be invoked directly through the API or another client until frontend-to-API integration is implemented.

## Frontend demo

The live static dashboard includes these illustrative views:

| View | Route | Purpose |
|---|---|---|
| Overview | [#/overview](https://nestho.github.io/wireguard-manager/#/overview) | Summary metrics, sample router health, traffic and recent peers |
| Routers | [#/routers](https://nestho.github.io/wireguard-manager/#/routers) | Synthetic router inventory and resource examples |
| Users & devices | [#/users-and-devices](https://nestho.github.io/wireguard-manager/#/users-and-devices) | Search/filter sample peers, addresses, device status and traffic |
| Traffic | [#/traffic](https://nestho.github.io/wireguard-manager/#/traffic) | Illustrative charts and sample usage breakdown |
| Diagnostics | [#/diagnostics](https://nestho.github.io/wireguard-manager/#/diagnostics) | Checks against demo data only |
| Audit log | [#/audit-log](https://nestho.github.io/wireguard-manager/#/audit-log) | Local demo events |
| Settings | [#/settings](https://nestho.github.io/wireguard-manager/#/settings) | Demo preferences, export and reset controls |
| Linux Servers | [#/linux-servers](https://nestho.github.io/wireguard-manager/#/linux-servers) | Illustrative onboarding information only; no live SSH operations |

### Screenshots

These are illustrative SVG mockups, not live monitoring data.

**Overview**

![WireGuard Manager overview dashboard](docs/dashboard-preview.svg)

**Router inventory**

![Router inventory preview](docs/routers-preview.svg)

**Users and devices**

![Users and devices preview](docs/devices-preview.svg)

**Operations views**

![Traffic, diagnostics, audit log and settings previews](docs/operations-preview.svg)

Demo changes are kept in the current browser's local storage. Resetting browser storage or using another browser/device may restore the seed data. Never treat the demo as an authoritative inventory.

## Backend capabilities

The API is built with FastAPI and supports these early-stage workflows.

### Authentication and persistence
- One-time administrator bootstrap when configured and when no users exist.
- Login, access-token issuance, refresh-token rotation, and logout revocation.
- Argon2 password hashing and admin/operator/viewer role checks.
- SQLAlchemy persistence and reviewed Alembic schema migrations.
- Fernet encryption for stored router credentials, Linux SSH private keys, and peer private keys.

### MikroTik RouterOS
- Register routers and test connectivity through HTTPS with TLS verification.
- Read WireGuard interfaces and peers.
- Read current peer RX/TX counters and handshake data where exposed by RouterOS.
- Run bounded, read-only diagnostics.
- Preview proposed peer creation with address/interface validation and local plus router-side overlap checks.
- Create/revoke peers only when the mutation gate is explicitly enabled; operations require explicit confirmation and include compensating rollback attempts.
- Generate audited client configuration and QR images. The QR encodes the full client configuration, including the private key.

### Linux WireGuard servers
- Register servers using SSH public-key authentication and an independently verified SHA256 host-key fingerprint.
- Require an IP literal for the target host; DNS hostnames are rejected to reduce DNS-rebinding/SSRF risk.
- Inspect OS release, kernel, package manager, and WireGuard tool availability.
- Generate installation previews for supported package-manager families:
  - Debian/Ubuntu family — apt-get
  - Fedora/RHEL family — dnf or yum
  - openSUSE/SLES — zypper
  - Alpine — apk
- Discover active interfaces and remote peers; retrieve point-in-time counters.
- Preview peer creation with address overlap checks and require an active interface plus a /etc/wireguard/<interface>.conf file for persistent changes.
- Gate package installation and peer create/revoke behind WGM_ENABLE_LINUX_MUTATIONS=false by default.
- Deliver audited client configuration and QR outputs with no-store response headers.

### Audit trail
- Record security-relevant actions without placing credentials/private keys in event details.
- Link audit events with hashes and provide an admin-only chain verification endpoint.
- This is **not immutable storage**: an actor able to rewrite the database and all records may be able to recompute the chain. Use off-host retention before relying on it for incident response.

## API overview

Run the API and open Swagger UI at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs). The OpenAPI page reflects the running version and is the source of truth for request/response schemas.

| Method | Endpoint | Purpose / access |
|---|---|---|
| GET | /healthz | Liveness check |
| GET | /api/v1/health | API readiness and provider summary |
| POST | /api/v1/admin/bootstrap | One-time initial admin bootstrap |
| POST | /api/v1/auth/login | Authenticate and issue tokens |
| POST | /api/v1/auth/refresh | Rotate refresh token |
| POST | /api/v1/auth/logout | Revoke presented refresh token |
| GET | /api/v1/auth/me | Current authenticated user |
| POST | /api/v1/auth/users | Admin user provisioning |
| GET / POST | /api/v1/routers | List/register RouterOS devices |
| POST | /api/v1/routers/{id}/test | Test RouterOS connectivity |
| GET | /api/v1/routers/{id}/wireguard/peers | Read RouterOS WireGuard interfaces/peers |
| GET | /api/v1/routers/{id}/traffic | Current peer counters; no history |
| GET | /api/v1/routers/{id}/diagnostics | Bounded read-only diagnostics |
| POST | /api/v1/routers/{id}/peers/preview | Validate and preview peer creation |
| POST | /api/v1/routers/{id}/peers | Guarded peer creation; disabled by default |
| DELETE | /api/v1/routers/{id}/peers/{peer_id}?confirm=true | Guarded peer revocation; disabled by default |
| POST | /api/v1/routers/{id}/peers/{peer_id}/config | Download generated client config; sensitive |
| POST | /api/v1/routers/{id}/peers/{peer_id}/qr | Download QR PNG; sensitive |
| GET / POST | /api/v1/linux-servers | List/register Linux servers |
| POST | /api/v1/linux-servers/{id}/inspect | Read-only host inspection and install-plan detection |
| POST | /api/v1/linux-servers/{id}/install/preview | Preview supported package installation |
| POST | /api/v1/linux-servers/{id}/install | Guarded WireGuard package installation |
| GET | /api/v1/linux-servers/{id}/peers | List peers tracked in the local database |
| GET | /api/v1/linux-servers/{id}/peers/remote | Discover active remote interfaces/peers and counters |
| POST | /api/v1/linux-servers/{id}/peers/preview | Validate and preview Linux peer creation |
| POST | /api/v1/linux-servers/{id}/peers | Guarded Linux peer creation |
| DELETE | /api/v1/linux-servers/{id}/peers/{peer_id}?confirm=true | Guarded Linux peer revocation |
| POST | /api/v1/linux-servers/{id}/peers/{peer_id}/config | Download generated Linux client config; sensitive |
| POST | /api/v1/linux-servers/{id}/peers/{peer_id}/qr | Download Linux client QR PNG; sensitive |
| GET | /api/v1/admin/audit/verify | Admin verifies audit hash chain |

Most routes require a Bearer access token; role requirements and body fields are shown in Swagger UI. Mutation endpoints must not be assumed safe merely because they are present.

## Quick start

### Requirements
- Node.js 20+ and npm for the frontend.
- Python 3.11+ for the backend.
- A supported SQLAlchemy database. SQLite is the local-development default.
- For live RouterOS access: network reachability, a dedicated RouterOS account, and a valid HTTPS certificate.
- For Linux access: network reachability, an SSH user/key, a verified SHA256 host-key fingerprint, and narrowly scoped non-interactive sudo -n permissions for the required commands.

### Start the frontend demo

~~~bash
git clone https://github.com/nestho/wireguard-manager.git
cd wireguard-manager
npm install
npm run dev
~~~

Vite prints the development URL, usually http://localhost:5173. The demo does not call the API.

### Start the backend API

From the repository root:

~~~bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
cp backend/.env.example .env
~~~

Generate two independent secrets and set them in the protected .env file:

~~~bash
python -c 'import secrets; print(secrets.token_urlsafe(48))'
python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
~~~

Set the first value as WGM_JWT_SECRET and the second as WGM_ENCRYPTION_KEY. Configure bootstrap credentials only for initial setup. Then run:

~~~bash
alembic upgrade head
uvicorn wireguard_manager_api.main:app --reload --app-dir backend
~~~

The API is available at http://127.0.0.1:8000; interactive docs are at /docs. Run the tests with:

~~~bash
python -m pytest backend/tests
~~~

See [backend/README.md](backend/README.md) for full setup and safety notes. Do not commit secrets, production configuration, client configs, QR images, or private keys.

## Configuration

All environment variables use the WGM_ prefix. Defaults are intentionally restrictive.

| Variable | Purpose | Default / guidance |
|---|---|---|
| WGM_DATABASE_URL | SQLAlchemy database URL | sqlite:///./wireguard-manager.db for local development |
| WGM_JWT_SECRET | Signs access tokens | Required for real use; generate a high-entropy secret (32+ characters) |
| WGM_ENCRYPTION_KEY | Fernet key for stored secrets | Required; generate with Fernet.generate_key(); back it up securely and separately |
| WGM_ACCESS_TOKEN_MINUTES | Access-token lifetime | 15 |
| WGM_BOOTSTRAP_ADMIN_USERNAME | Initial admin account name | Empty; configure only for one-time bootstrap |
| WGM_BOOTSTRAP_ADMIN_PASSWORD | Initial admin password | Empty; remove from environment after bootstrap |
| WGM_ALLOWED_ORIGINS | Allowed browser origins | http://localhost:5173; frontend integration is not yet implemented |
| WGM_ALLOW_PUBLIC_ROUTER_HOSTS | Allow public RouterOS host IPs | false; keep false unless egress controls are reviewed |
| WGM_ALLOW_PUBLIC_LINUX_HOSTS | Allow public Linux SSH target IPs | false; keep false unless egress controls are reviewed |
| WGM_ENABLE_PEER_MUTATIONS | Enable RouterOS peer create/revoke | false; keep disabled until device-specific integration tests pass |
| WGM_ENABLE_LINUX_MUTATIONS | Enable Linux package install and peer mutations | false; keep disabled until distro/sudo/rollback tests pass |

Use a secret manager or protected environment for production secrets. Losing WGM_ENCRYPTION_KEY can make stored credentials and peer keys unrecoverable. Exposing it compromises those stored values.

## Security and operational guardrails

- Keep the API on a private management network behind HTTPS termination and firewall rules. Do not expose it publicly without a deployment-specific review.
- Use least-privilege RouterOS credentials and a dedicated Linux SSH account; avoid root SSH where restricted sudo is sufficient.
- Keep RouterOS TLS verification enabled.
- Verify Linux SSH host-key fingerprints independently before registration. Do not trust a fingerprint copied from an unverified connection.
- Public RouterOS/Linux hosts and all live mutations are disabled by default.
- Review preview output and require explicit confirmation before live writes.
- Mutation flows attempt compensating rollback, but rollback is not guaranteed after a timeout, process failure, or remote/local state mismatch. Inspect the remote server before retrying an ambiguous operation.
- Client configuration files and QR images contain private key material. Treat them like credentials; no-store response headers do not prevent client-side capture.
- Audit hash linking detects some changes but is not a substitute for remote append-only logging.
- Do not expose /docs or detailed errors publicly without an explicit operational decision.
- Keep backups of the database and encryption key, and test restoration.
- The API has no complete production hardening, external secret-manager integration, rate limiting, historical monitoring pipeline, or frontend integration yet.

## Testing and CI

The GitHub Actions workflow on pushes and pull requests to main:
1. Installs frontend dependencies and runs the TypeScript/Vite production build.
2. Installs backend dependencies with development extras.
3. Applies and validates Alembic migrations.
4. Runs python -m pytest backend/tests.
5. Builds the GitHub Pages artifact; deploys the static frontend on pushes to main.

CI passing means the automated build/tests succeeded; it does **not** prove compatibility or safe rollback on physical routers or production Linux hosts. Run integration tests in an isolated lab before enabling mutations.

## Repository layout

~~~text
wireguard-manager/
├── .github/workflows/ci.yml       # Frontend build, migration check, backend tests, Pages deploy
├── backend/
│   ├── wireguard_manager_api/     # FastAPI routes, auth, providers, models and security
│   ├── tests/                     # Backend/API tests
│   ├── alembic/                   # Versioned database migrations
│   ├── .env.example               # Safe local-development template
│   └── README.md                  # Backend setup, API details and operational caveats
├── docs/                          # Dashboard preview illustrations
├── demo/seed-data.json            # Synthetic fixture
├── src/                           # React/TypeScript demo frontend
├── alembic.ini                    # Alembic configuration
├── pyproject.toml                 # Python project/dependency configuration
├── package.json                   # Frontend scripts/dependencies
├── CHANGELOG.md                   # Change history
├── SECURITY.md                    # Security reporting and deployment guardrails
└── LICENSE                        # MIT license
~~~

## Known limitations and roadmap

- [ ] Connect the frontend to the authenticated API and replace mock state with explicit live/demo modes.
- [ ] Add frontend authentication/session handling and role-aware UI.
- [ ] Add integration tests against supported RouterOS versions and Linux distribution/sudo combinations.
- [ ] Add robust reconciliation for timeout-after-write and failed rollback scenarios.
- [ ] Add rate limiting, production deployment templates, secret-manager integration, and hardening guidance.
- [ ] Add off-host append-only audit retention and an operational alerting/metrics pipeline.
- [ ] Add historical traffic collection; current API counters are point-in-time snapshots.
- [ ] Add end-to-end and accessibility testing.
- [ ] Complete review/benchmarking of any future Linux performance-optimization feature before describing it as supported.

## Contributing

Issues and pull requests are welcome. Include minimal reproduction steps and sanitized logs. Never publish production router exports, credentials, SSH/WireGuard private keys, client configuration files, QR codes, or real secret values. Use synthetic fixtures.

## License

Distributed under the [MIT License](LICENSE).
