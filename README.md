# WireGuard Manager

**WireGuard Manager** manages WireGuard deployments across **MikroTik RouterOS** and **Linux servers**. GitHub Pages and the default Vite build remain a public demo only. A separate PM2-managed production deployment provides an API-backed UI with authentication, persistent inventory, peer workflows, access-control management, configuration delivery, diagnostics, and audit views.

> [!IMPORTANT]
> **Production deployment path implemented; operational release gates remain.** The production entry point is isolated from the demo dashboard and does not import its synthetic fixture records. CI passed for the merged production deployment implementation, including frontend builds, production-bundle marker checks, migrations, and backend tests. CI does not validate live router/server compatibility or certify the system secure. Keep peer create/revoke, Linux install, and optimizer-apply mutations disabled until the exact target versions, firewall behavior, rollback paths, and change-control procedures are validated. Deploy behind TLS on a restricted management network. The Electron package remains a separate read-only audit client, not a bundled full production manager.

<p align="center">
  <a href="https://nestho.github.io/wireguard-manager/"><strong>Open the frontend demo →</strong></a>
  &nbsp; · &nbsp;
  <a href="https://github.com/nestho/wireguard-manager/actions/workflows/ci.yml"><strong>CI workflow</strong></a>
  &nbsp; · &nbsp;
  <a href="https://github.com/nestho/wireguard-manager/blob/main/docs/PRODUCTION_DEPLOYMENT.md"><strong>Production deployment guide</strong></a>
  &nbsp; · &nbsp;
  <a href="https://github.com/nestho/wireguard-manager/blob/main/backend/README.md"><strong>Backend setup</strong></a>
</p>

## Table of contents

- [What is implemented](#what-is-implemented)
- [Architecture](#architecture)
- [Frontend demo](#frontend-demo)
- [Production deployment](#production-deployment)
- [PM2 process operations](#pm2-process-operations)
- [Backend capabilities](#backend-capabilities)
- [API overview](#api-overview)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Security and operational guardrails](#security-and-operational-guardrails)
- [Testing and CI](#testing-and-ci)
- [Repository layout](#repository-layout)
- [Production release criteria](#production-release-criteria)
- [Known limitations and roadmap](#known-limitations-and-roadmap)
- [Contributing](#contributing)
- [License](#license)

## What is implemented

| Area | Status | Notes |
|---|---|---|
| React dashboard | Two build modes | Default Vite/Pages build is demo-only; `npm run build:production` builds a separate API-backed UI with no synthetic seed records |
| Authentication | Implemented in API | JWT access tokens, rotating/revocable refresh tokens, Argon2 password hashing |
| Authorization | Implemented in API | Admin, operator, and viewer roles |
| Database | Implemented | SQLAlchemy models and Alembic migrations; schema is not auto-mutated at app startup |
| Secret storage | Implemented | Fernet-encrypted router credentials, Linux SSH private keys, and stored peer private-key material |
| MikroTik RouterOS | Early integration | Registration, TLS-verified connectivity checks, read-only WireGuard discovery, point-in-time counters, diagnostics |
| Linux WireGuard servers | Early integration | SSH onboarding with pinned host-key fingerprints, host inspection, distro/package-manager detection, install preview, interface/peer discovery, counters |
| Peer lifecycle | Implemented behind safety gates | Address validation, dry-run preview, explicit confirmation, guarded create/revoke, compensating rollback attempts |
| Per-peer destination ACL | Implemented in PR #6 | CIDR allowlists with RouterOS/Linux firewall enforcement; existing peers require explicit ACL reconciliation |
| Client configuration / QR | Implemented in API | Audited config and QR delivery; outputs contain private key material and must be handled as secrets |
| Audit trail | Implemented | Hash-linked audit events and admin chain verification; not tamper-proof against an administrator who can rewrite the database |
| Traffic history | Not implemented | API returns point-in-time counters, not historical time series |
| Linux performance optimizer | Backend endpoints and guarded production UI controls exist | Read-only inspection is distinct from mutation; apply operations remain disabled unless explicitly enabled and validated |

## Architecture

```text
GitHub Pages / default Vite build
  └── React demo with synthetic fixtures and browser-local state

PM2 production host
  └── Production-only React entry point
      └── Same-origin /api proxy
          └── FastAPI authentication/RBAC
              ├── SQLAlchemy + Alembic persistence
              ├── RouterOS REST provider (HTTPS)
              ├── Linux SSH provider (pinned host key)
              └── Hash-linked audit events
```

The Pages/default development dashboard is illustrative and must never be used as an operational control plane. The production build is isolated from the demo entry point and does not seed sample routers, peers, traffic, or audit events. It uses authenticated API calls and reads/writes the configured persistent database. Build isolation is checked in CI and again by the deployment script using known fixture markers; this is a useful guard, not a formal proof that every possible demo string is absent.

## Production deployment

The production host deployment and PM2 process definitions are merged into `main`. Follow the [production deployment and operations guide](docs/PRODUCTION_DEPLOYMENT.md); do not use GitHub Pages as the live manager.

Quick path on a prepared host:

```bash
git clone https://github.com/nestho/wireguard-manager.git
cd wireguard-manager
cp .env.production.example .env
nano .env
chmod 600 .env
bash scripts/deploy-production.sh
```

Before running the script, replace every placeholder in `.env`, generate independent `WGM_JWT_SECRET` and `WGM_ENCRYPTION_KEY` values, set a persistent `WGM_DATABASE_URL`, configure the exact external origin, and set the one-time admin credentials. The script does **not** prompt for or generate those secrets. On successful first bootstrap it removes the one-time bootstrap username/password from `.env`; save the admin credentials in a password manager first.

The app listens on loopback at `127.0.0.1:4173` (web) and `127.0.0.1:8000` (API). Use a TLS reverse proxy and a restricted management network before remote access. Do not expose either listener directly to the public internet.

**Release status:** CI passed for the merged production deployment change, including frontend builds, production-bundle marker checks, migration validation, and backend tests. This is not a claim of security certification or fully validated live infrastructure operations. Keep remote mutation gates disabled until the exact RouterOS/Linux versions, firewall ordering, rollback behavior, and change-control procedures have been tested in a lab. Review the limitations and release gates below.

## Frontend demo

**This GitHub Pages site is a demo only.** It uses synthetic fixtures and browser-local state, has no connection to your routers or the production database, and must never be used as an operational control plane. Publishing the demo does not publish or deploy the backend.

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

## Desktop client and read-only pre-configuration audit

A cross-platform Electron desktop client is available in this branch. It can be packaged as:
- Windows: NSIS installer for x64 and arm64
- macOS: DMG and ZIP (the CI build is unsigned unless signing credentials are configured)
- Linux: AppImage and DEB

Build locally on the matching operating system:
```bash
npm install
npm run desktop:build
```
Artifacts are written to `release/`. The manually triggered GitHub Actions workflow builds preview artifacts for Windows, macOS, and Linux; artifacts are retained for 7 days. It intentionally does not publish on version tags because this is not the complete product. These preview packages are unsigned, so macOS Gatekeeper/Windows SmartScreen may warn.

**Architecture note:** the installer is currently the desktop audit client, not a self-contained bundle of the FastAPI service. The API must already be running and reachable (locally or on a trusted management network). The app defaults to `http://127.0.0.1:8000`; use HTTPS for remote API connections.

### Read-only RouterOS audit

After logging in, choose a registered router and run the audit. The backend collects RouterOS resource/version, identity, packages, management services, input firewall rules, NAT rules, addresses, routes, WireGuard interfaces and peers using GET requests only. The report includes:
- Severity-labelled findings, recommendations and supporting evidence
- Collected versus unassessed checks (a permission/collection failure is never treated as a clean result)
- JSON and HTML export
- A "continue to configuration docs" action, or close the app

The audit endpoint is `GET /api/v1/routers/{router_id}/audit` and requires an admin/operator bearer token. It records a summary in the manager's audit log but never writes RouterOS configuration. The desktop IPC layer only permits login, router-list, and this audit endpoint; it does not expose arbitrary HTTP requests to the renderer.

**Audit limitations:** this is a configuration review, not a penetration test. It does not exploit vulnerabilities, change settings, validate actual packet flow, or query a live CVE/vendor-advisory feed. RouterOS version support must be verified against official MikroTik advisories. Findings about input firewall rules are indicators for manual review, not proof of internet exposure. Exported reports can contain router addresses and configuration evidence; store them as sensitive operational data.

The configuration UI/API is not yet wired into this desktop audit client. The continue action opens the backend API documentation; it does not silently apply or change any settings.

## PM2 process operations

The production service is managed by PM2. Run these commands as the same operating-system user that performed deployment:

```bash
pm2 status
pm2 logs wireguard-manager-api
pm2 logs wireguard-manager-web
pm2 restart wireguard-manager-api
pm2 restart wireguard-manager-web
pm2 save
```

The web process serves `dist-production` on `127.0.0.1:4173` and proxies same-origin `/api/*` requests to FastAPI on `127.0.0.1:8000`. The API is not the frontend; opening port 8000 at `/` can correctly return 404. See [production deployment and operations](docs/PRODUCTION_DEPLOYMENT.md) for first login, reverse proxy, backups, upgrades, smoke tests, and recovery.

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
- Node.js 20.19+ or 22.12+ and npm for the frontend.
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
| WGM_ALLOWED_ORIGINS | Allowed browser origins | Exact external origin, e.g. `https://vpn-manager.example.com`; production UI uses same-origin `/api` proxy |
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
5. Builds the GitHub Pages demo artifact; deploys that static demo on pushes to main. This is not a production backend deployment.

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

## Production release criteria

A successful CI run or `/healthz` response is not sufficient by itself to declare the whole product production-ready. Before enabling live write operations or describing a deployment as production-approved, verify and document all of the following:

- [ ] Run the deployment and upgrade workflow on the intended supported production OS and confirm a clean install and an upgrade with existing data.
- [ ] Verify admin bootstrap, login/logout, token refresh/expiry, role enforcement, and denied unauthenticated requests.
- [ ] Test every production UI/API workflow against lab RouterOS versions and supported Linux distributions, including permission errors, timeouts, partial failures, and rollback failures.
- [ ] Confirm peer create/revoke and per-peer ACL enforcement against actual firewall rule ordering, routing/NAT, and existing peers; keep mutation gates disabled until sign-off.
- [ ] Test configuration and QR downloads securely; verify secrets are not logged, cached, or exposed to unauthorized roles.
- [ ] Exercise database backup and restore together with the exact `WGM_ENCRYPTION_KEY`; verify a restore in an isolated environment.
- [ ] Configure HTTPS, reverse-proxy headers, firewall restrictions, and the exact `WGM_ALLOWED_ORIGINS`; confirm the API listener is not public.
- [ ] Validate PM2 restart/reboot recovery, log rotation/retention, disk monitoring, and a documented rollback path.
- [ ] Add end-to-end tests, failure-injection tests, rate limiting, dependency/security scanning, and an external security review before broad production use.
- [ ] Validate audit retention off-host; hash-linked database records alone are not immutable.
- [ ] Treat the Electron desktop audit client as a separate read-only client, not a bundled full production manager.

CI currently validates TypeScript/frontend builds, the isolated production build and known fixture-marker checks, Alembic migrations, and backend tests. It does not prove live router/server interoperability or production security.

## Known limitations and roadmap

- The deployment script and PM2 path are implemented; host-level backup/restore, upgrade/rollback, TLS/reverse-proxy, and reboot-recovery procedures still need to be validated in the target environment.
- Real-device and Linux distribution integration tests, timeout-after-write reconciliation, and mutation rollback/failure-injection tests remain release gates.
- Rate limiting, external secret-manager integration, formal key rotation/recovery, and independent security review remain outstanding.
- Hash-linked audit events can be rewritten by an actor with database-level control; configure off-host retention for incident response.
- Historical traffic collection, historical charts, alerting, and a metrics/monitoring pipeline are not implemented; traffic values are point-in-time counters.
- Live peer create/revoke, Linux package installation, and optimizer apply operations are gated off by default. Do not enable them without lab validation, rollback testing, and change approval.
- The Electron desktop package remains a separate read-only RouterOS audit client and does not bundle the complete API-backed manager.
- GitHub Pages and the default Vite mode remain demo-only; no demo records are imported into the production entry point.

## Contributing

Issues and pull requests are welcome. Include minimal reproduction steps and sanitized logs. Never publish production router exports, credentials, SSH/WireGuard private keys, client configuration files, QR codes, or real secret values. Use synthetic fixtures.

## License

Distributed under the [MIT License](LICENSE).
