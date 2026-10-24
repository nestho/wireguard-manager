# Production deployment and operations (PM2)

This guide describes the **hosted production-mode UI/API deployment**, not the GitHub Pages demo and not the Electron audit client. The production entry point is isolated from the demo dashboard and starts with empty inventories when the configured database is empty. It does not intentionally seed sample routers, peers, traffic, or audit events.

> [!WARNING]
> A successful build, deployment, or health check does not certify the product or validate remote changes against your infrastructure. Keep peer creation/revocation, Linux installation, and optimizer-apply gates disabled until the exact environment has been tested and approved. Do not expose the web/API listeners directly to the public internet.

## 1. Host requirements

Recommended deployment target: a dedicated Linux host on a restricted management network. The script may run in other shell environments, but the supported production target and this operational guide assume Linux.

- Node.js 20+ and npm.
- Python 3.11+ and a working Python venv/pip installation.
- PM2 installed and available in the deploying user's `PATH`.
- `curl`, Git, and outbound package-registry access during install/upgrade.
- Network access from the manager to intended RouterOS HTTPS REST endpoints and Linux SSH targets.
- A persistent database path and a backup location outside the application checkout.
- TLS reverse proxy / HTTPS endpoint before any remote user access.
- A documented owner for credentials, database/key backups, upgrades, and incident response.

Use the same OS account for deployment and PM2 management. Do not run the application as root unless your environment has a reviewed reason to do so.

## 2. Clone and configure (first install only)

```bash
git clone https://github.com/nestho/wireguard-manager.git
cd wireguard-manager
cp .env.production.example .env
chmod 600 .env
nano .env
```

Generate two **independent** secrets. Run these from the project Python environment if `cryptography` is already installed; otherwise the deployment script installs the package in `.venv` and you can generate the Fernet key with that interpreter after installing dependencies.

JWT signing secret:

```bash
python3 -c 'import secrets; print(secrets.token_urlsafe(48))'
```

Fernet encryption key (prepare an isolated venv if the package is not already available):

```bash
python3 -m venv .venv
.venv/bin/python -m pip install cryptography
.venv/bin/python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

Paste the actual outputs into `WGM_JWT_SECRET` and `WGM_ENCRYPTION_KEY`. Do not use the example placeholders or reuse one value for both settings.

Configure these required values in `.env`:

- `WGM_JWT_SECRET`: unique high-entropy secret, at least 32 characters.
- `WGM_ENCRYPTION_KEY`: valid Fernet key. Back it up securely; losing it makes previously encrypted router credentials, SSH private keys, and peer private-key material unreadable.
- `WGM_DATABASE_URL`: a persistent database URL. The example uses SQLite for a single-host deployment. Confirm backup/restore and concurrency behavior before relying on SQLite for operational use; configure and test a supported PostgreSQL driver before switching to PostgreSQL.
- `WGM_ALLOWED_ORIGINS`: the exact origin users will access, including scheme and port if nonstandard (for example, `https://vpn-manager.example.com`). Do not add a trailing path.
- `WGM_BOOTSTRAP_ADMIN_USERNAME` and `WGM_BOOTSTRAP_ADMIN_PASSWORD`: unique first-admin credentials. The password must be at least 12 characters and should be generated/stored in a password manager.
- Keep `WGM_ALLOW_PUBLIC_ROUTER_HOSTS=false` and `WGM_ALLOW_PUBLIC_LINUX_HOSTS=false` unless a specific, reviewed network design requires otherwise.
- Keep `WGM_ENABLE_PEER_MUTATIONS=false`, `WGM_ENABLE_LINUX_MUTATIONS=false`, and `WGM_ENABLE_LINUX_OPTIMIZER_MUTATIONS=false` until release gates are met.

The deployment script **does not prompt for or generate secrets**. You must configure them before the first run. Do not commit `.env`, print its contents to logs, or paste secrets into issue reports.

## 3. Deploy or upgrade with one command

From the repository root:

```bash
bash scripts/deploy-production.sh
```

The script:

1. Validates required host tools, environment settings, secret formats, and supported minimum versions.
2. Creates/updates the isolated Python environment and installs backend dependencies.
3. Installs frontend dependencies and builds the production-only entry point.
4. Checks the generated production bundle for known demo fixture markers.
5. Applies Alembic migrations with `upgrade head`; it does not intentionally seed demo data, reset the database, or drop tables.
6. Starts/reloads `wireguard-manager-api` and `wireguard-manager-web` with PM2 and saves the PM2 process list.
7. Checks local health endpoints.
8. If bootstrap credentials are configured, attempts the one-time admin bootstrap. On success—or when the API reports an existing user—it removes the bootstrap username/password lines from `.env`.

Before the first run, record the initial admin username/password in a password manager. The password is intentionally removed from `.env` after bootstrap and cannot be recovered from that file. A subsequent deployment does not recreate or reset the administrator.

The migration step is not a substitute for a database backup. Take a verified backup before every upgrade, especially before schema changes.

## 4. Verify the deployment

The service binds to loopback by default:

- Web UI: `http://127.0.0.1:4173`
- API readiness: `http://127.0.0.1:8000/healthz`
- API health: `http://127.0.0.1:8000/api/v1/health`
- API docs for local troubleshooting: `http://127.0.0.1:8000/docs`

Run:

```bash
curl -sS -o /dev/null -w 'Frontend: HTTP %{http_code}\n' http://127.0.0.1:4173/
curl -fsS http://127.0.0.1:8000/healthz
printf '\n'
curl -fsS http://127.0.0.1:8000/api/v1/health
printf '\n'
curl -i http://127.0.0.1:4173/api/v1/health
pm2 status
```

Expected: frontend HTTP 200; both backend health endpoints succeed; the frontend same-origin `/api/v1/health` request is proxied to the API; both PM2 apps are online. The API root `/` may return 404—use the documented health endpoints and the frontend port for the UI.

If checks fail:

```bash
pm2 logs wireguard-manager-api --lines 100
pm2 logs wireguard-manager-web --lines 100
pm2 describe wireguard-manager-api
pm2 describe wireguard-manager-web
```

Do not post unredacted logs if they contain hostnames, usernames, tokens, or internal addresses.

## 5. HTTPS and reverse proxy

Do not expose ports 4173 or 8000 directly to the internet. Keep both services loopback-bound and configure a TLS reverse proxy on the same host or a controlled ingress. The proxy should:

- Serve the exact HTTPS origin configured in `WGM_ALLOWED_ORIGINS`.
- Forward browser requests to the web listener on `127.0.0.1:4173`.
- Preserve the `Host` header and set appropriate `X-Forwarded-Proto` / forwarding headers according to the proxy and deployment design.
- Redirect HTTP to HTTPS, use a valid certificate, and restrict access to the VPN/management network where possible.
- Avoid caching authenticated API responses, login/session responses, configuration downloads, or QR responses.
- Apply request-size/time-out settings appropriate to the UI and API, without masking API errors.
- Keep port 8000 private; the browser should use the same-origin `/api` proxy rather than connect to it directly.

A reverse-proxy configuration is environment-specific; validate its syntax, TLS chain, forwarded headers, allowed origin, and external reachability before use. Do not copy a generic configuration into production without adapting the hostname and certificate paths.

## 6. First login and functional acceptance

1. Open the HTTPS frontend URL (or `http://127.0.0.1:4173` for local-only smoke testing).
2. Sign in with the first-admin credentials saved during setup.
3. Verify logout/login and that protected pages require authentication.
4. Register a **lab** RouterOS device using a dedicated least-privilege account; validate its HTTPS certificate and run connection/discovery/diagnostic/audit checks.
5. Register a **lab** Linux host only after independently verifying the SSH host-key fingerprint. Check OS inspection and remote peer discovery.
6. Test peer preview, inventory, ACL behavior, config/QR delivery, audit-event browsing, and audit-chain verification using lab data.
7. Confirm role enforcement, failed-login/error handling, and that sensitive config/QR responses are not logged or cached.
8. Do not enable mutation flags until create/revoke, firewall ordering, rollback, ambiguous timeout behavior, and existing-peer reconciliation have been tested on the exact target versions and approved.

The production UI contains API-backed management workflows, but CI does not connect to real RouterOS or Linux systems. Passing CI is not evidence that your specific routers, Linux distributions, SSH sudo rules, or firewall layouts are compatible.

## 7. PM2 operations and reboot recovery

Run these commands as the deployment user:

```bash
pm2 status
pm2 logs wireguard-manager-api
pm2 logs wireguard-manager-web
pm2 restart wireguard-manager-api
pm2 restart wireguard-manager-web
pm2 reload ecosystem.config.cjs --update-env
pm2 save
```

PM2 process definitions live in `ecosystem.config.cjs`. Configure PM2 startup integration for the host OS/user using the official PM2 startup instructions, then verify after a real reboot that both services return and health checks pass. `pm2 save` alone does not configure the operating system's startup integration.

Review log size/retention and disk-space monitoring. Logs and backups may contain sensitive infrastructure metadata; set restrictive permissions and retention.

## 8. Backups, restore, and encryption-key protection

Before real use, implement and test a backup routine for:

- The database referenced by `WGM_DATABASE_URL` (for SQLite, back up the actual database file using a consistent backup method).
- The exact `WGM_ENCRYPTION_KEY` and JWT configuration as appropriate to your recovery policy.
- The application version/configuration needed to restore service.

Store backups off-host with access controls and encryption. Never place the encryption key beside an unencrypted database backup without equivalent protection. A database-only restore is incomplete if the Fernet key is lost or changed. Do not rotate `WGM_ENCRYPTION_KEY` by simply replacing the value: previously encrypted values may become unreadable unless a supported re-encryption/rotation procedure is performed.

Perform a restore drill in an isolated environment before registering production infrastructure. Verify login, database records, and the ability to decrypt previously stored credentials after restore.

## 9. Upgrade and recovery procedure

1. Review the release notes/CHANGELOG and inspect migration changes.
2. Back up the database and securely verify the encryption key is available.
3. Fetch the intended release/commit and inspect local changes; do not overwrite an operator-maintained `.env`.
4. Run `bash scripts/deploy-production.sh`.
5. Verify PM2 status, frontend HTTP 200, API readiness, same-origin API proxy, login, and the key read-only workflows.
6. If an upgrade fails, inspect PM2 logs and deployment output before retrying. Do not delete the database or run `alembic downgrade` blindly. Restore the verified backup or follow a migration-specific recovery plan with an operator who understands the schema/data implications.

The script preserves the existing `.env` and database; however, an Alembic migration may alter the schema. A successful script run is not an atomic rollback guarantee.

## 10. Known limitations and production release gates

- Historical traffic time series, historical charts, and alerting are not implemented; counters are point-in-time snapshots.
- Hash-linked audit events are not immutable against an actor with database-level write access. Configure off-host retention.
- Mutation rollback is best-effort; timeouts after a remote write can require manual reconciliation.
- Rate limiting, external secret-manager integration, formal key rotation/recovery, and an independent security review remain outstanding.
- End-to-end tests and failure-injection tests against real supported RouterOS/Linux versions remain outstanding.
- The Electron desktop package is a separate read-only RouterOS audit client, not a self-contained production manager.
- GitHub Pages and the default Vite build are demo-only. They must never be used to operate live infrastructure.

Do not describe a deployment as production-approved until target-host install/upgrade, TLS/reverse proxy, backups/restores, reboot recovery, role/access controls, real-device integration, failure handling, and change-control procedures have been validated and documented.
