# Production deployment with PM2

This deployment path runs FastAPI and serves the production React UI from the same process. It is not the GitHub Pages demo and it does not seed sample routers, peers, traffic, or audit events. The production UI uses authenticated API requests and shows empty states when the database has no records.

> This is a first production-host deployment path, not a certification that all RouterOS/Linux mutations are safe. Mutations remain disabled by default.

## Requirements

- Linux host (Ubuntu/Debian recommended) with a dedicated unprivileged service account.
- Node.js 20+, npm, Python 3.11+, curl, Git and PM2 installed for that account.
- Network access to package registries during installation.
- A TLS reverse proxy such as Nginx/Caddy for remote access. The app binds only to 127.0.0.1:8000.
- Egress policy allowing access only to intended RouterOS management and SSH networks.

Install PM2 for the deployment user if needed:

~~~bash
npm install --global pm2
pm2 startup
# Run the exact sudo/systemd command printed by pm2 startup, then:
pm2 save
~~~

## One-command first deployment

From a clean checkout on the target host:

~~~bash
git clone https://github.com/nestho/wireguard-manager.git
cd wireguard-manager
bash scripts/deploy-production.sh
~~~

The script asks for an initial admin username/password, generates independent JWT and Fernet keys, installs dependencies, builds the API-backed production UI, applies Alembic migrations, starts the service under PM2, creates the initial admin through the one-time bootstrap endpoint, removes the bootstrap password from .env, and restarts the service. The password is not printed. Keep the generated .env private (mode 0600).

For later updates, pull a reviewed version and rerun the script. It preserves an existing .env and database. Review release notes and take a tested backup before upgrading; migrations are not automatically reversible.

## PM2 operations

~~~bash
pm2 status
pm2 logs wireguard-manager
pm2 restart wireguard-manager --update-env
pm2 stop wireguard-manager
pm2 start ecosystem.config.cjs
pm2 save
~~~

PM2 logs are under logs/. Restrict access and configure log rotation.

## Database and secrets

- SQLite database: data/wireguard-manager.db.
- Runtime config and encryption key: .env (mode 0600).
- Back up the database and encryption key separately, encrypted at rest, and test restore procedures.
- Never replace WGM_ENCRYPTION_KEY on an existing database. Doing so can make saved credentials and private keys undecryptable.
- Keep the database on a local filesystem with reliable locking; use PostgreSQL for a multi-worker or higher-concurrency deployment.
- Never commit .env, the database, client configs, QR exports, or private keys.

## Network and security

- The API binds to loopback; terminate HTTPS at a reverse proxy and do not expose port 8000 directly.
- The production frontend is served by FastAPI at the same origin; CORS is not needed for the bundled UI.
- Public targets and live mutations remain disabled by default.
- Restrict the reverse proxy to trusted networks, configure TLS and request/time limits, and consider VPN-only access.
- OpenAPI docs are disabled in production mode.
- The UI currently provides authentication, router/Linux inventory and registration, router connection tests, Linux host inspection, and read-only WireGuard peer discovery. It does not yet provide full peer lifecycle management, full audit/traffic/diagnostics views, or desktop packaging of this full UI.
- Do not describe this as fully feature-complete or fully security-audited. Run tests and a security review before using it to change production networks.

## Health checks

- GET /healthz — process liveness.
- GET /api/v1/health — API status.
- PM2 logs — pm2 logs wireguard-manager.

## Rollback

Before upgrade, stop writes and take an encrypted copy of data/wireguard-manager.db and .env. If a migration changes the schema, restoring only old application code may not work; restore the matching database backup and encryption key as a unit.
